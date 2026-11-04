"""Deterministic pre-analysis: facts extracted before (and without) any model call.

Every fact is an observation with a location in the redacted, stored content
(source id, line, character range) and a short excerpt. Facts are labeled with
a category hint from the fixed review categories; they are never findings and
never claim exploitability. They are useful on their own and are shown even
when AI is disabled, unavailable or fails.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from watchtower.services.ai.jslex import Token, code_tokens, tokenize
from watchtower.services.ai.redaction import LineIndex

CATEGORIES = ("dom_xss_sink", "open_redirect", "sensitive_data_in_client", "insecure_token_storage", "weak_csp",
              "cors_misconfiguration", "outdated_library", "exposed_endpoint", "debug_artifact", "other")
CATEGORY_LABELS = {
    "dom_xss_sink": "DOM XSS sink", "open_redirect": "Open redirect", "sensitive_data_in_client": "Sensitive data in client",
    "insecure_token_storage": "Insecure storage of tokens", "weak_csp": "Weak CSP", "cors_misconfiguration": "CORS misconfiguration",
    "outdated_library": "Outdated library", "exposed_endpoint": "Exposed endpoint", "debug_artifact": "Debug or test artifact",
    "other": "Other",
}
WEIGHTS = {"sink": 3, "flow": 4, "secret": 3, "redirect": 2, "postmessage": 3, "storage": 2, "auth": 2, "library": 2,
           "graphql": 2, "debug": 2, "endpoint": 1, "header": 1}

SOURCES = {("location", "hash"), ("location", "search"), ("location", "href"), ("document", "URL"),
           ("document", "documentURI"), ("document", "referrer"), ("window", "name"), ("event", "data"),
           ("e", "data"), ("message", "data")}
SOURCE_IDENTS = {"URLSearchParams", "decodeURIComponent", "getParameter"}
TOKENISH = re.compile(r"(?i)token|jwt|auth|session|bearer|refresh|credential|secret|apikey|api_key")
URL_VALUE = re.compile(r"^(?:https?|wss?)://[^\s\"'<>`]{3,500}$")
PATH_VALUE = re.compile(r"^/(?:api|v\d+|graphql|rest|auth|oauth|oauth2|admin|internal|debug|test|private|_[a-z]+)"
                        r"(?:[/?#.][^\s\"'<>`]{0,300})?$", re.I)
DEBUG_HOST = re.compile(r"(?i)^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\])$|(?:^|[.-])(?:dev|staging|stage|test|qa|uat|"
                        r"local|internal)(?:[.-]|$)")
SENSITIVE_PATH = re.compile(r"(?i)/(?:admin|internal|debug|private|actuator|_debug|phpinfo|console|swagger|graphiql)\b")

# name: (advisory product identifiers, version patterns over the file text, URL patterns)
LIBRARIES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "jquery": (("npm:jquery", "jquery:jquery"), (r"jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)",
                                                  r"jquery:\s*[\"'](\d+\.\d+\.\d+)[\"']")),
    "jquery-ui": (("npm:jquery-ui", "jquery:jquery_ui"), (r"jQuery UI - v(\d+\.\d+\.\d+)",)),
    "angularjs": (("npm:angular", "angularjs:angular.js"), (r"AngularJS v(\d+\.\d+\.\d+)",)),
    "react": (("npm:react", "facebook:react"), (r"React v(\d+\.\d+\.\d+)", r"react\.production\.min\.js.*?v(\d+\.\d+\.\d+)")),
    "vue": (("npm:vue", "vuejs:vue.js"), (r"Vue\.js v(\d+\.\d+\.\d+)",)),
    "lodash": (("npm:lodash", "lodash:lodash"), (r"lodash <https://lodash\.com/>.*?VERSION\s*=\s*[\"'](\d+\.\d+\.\d+)",
                                                 r"@license\s+Lodash\s+(\d+\.\d+\.\d+)", r"lodash (\d+\.\d+\.\d+)")),
    "underscore": (("npm:underscore", "underscorejs:underscore"), (r"Underscore\.js (\d+\.\d+\.\d+)",)),
    "bootstrap": (("npm:bootstrap", "getbootstrap:bootstrap"), (r"Bootstrap v(\d+\.\d+\.\d+)",)),
    "moment": (("npm:moment", "momentjs:moment"), (r"//! moment\.js.*?version\s*:\s*(\d+\.\d+\.\d+)",
                                                   r"//! version : (\d+\.\d+\.\d+)")),
    "handlebars": (("npm:handlebars", "handlebarsjs:handlebars"), (r"handlebars v(\d+\.\d+\.\d+)",)),
    "dompurify": (("npm:dompurify", "cure53:dompurify"), (r"DOMPurify (\d+\.\d+\.\d+)",)),
    "axios": (("npm:axios", "axios:axios"), (r"axios v(\d+\.\d+\.\d+)",)),
    "backbone": (("npm:backbone", "backbonejs:backbone"), (r"Backbone\.js (\d+\.\d+\.\d+)",)),
    "knockout": (("npm:knockout", "knockoutjs:knockout"), (r"Knockout JavaScript library v(\d+\.\d+\.\d+)",)),
}
URL_VERSION = re.compile(r"(?i)/(jquery-ui|jquery|angular(?:js)?|react(?:-dom)?|vue|lodash|underscore|bootstrap|moment|"
                         r"handlebars|dompurify|axios|backbone|knockout)(?:\.js)?[@/-]v?(\d+\.\d+(?:\.\d+)?)")
NO_VERSION_HINTS = {"__NEXT_DATA__": "next.js", "__NUXT__": "nuxt", "ng-version": "angular", "webpackJsonp": "webpack",
                    "__webpack_require__": "webpack"}


def fact(kind: str, category: str, detail: str, *, source_id: str, index: LineIndex, start: int, end: int,
         **extra: Any) -> dict[str, Any]:
    line = index.line(start)
    line_start, line_end = index.line_span(line)
    excerpt_start = max(line_start, start - 80)
    excerpt_end = min(line_end, max(end, start) + 80)
    return {"kind": kind, "category": category, "detail": detail, "source_id": source_id, "line": line,
            "start": start, "end": end, "excerpt": index.text[excerpt_start:excerpt_end][:240],
            "weight": WEIGHTS.get(kind, 1), **extra}


def _member(tokens: Sequence[Token], i: int) -> tuple[str, str] | None:
    """``(object, property)`` when tokens[i] is the property in ``object.property``."""
    if i >= 2 and tokens[i - 1].text in (".", "?.") and tokens[i - 2].kind == "ident":
        return tokens[i - 2].text, tokens[i].text
    return None


def _statement(tokens: Sequence[Token], i: int, limit: int = 80) -> tuple[int, int]:
    """Token index range of the statement around ``i`` (bounded)."""
    start = i
    while start > 0 and i - start < limit and tokens[start - 1].text not in (";", "{", "}"):
        start -= 1
    end = i
    while end < len(tokens) - 1 and end - i < limit and tokens[end + 1].text not in (";", "}"):
        end += 1
    return start, end + 1


def _navigation(name: str, member: tuple[str, str] | None, following: Token | None) -> bool:
    """``location = x``, ``location.href = x``, ``location.assign(x)`` or ``location.replace(x)``."""
    after = following.text if following else ""
    if name == "location":
        return after == "="
    return bool(member and member[0] == "location"
                and ((member[1] == "href" and after == "=") or (member[1] in ("assign", "replace") and after == "(")))


def _sources_in(tokens: Sequence[Token], lo: int, hi: int, skip: int = -1) -> list[str]:
    """Attacker-influenced sources in tokens ``lo..hi``; ``skip`` is the sink's own token."""
    found = []
    for j in range(lo, hi):
        token = tokens[j]
        if token.kind != "ident" or j == skip:
            continue
        member = _member(tokens, j)
        if member and (member in SOURCES or (member[0] in ("window", "document") and member[1] == "location")):
            found.append(".".join(member))
        elif token.text in SOURCE_IDENTS:
            found.append(token.text)
    return sorted(set(found))


def analyze_script(text: str, *, source_id: str, url: str = "") -> dict[str, Any]:
    """Facts for one script (redacted text)."""
    index = LineIndex(text)
    all_tokens = tokenize(text)
    tokens = code_tokens(all_tokens)
    facts: list[dict[str, Any]] = []
    endpoints: dict[str, dict[str, Any]] = {}
    add = facts.append

    def at(token: Token, kind: str, category: str, detail: str, **extra: Any) -> None:
        add(fact(kind, category, detail, source_id=source_id, index=index, start=token.start, end=token.end, **extra))

    def flow(i: int, sink: str, category: str) -> None:
        lo, hi = _statement(tokens, i)
        sources = _sources_in(tokens, lo, hi)
        if sources:
            at(tokens[i], "flow", category, f"{', '.join(sources)} reaches {sink} in the same statement "
               "(static hint; whether the value is sanitized is not known)", sink=sink, sources=sources)

    for i, token in enumerate(tokens):
        following = tokens[i + 1] if i + 1 < len(tokens) else None
        after = tokens[i + 2] if i + 2 < len(tokens) else None
        if token.kind == "ident":
            name = token.text
            member = _member(tokens, i)
            if name in ("innerHTML", "outerHTML") and following and following.text in ("=", "+="):
                at(token, "sink", "dom_xss_sink", f"assignment to {name}", sink=name)
                flow(i, name, "dom_xss_sink")
            elif name in ("insertAdjacentHTML", "dangerouslySetInnerHTML") and following and following.text in ("(", ":", "="):
                at(token, "sink", "dom_xss_sink", f"use of {name}", sink=name)
                flow(i, name, "dom_xss_sink")
            elif member in (("document", "write"), ("document", "writeln")) and following and following.text == "(":
                at(token, "sink", "dom_xss_sink", f"document.{name}()", sink="document." + name)
                flow(i, "document." + name, "dom_xss_sink")
            elif name == "eval" and not member and following and following.text == "(":
                at(token, "sink", "dom_xss_sink", "eval()", sink="eval")
                flow(i, "eval", "dom_xss_sink")
            elif name == "Function" and i > 0 and tokens[i - 1].text == "new":
                at(token, "sink", "dom_xss_sink", "new Function()", sink="Function")
            elif name in ("setTimeout", "setInterval") and following and following.text == "(" and after \
                    and after.kind in ("string", "template"):
                at(token, "sink", "dom_xss_sink", f"{name}() with a string argument (evaluated as code)", sink=name)
            elif _navigation(name, member, following):
                lo, hi = _statement(tokens, i)
                sources = _sources_in(tokens, lo, hi, skip=i)
                detail = "navigation to a computed location" + (f" using {', '.join(sources)}" if sources else "")
                at(token, "redirect", "open_redirect", detail, sources=sources, weight=4 if sources else 2)
            elif name in ("localStorage", "sessionStorage") and following and following.text in (".", "["):
                key_token = next((t for t in tokens[i + 2:i + 6] if t.kind in ("string", "template")), None)
                operation = after.text if after and after.kind == "ident" else "access"
                key = key_token.value if key_token else ""
                tokenish = bool(TOKENISH.search(key) or (after and TOKENISH.search(after.text)))
                at(token, "storage", "insecure_token_storage" if tokenish else "other",
                   f"{name}.{operation}" + (f" key {key!r}" if key else ""), storage=name, key=key[:100],
                   weight=3 if tokenish else 1)
            elif name == "indexedDB" and following and following.text == ".":
                at(token, "storage", "other", "IndexedDB use", storage="indexedDB", weight=1)
            elif member == ("document", "cookie"):
                write = bool(following and following.text == "=")
                at(token, "storage", "insecure_token_storage" if write else "other",
                   "document.cookie " + ("written by script (cannot be HttpOnly)" if write else "read by script"),
                   storage="document.cookie")
            elif name in ("addEventListener",) and following and following.text == "(" and after \
                    and after.kind == "string" and after.value == "message":
                window = tokens[i:i + 400]
                if not any(t.kind == "ident" and t.text == "origin" for t in window):
                    at(token, "postmessage", "dom_xss_sink", "message event handler with no origin check nearby")
            elif name == "onmessage" and following and following.text == "=":
                if not any(t.kind == "ident" and t.text == "origin" for t in tokens[i:i + 400]):
                    at(token, "postmessage", "dom_xss_sink", "onmessage handler with no origin check nearby")
            elif name in ("jwt_decode", "jwtDecode", "decodeJwt", "parseJwt") or \
                    name in ("accessToken", "refreshToken", "idToken", "access_token", "refresh_token", "id_token"):
                at(token, "auth", "sensitive_data_in_client", f"authentication-related code ({name})")
            elif name == "debugger":
                at(token, "debug", "debug_artifact", "debugger statement")
        elif token.kind in ("string", "template"):
            value = token.value.strip()
            if not value:
                continue
            call = tokens[i - 2].text if i >= 2 and tokens[i - 1].text == "(" else ""
            via = {"fetch": "fetch", "open": "XMLHttpRequest.open", "WebSocket": "WebSocket", "get": "HTTP GET",
                   "post": "HTTP POST", "put": "HTTP PUT", "delete": "HTTP DELETE", "patch": "HTTP PATCH",
                   "ajax": "ajax", "axios": "axios", "EventSource": "EventSource"}.get(call, "")
            if value.lower() == "authorization":
                at(token, "auth", "sensitive_data_in_client", "Authorization header set by script")
            elif value.lower().startswith("bearer"):
                at(token, "auth", "sensitive_data_in_client", "bearer token handling")
            if URL_VALUE.match(value) or PATH_VALUE.match(value) or (via and value.startswith(("/", "./", "http"))):
                key = value[:300]
                parts = urlsplit(value if "://" in value else "https://x" + value)
                host = parts.hostname or ""
                if key not in endpoints:
                    category = "exposed_endpoint" if SENSITIVE_PATH.search(parts.path) else "other"
                    if "://" in value and host and DEBUG_HOST.search(host):
                        category = "debug_artifact"
                    entry = fact("debug" if category == "debug_artifact" else "endpoint", category,
                                 f"{via + ' ' if via else ''}{key}", source_id=source_id, index=index,
                                 start=token.start, end=token.end, url=key, via=via)
                    endpoints[key] = entry
                    add(entry)
                if "graphql" in value.lower():
                    at(token, "graphql", "exposed_endpoint", "GraphQL endpoint", url=key)
            elif re.match(r"(?s)^(?:query|mutation|subscription)\b[\s\w]*[({]", value) or "__schema" in value:
                at(token, "graphql", "exposed_endpoint", "GraphQL operation" + (" (introspection)" if "__schema" in value else ""))
    for token in all_tokens:
        if token.kind == "comment":
            if re.search(r"(?i)\b(?:todo|fixme|hack|xxx)\b.*\b(?:password|secret|token|key|auth|bypass)\b", token.text):
                at(token, "debug", "debug_artifact", "developer comment mentioning credentials or a bypass")
            if token.text.startswith("//# sourceMappingURL=") or token.text.startswith("//@ sourceMappingURL="):
                at(token, "debug", "other", "source map reference", source_map=token.text.split("=", 1)[1].strip()[:500],
                   weight=1)
    return {"facts": facts, "libraries": detect_libraries(text, url, source_id=source_id, index=index),
            "tokens": len(all_tokens), "endpoints": sorted(endpoints)}


def detect_libraries(text: str, url: str = "", *, source_id: str = "", index: LineIndex | None = None) -> list[dict[str, Any]]:
    index = index or LineIndex(text)
    found: dict[str, dict[str, Any]] = {}
    head = text[:200_000]
    for name, (_, patterns) in LIBRARIES.items():
        for pattern in patterns:
            match = re.search(pattern, head, re.S)
            if match:
                found[name] = {"name": name, "version": match.group(1), "how": "banner or version string in the file",
                               "source_id": source_id, "line": index.line(match.start(1)),
                               "start": match.start(1), "end": match.end(1)}
                break
    for match in URL_VERSION.finditer(url or ""):
        name = match.group(1).lower()
        name = {"angular": "angularjs", "react-dom": "react"}.get(name, name)
        found.setdefault(name, {"name": name, "version": match.group(2), "how": "version in the script URL",
                                "source_id": source_id, "line": None, "start": None, "end": None})
    for hint, name in NO_VERSION_HINTS.items():
        if hint in head and name not in found:
            found[name] = {"name": name, "version": "", "how": "framework marker (version not determinable)",
                           "source_id": source_id, "line": index.line(head.index(hint)),
                           "start": head.index(hint), "end": head.index(hint) + len(hint)}
    return sorted(found.values(), key=lambda item: item["name"])


def match_advisories(libraries: Iterable[Mapping[str, Any]], advisories: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Advisory matches for detected libraries, using the existing applicability rules (facts, not findings)."""
    from watchtower.adapters.intelligence.applicability import Applicability, match_component

    matches = []
    for library in libraries:
        products = LIBRARIES.get(library["name"], ((),))[0]
        for advisory in advisories:
            if advisory.get("product") not in products:
                continue
            result = match_component(advisory["product"], library.get("version") or None, advisory)
            if result.applicability in (Applicability.AFFECTED, Applicability.POSSIBLE, Applicability.UNKNOWN):
                matches.append({"library": library["name"], "version": library.get("version", ""),
                                "advisory": advisory.get("id"), "cves": list(advisory.get("cves", ())),
                                "applicability": result.applicability.value, "reason": result.reason,
                                "summary": str(advisory.get("summary", ""))[:300], "source_id": library.get("source_id")})
    return matches


def _csp_directives(policy: str) -> dict[str, list[str]]:
    directives = {}
    for part in policy.split(";"):
        words = part.strip().split()
        if words:
            directives.setdefault(words[0].lower(), [w.lower() for w in words[1:]])
    return directives


def analyze_headers(headers: Mapping[str, str], url: str, *, source_id: str, meta_csp: str = "") -> list[dict[str, Any]]:
    """Security header facts for one page response. ``headers`` keys are lower-case."""
    facts = []

    def add(category: str, detail: str, header: str = "") -> None:
        facts.append({"kind": "header", "category": category, "detail": detail, "source_id": source_id,
                      "header": header, "line": None, "start": None, "end": None, "excerpt": "",
                      "weight": WEIGHTS["header"]})

    https = url.lower().startswith("https://")
    if https and "strict-transport-security" not in headers:
        add("other", "Strict-Transport-Security (HSTS) header is missing on an HTTPS page")
    csp = headers.get("content-security-policy") or meta_csp
    if not csp:
        add("weak_csp", "no Content-Security-Policy" + (" (only report-only)" if headers.get(
            "content-security-policy-report-only") else ""))
    else:
        directives = _csp_directives(csp)
        scripts = directives.get("script-src", directives.get("default-src"))
        if scripts is None:
            add("weak_csp", "CSP has neither script-src nor default-src", "content-security-policy")
        else:
            nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in scripts)
            if "'unsafe-inline'" in scripts and not nonce_or_hash:
                add("weak_csp", "CSP allows 'unsafe-inline' scripts", "content-security-policy")
            if "'unsafe-eval'" in scripts:
                add("weak_csp", "CSP allows 'unsafe-eval'", "content-security-policy")
            if any(s in ("*", "http:", "https:", "data:") for s in scripts):
                add("weak_csp", "CSP script sources include a wildcard or a whole scheme", "content-security-policy")
        if "object-src" not in directives and "'none'" not in directives.get("default-src", []):
            add("weak_csp", "CSP does not restrict object-src", "content-security-policy")
        if "base-uri" not in directives:
            add("weak_csp", "CSP does not set base-uri", "content-security-policy")
    if "x-frame-options" not in headers and "frame-ancestors" not in (csp or "").lower():
        add("other", "no X-Frame-Options or CSP frame-ancestors (framing is not restricted)")
    origin = headers.get("access-control-allow-origin", "").strip()
    credentials = headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    if origin == "*" and credentials:
        add("cors_misconfiguration", "CORS allows any origin together with credentials", "access-control-allow-origin")
    elif origin == "null":
        add("cors_misconfiguration", "CORS allows the 'null' origin", "access-control-allow-origin")
    elif origin == "*":
        add("other", "CORS allows any origin (fine for public resources; check for private data)",
            "access-control-allow-origin")
    if "x-content-type-options" not in headers:
        add("other", "X-Content-Type-Options: nosniff is missing")
    return facts


def secret_facts(secrets: Iterable[Mapping[str, Any]], text: str, *, source_id: str) -> list[dict[str, Any]]:
    index = LineIndex(text)
    return [fact("secret", "sensitive_data_in_client", f"secret-like value ({item['kind'].replace('_', ' ')}) "
                 "was found and redacted; review whether it is meant to be public",
                 source_id=source_id, index=index, start=item["start"], end=item["end"], secret_kind=item["kind"])
            for item in secrets]
