"""Phase 2: redaction with offset maps, the JavaScript lexer, pre-analysis, HTML reading and chunking."""

from __future__ import annotations

import hashlib

import pytest

from watchtower.services.ai.chunking import chunk_source, estimate_tokens, minified, select_chunks
from watchtower.services.ai.html import parse_html, static_imports
from watchtower.services.ai.jslex import statement_ends, tokenize
from watchtower.services.ai.preanalysis import analyze_headers, analyze_script, detect_libraries, match_advisories, secret_facts
from watchtower.services.ai.redaction import LineIndex, Redacted, redact, secret_value

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
# Fake provider keys, assembled at runtime so secret scanners do not mistake the source for a leak.
GOOGLE_KEY = "AIza" + "SyA1234567890abcdefghijklmnopqrstuv"
STRIPE_KEY = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


# -- redaction -------------------------------------------------------------


@pytest.mark.parametrize("original, secret", [
    ('const apiKey = "AbC123def456ghi";', "AbC123def456ghi"),
    ('fetch(u, {headers: {Authorization: "Bearer ' + JWT + '"}})', JWT),
    ('const db = "postgres://admin:hunter2@db.example.com/app";', "hunter2"),
    ('k = "' + GOOGLE_KEY + '"', GOOGLE_KEY),
    ('stripe("' + STRIPE_KEY + '")', STRIPE_KEY),
    ('aws = "' + AWS_KEY + '"', AWS_KEY),
    ('password: "correct horse battery"', "correct horse battery"),
    ('document.cookie = "session=' + JWT + '"', JWT),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "MIIEow"),
])
def test_secrets_are_redacted(original, secret):
    result = redact(original)
    assert secret not in result.text and "[REDACTED]" in result.text and result.count >= 1
    assert result.original_sha256 == hashlib.sha256(original.encode()).hexdigest()


@pytest.mark.parametrize("code", [
    'token = localStorage.getItem("token")', 'headers.Authorization = "Bearer " + token',
    'var secret = process.env.SECRET;', 'x.password = input.value', 'type: "password"', 'tokenType: "Bearer"',
    'const auth = useAuth();',
])
def test_code_that_only_refers_to_secrets_stays_readable(code):
    assert redact(code).text == code


def test_secret_value_rules():
    assert secret_value('"abcd"', "password") and not secret_value('"abc"', "password")
    assert not secret_value("getToken()", "token") and not secret_value('"short"', "apiKey")
    assert secret_value('"k3y-v4lue-1234"', "apiKey") and secret_value('"' + "a" * 24 + '"', "token")


def test_offset_map_points_back_to_the_original():
    original = 'a="x"; const apiKey = "AbC123def456ghi"; b = 1; auth = "Bearer ' + JWT + '"; tail()'
    result = redact(original)
    tail = result.text.index("tail()")
    assert result.to_original(tail, tail + 6) == (original.index("tail()"), original.index("tail()") + 6)
    first = result.text.index("[REDACTED]")
    start, end = result.to_original(first, first + len("[REDACTED]"))
    assert original[start:end] == "AbC123def456ghi"
    restored = Redacted.from_map(result.text, result.original_sha256, result.offset_map())
    assert restored.to_original(tail, tail + 6) == result.to_original(tail, tail + 6)
    assert [s["kind"] for s in result.secrets()] == ["named_secret", "jwt"]
    assert result.redacted_within(first, first + 1) and not result.redacted_within(0, 3)


def test_redaction_is_stable():
    once = redact('cfg = {"api_key": "Zm9vYmFyYmF6cXV4MTIzNDU2", token: "' + JWT + '"}')
    assert redact(once.text).text == once.text


# -- lexer -----------------------------------------------------------------


def kinds(source):
    return [(t.kind, t.text) for t in tokenize(source)]


def test_regex_and_division_are_told_apart():
    tokens = kinds("x = a / b / c; y = /ab+c/gi.test(s); return /x/;")
    assert ("regex", "/ab+c/gi") in tokens and ("regex", "/x/") in tokens
    assert [t for t in tokens if t[0] == "regex"].__len__() == 2


def test_strings_comments_and_templates():
    source = 'a = "q\\"uote"; // fetch("/not-code")\n/* eval(x) */ b = `x${y + `inner${z}`}tail`; c = \'s\''
    tokens = tokenize(source)
    assert [t.value for t in tokens if t.kind == "string"] == ['q"uote', "s"]
    assert sum(t.kind == "comment" for t in tokens) == 2
    assert [t.text for t in tokens if t.kind == "ident"] == ["a", "b", "y", "z", "c"]
    assert tokens[-1].line == 2


def test_lexer_never_raises_on_broken_input():
    for source in ['"unterminated', "/* never closed", "`tpl ${", "x = /[/", "\x00\x01@#", "}}}{{{"]:
        tokenize(source)


def test_statement_boundaries():
    source = "a(); function f() { b(); c(); } d = {x: 1};"
    tokens = tokenize(source)
    assert statement_ends(tokens) == [4, 31, 43]
    assert statement_ends(tokens, depth=1) == [24, 29]


# -- pre-analysis ----------------------------------------------------------

SAMPLE = """/*! jQuery v3.4.1 | (c) JS Foundation */
const q = new URLSearchParams(location.search);
el.innerHTML = location.hash.slice(1);
localStorage.setItem("access_token", data.token);
fetch("/api/v1/users", {headers: {Authorization: "Bearer " + t}});
window.addEventListener("message", function (e) { eval(e.data) });
location.href = q.get("next");
var u = "http://staging.example.com/admin"; // TODO remove password bypass
setTimeout("go()", 10); var re = /ab+c/g; x = a / b / c;
document.cookie = "theme=dark";
// eval(commentedOut) and fetch("/api/ignored") inside a comment
var s = "innerHTML = notcode";
"""


def test_pre_analysis_finds_sinks_flows_storage_endpoints_and_debug_artifacts():
    result = analyze_script(SAMPLE, source_id="s1", url="https://cdn.example.com/app.js")
    found = {(f["kind"], f["line"]) for f in result["facts"]}
    assert ("sink", 3) in found and ("flow", 3) in found  # location.hash reaches innerHTML
    assert ("storage", 4) in found and ("endpoint", 5) in found and ("auth", 5) in found
    assert ("postmessage", 6) in found and ("sink", 6) in found and ("flow", 6) in found
    assert ("redirect", 7) in found and ("debug", 8) in found and ("sink", 9) in found and ("storage", 10) in found
    storage = next(f for f in result["facts"] if f["kind"] == "storage" and f["line"] == 4)
    assert storage["category"] == "insecure_token_storage" and storage["key"] == "access_token"
    redirect = next(f for f in result["facts"] if f["kind"] == "redirect")
    assert redirect["sources"] == [] and redirect["category"] == "open_redirect"
    assert not any(f["line"] in (11, 12) for f in result["facts"])  # comments and strings are not code
    assert "/api/v1/users" in result["endpoints"] and "/api/ignored" not in result["endpoints"]
    assert all(f["excerpt"] and f["source_id"] == "s1" for f in result["facts"])


def test_libraries_and_advisory_matching_are_observed_facts():
    libraries = detect_libraries(SAMPLE, "https://cdn.example.com/lodash@4.17.15/lodash.min.js", source_id="s1")
    assert {(lib["name"], lib["version"]) for lib in libraries} == {("jquery", "3.4.1"), ("lodash", "4.17.15")}
    advisories = [{"id": "CVE-2020-11022", "cves": ["CVE-2020-11022"], "product": "npm:jquery",
                   "affected": [{"introduced": "1.2", "fixed": "3.5.0"}], "summary": "jQuery htmlPrefilter XSS"},
                  {"id": "X", "product": "npm:jquery", "affected": [{"introduced": "4.0.0"}]}]
    matches = match_advisories(libraries, advisories)
    assert [(m["library"], m["advisory"], m["applicability"]) for m in matches] == [("jquery", "CVE-2020-11022", "affected")]


def test_header_facts():
    facts = analyze_headers({"content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https:",
                             "access-control-allow-origin": "*", "access-control-allow-credentials": "true"},
                            "https://www.example.com/", source_id="page")
    details = {f["detail"] for f in facts}
    assert "Strict-Transport-Security (HSTS) header is missing on an HTTPS page" in details
    assert "CSP allows 'unsafe-inline' scripts" in details
    assert "CSP script sources include a wildcard or a whole scheme" in details
    assert "CORS allows any origin together with credentials" in details
    strong = analyze_headers({"content-security-policy": "default-src 'none'; script-src 'nonce-abc' 'unsafe-inline'; "
                              "base-uri 'none'; frame-ancestors 'none'", "strict-transport-security": "max-age=1",
                              "x-content-type-options": "nosniff"}, "https://x/", source_id="p")
    assert strong == []
    assert any(f["detail"] == "no Content-Security-Policy" for f in analyze_headers({}, "http://x/", source_id="p"))


def test_secret_facts_have_locations_but_no_values():
    original = 'line1\nconst apiKey = "AbC123def456ghi";\n'
    result = redact(original)
    facts = secret_facts(result.secrets(), result.text, source_id="s")
    assert facts[0]["line"] == 2 and facts[0]["category"] == "sensitive_data_in_client"
    assert "AbC123def456ghi" not in repr(facts)


# -- HTML ------------------------------------------------------------------


def test_html_scripts_inline_code_and_meta_csp():
    page = ("<html><head><base href='/app/'><meta http-equiv='Content-Security-Policy' content=\"script-src 'self'\">"
            "<script src='main.js' integrity='sha384-abc'></script>"
            "<script src='https://cdn.example.net/jquery-3.4.1.min.js'></script>"
            "<script type='application/ld+json'>{\"a\":1}</script>\n"
            "<link rel='modulepreload' href='/chunk.js'>\n<script>\nvar x = location.hash;\n</script></head></html>")
    facts = parse_html(page, "https://www.example.com/index.html")
    assert [s.url for s in facts.scripts] == ["https://www.example.com/app/main.js",
                                              "https://cdn.example.net/jquery-3.4.1.min.js",
                                              "https://www.example.com/chunk.js"]
    assert facts.scripts[0].integrity == "sha384-abc" and facts.scripts[2].preload
    assert facts.meta_csp == "script-src 'self'"
    assert len(facts.inline) == 1 and "location.hash" in facts.inline[0].text
    assert page[facts.inline[0].start:].startswith("\nvar x")


def test_static_imports():
    tokens = tokenize('import a from "./a.js"; import "/b.js"; const c = import("../c.js"); import d from "react";')
    assert static_imports(tokens, "https://x.test/js/app.js") == [
        "https://x.test/js/a.js", "https://x.test/b.js", "https://x.test/c.js"]


# -- chunking --------------------------------------------------------------


def test_chunks_follow_statement_boundaries_and_keep_ranges():
    text = "".join(f"function f{i}() {{ return {i}; }}\n" for i in range(40))
    chunks = chunk_source(text, source_id="s", url="u", max_chars=200)
    assert len(chunks) > 1 and all(len(c.text) <= 200 for c in chunks)
    assert "".join(c.text for c in chunks).strip() == text.strip()
    assert all(c.text.rstrip().endswith("}") for c in chunks)
    first = chunks[0]
    assert (first.line_start, first.start, first.byte_start) == (1, 0, 0) and len(first.sha256) == 64


def test_minified_code_is_cut_inside_large_statements_with_context():
    body = ";".join(f"a{i}=b{i}(c{i})" for i in range(400))
    text = "!function(){" + body + "}();"
    chunks = chunk_source(text, source_id="s", url="u", max_chars=500)
    assert minified(text) and all(c.minified for c in chunks)
    assert len(chunks) > 5 and all(len(c.text) <= 500 for c in chunks)
    assert chunks[1].context.startswith("!function(){")


def test_chunk_flags_redaction_truncation_and_scores_hits():
    redacted = redact('a();\nconst apiKey = "AbC123def456ghi";\nel.innerHTML = location.hash;\n')
    facts = analyze_script(redacted.text, source_id="s")["facts"]
    chunks = chunk_source(redacted.text, source_id="s", url="u", max_chars=32, truncated=True,
                          redacted=[(r.out_start, r.out_end) for r in redacted.replacements], facts=facts)
    assert [c.redacted for c in chunks] == [False, True, False]
    assert chunks[-1].truncated and not chunks[0].truncated
    assert chunks[2].score > 0 and chunks[0].score == 0


def test_selection_prefers_hits_and_reports_what_was_skipped():
    text = "".join(f"x{i}();\n" for i in range(10)) + "el.innerHTML = location.hash;\n"
    facts = analyze_script(text, source_id="s")["facts"]
    chunks = chunk_source(text, source_id="s", url="u", max_chars=30, facts=facts)
    selection = select_chunks(chunks, max_chunks=2, max_total_chars=10_000)
    assert "innerHTML = location.hash" in selection.chunks[0].text
    assert len(selection.skipped) == len(chunks) - 2
    assert all(s["reason"].startswith("budget") for s in selection.skipped)
    tight = select_chunks(chunks, max_chunks=99, max_total_chars=20)
    assert any("characters" in s["reason"] for s in tight.skipped)


def test_token_estimate_and_line_index():
    assert estimate_tokens("x" * 30) == 10
    index = LineIndex("ab\ncd\né")
    assert index.line(4) == 2 and index.line_span(2) == (3, 5) and index.byte(6) == 6 and index.byte(7) == 8
