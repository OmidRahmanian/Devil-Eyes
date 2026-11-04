"""The ``ai.collect`` job: fetch in-scope pages and scripts for review, statically.

A collection is an authorized, budgeted, cancellable run. It uses the same
pinned-connection prober as scans, so every request and every redirect hop is
checked against scope, destination policy, permitted ports and paths, the
run's request budget and rate limits. Requests are sequential (one per host at
a time) and stop at cancellation between files.

* Pages: fetched to find scripts. Their HTML (and inline scripts) is kept only
  when the owner enabled ``retain_response_bodies``; otherwise only the
  allow-listed security headers are kept.
* Scripts referenced by the pages (and, up to ``ai.max_fetch_depth``, scripts
  they import statically): fetched when in scope. Third-party or out-of-scope
  scripts are recorded as references only (host, path, integrity, version hints)
  and are never fetched.
* Source maps: fetched only when the owner enabled ``allow_source_maps`` and
  the map URL is in scope.

Downloaded code is never executed, evaluated or rendered; it is only
tokenized. Everything stored is redacted first and expires after
``ai.retention_days``.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import urljoin, urlsplit
from uuid import UUID, uuid4

from watchtower.adapters.probing.guard import explain
from watchtower.adapters.probing.http import HttpProber
from watchtower.services.ai import store
from watchtower.services.ai.chunking import minified
from watchtower.services.ai.html import VERSION_HINT, parse_html, static_imports
from watchtower.services.ai.jslex import tokenize
from watchtower.services.ai.preanalysis import analyze_headers, analyze_script, secret_facts
from watchtower.services.ai.redaction import redact

SECURITY_HEADERS = ("content-security-policy", "content-security-policy-report-only", "strict-transport-security",
                    "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy",
                    "access-control-allow-origin", "access-control-allow-credentials",
                    "cross-origin-opener-policy", "cross-origin-resource-policy")
HTML_LIMIT = 256 * 1024  # the existing probe limit for page bodies
MAX_PAGES = 5
MAX_SOURCE_MAP_BYTES = 8 * 1024 * 1024


def _charset(content_type: str) -> str:
    match = re.search(r"charset=([\w-]+)", content_type or "", re.I)
    return match.group(1) if match else "utf-8"


def _decode(body: bytes, content_type: str) -> str:
    try:
        return body.decode(_charset(content_type), "replace")
    except LookupError:
        return body.decode("utf-8", "replace")


def _fetch(prober: Any, url: str) -> dict[str, Any]:
    parts = urlsplit(url)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return prober.probe(parts.hostname or "", scheme=parts.scheme, port=parts.port, path=path)


def reference_details(url: str, integrity: str = "", reason: str = "") -> dict[str, Any]:
    parts = urlsplit(url)
    hints = re.findall(VERSION_HINT, url)
    return {"host": parts.hostname or "", "path": parts.path, "integrity": integrity, "version_hints": hints[:3],
            "reason": reason, "fetched": False}


class Collector:
    def __init__(self, pipeline: Any, job: Any, policy: Any, token: Any) -> None:
        self.pipeline, self.job, self.policy, self.token = pipeline, job, policy, token
        self.settings = pipeline.settings.ai
        self.blobs = pipeline._blobs()
        self.options = job.payload.get("ai", {})
        with pipeline.db.project(job.project_id) as uow:
            self.switches = store.project_settings(uow)
            self.done = {row["url"]: row for row in store.sources(uow, run_id=job.run_id)}
        if pipeline.adapters.prober is not None:
            self.page_prober = self.script_prober = pipeline.adapters.prober(policy)
        else:
            common = {"clock": pipeline.clock, "max_redirects": pipeline.settings.scope.max_redirects,
                      "keep_body": True, "extra_headers": SECURITY_HEADERS}
            self.page_prober = HttpProber(policy, max_body_bytes=HTML_LIMIT, **common)
            self.script_prober = HttpProber(policy, max_body_bytes=self.settings.max_file_bytes, **common)
        self.deadline = time.monotonic() + self.settings.max_review_seconds
        self.report: dict[str, Any] = {"pages": 0, "scripts": 0, "references": 0, "inline_scripts": 0,
                                       "source_map_files": 0, "skipped": [], "notes": [], "partial": False,
                                       "source_ids": [str(row["id"]) for row in self.done.values()]}
        self.files = sum(row["kind"] in ("script", "source_map_source") for row in self.done.values())
        self.total_bytes = sum(row["size_bytes"] for row in self.done.values() if row["kind"] != "html")
        self.seen: set[str] = set()

    # helpers

    def _save(self, **values: Any) -> UUID:
        source_id = values.pop("source_id", None) or uuid4()
        with self.pipeline.db.project(self.job.project_id) as uow:
            store.add_source(uow, blobs=self.blobs, run_id=self.job.run_id, retention_days=self.settings.retention_days,
                             source_id=source_id, **values)
        self.report["source_ids"].append(str(source_id))
        return source_id

    def _skip(self, url: str, reason: str, *, partial: bool = False) -> None:
        self.report["skipped"].append({"url": url[:500], "reason": reason[:300]})
        self.report["partial"] = self.report["partial"] or partial

    def _note(self, text: str) -> None:
        if text not in self.report["notes"]:
            self.report["notes"].append(text)

    def _reference(self, url: str, integrity: str, reason: str, parent: str = "") -> None:
        if url in self.done:
            return
        details = {**reference_details(url, integrity, reason), "referenced_by": parent}
        self._save(origin="reference", kind="reference", url=url, details=details)
        self.report["references"] += 1

    def _out_of_time(self) -> bool:
        return time.monotonic() > self.deadline

    # pages and scripts

    def pages(self) -> list[str]:
        explicit = [str(url) for url in self.options.get("urls") or []]
        if explicit:
            return explicit[:MAX_PAGES]
        paths = self.policy.execution_policy.allowed_paths
        urls = []
        for target in self.job.payload["run"]["targets"]:
            endpoints = self.pipeline._endpoints(self.job, target)
            for endpoint in endpoints:
                urls.append(endpoint.url(paths[0]))
            if not endpoints:
                scheme = "https" if "https" in self.policy.execution_policy.allowed_schemes else "http"
                urls.append(f"{scheme}://{target}{paths[0]}")
        return list(dict.fromkeys(urls))[:MAX_PAGES]

    def page(self, url: str) -> list[tuple[str, int, str, str]]:
        """Fetch one page; return the scripts it references as ``(url, depth, parent, integrity)``."""
        if url in self.done:
            return []
        result = _fetch(self.page_prober, url)
        if result.get("outcome") != "ok" or not result.get("status_code"):
            error = result.get("error") or {}
            self._skip(url, f"page not fetched: {error.get('message') or result.get('outcome')}", partial=True)
            return []
        headers = {k.lower(): v for k, v in (result.get("headers") or {}).items()}
        final_url = result.get("url") or url
        html_text = _decode(result.get("body") or b"", headers.get("content-type", ""))
        found = parse_html(html_text, final_url)
        page_id = uuid4()
        facts = analyze_headers(headers, final_url, source_id=str(page_id), meta_csp=found.meta_csp)
        keep = self.switches["retain_response_bodies"]
        content = redact(html_text) if keep else None
        if content is not None:
            facts += secret_facts(content.secrets(), content.text, source_id=str(page_id))
        security_headers = {k: v for k, v in headers.items() if k in SECURITY_HEADERS or k in ("content-type", "server")}
        self._save(source_id=page_id, origin="retained_body" if keep else "collected", kind="html", url=url,
                   final_url=final_url, status_code=result["status_code"], content_type=headers.get("content-type", ""),
                   size_bytes=len(result.get("body") or b""), truncated=bool(result.get("truncated")), content=content,
                   details={"headers": security_headers, "meta_csp": found.meta_csp, "body_retained": keep,
                            "scripts": [ref.url for ref in found.scripts][:200], "inline_scripts": len(found.inline),
                            "redirects": result.get("redirects", [])},
                   preanalysis={"facts": facts})
        self.report["pages"] += 1
        if found.inline:
            if keep:
                for number, inline in enumerate(found.inline, 1):
                    self._inline(page_id, final_url, number, inline)
            else:
                self._note(f"{len(found.inline)} inline script(s) were seen but not kept: response-body retention "
                           "is off for this project")
        return [(ref.url, 1, str(page_id), ref.integrity) for ref in found.scripts]

    def _inline(self, page_id: UUID, page_url: str, number: int, inline: Any) -> None:
        source_id = uuid4()
        content = redact(inline.text)
        analysis = analyze_script(content.text, source_id=str(source_id), url=page_url)
        facts = analysis["facts"] + secret_facts(content.secrets(), content.text, source_id=str(source_id))
        self._save(source_id=source_id, origin="retained_body", kind="inline_script", url=f"{page_url}#inline-{number}",
                   content=content, size_bytes=len(inline.text.encode("utf-8", "surrogatepass")),
                   details={"parent": str(page_id), "line_offset": inline.line - 1},
                   preanalysis={"facts": facts, "libraries": analysis["libraries"], "endpoints": analysis["endpoints"]})
        self.report["inline_scripts"] += 1

    def script(self, url: str, depth: int, parent: str, integrity: str) -> list[tuple[str, int, str, str]]:
        decision = self.policy.check_url(url)
        if not decision:
            self._reference(url, integrity, f"not fetched: {explain(decision)}", parent)
            return []
        if self.files >= self.settings.max_files:
            self._skip(url, f"budget: at most {self.settings.max_files} files per collection", partial=True)
            return []
        if self.total_bytes >= self.settings.max_total_bytes:
            self._skip(url, f"budget: at most {self.settings.max_total_bytes} bytes per collection", partial=True)
            return []
        result = _fetch(self.script_prober, url)
        if result.get("outcome") == "unauthorized":
            self._reference(url, integrity, f"not fetched: {(result.get('error') or {}).get('message', 'not authorized')}",
                            parent)
            return []
        if result.get("outcome") != "ok":
            self._skip(url, f"not fetched: {(result.get('error') or {}).get('message') or result.get('outcome')}",
                       partial=True)
            return []
        if result.get("status_code") != 200:
            self._skip(url, f"HTTP status {result.get('status_code')}")
            return []
        body = result.get("body") or b""
        final_url = result.get("url") or url
        headers = {k.lower(): v for k, v in (result.get("headers") or {}).items()}
        self.files += 1
        self.total_bytes += len(body)
        source_id = uuid4()
        content = redact(_decode(body, headers.get("content-type", "")))
        analysis = analyze_script(content.text, source_id=str(source_id), url=final_url)
        facts = analysis["facts"] + secret_facts(content.secrets(), content.text, source_id=str(source_id))
        self._save(source_id=source_id, origin="collected", kind="script", url=url, final_url=final_url,
                   status_code=200, content_type=headers.get("content-type", ""), size_bytes=len(body),
                   truncated=bool(result.get("truncated")), content=content,
                   details={"integrity": integrity, "referenced_by": parent, "depth": depth,
                            "minified": minified(content.text)},
                   preanalysis={"facts": facts, "libraries": analysis["libraries"],
                                "endpoints": analysis["endpoints"][:200]})
        self.report["scripts"] += 1
        following = []
        if depth < self.settings.max_fetch_depth:
            following = [(u, depth + 1, str(source_id), "") for u in static_imports(tokenize(content.text), final_url)]
        for item in facts:
            if item.get("source_map"):
                self.source_map(urljoin(final_url, item["source_map"]), str(source_id))
        return following

    def source_map(self, url: str, generated: str) -> None:
        if url.startswith("data:") or url in self.done or url in self.seen:
            return
        self.seen.add(url)
        if not self.switches["allow_source_maps"]:
            self._note("Source maps were referenced but not fetched: allow_source_maps is off for this project")
            return
        if not self.policy.check_url(url):
            self._reference(url, "", "source map outside the authorized scope; not fetched", generated)
            return
        if self.files >= self.settings.max_files:
            self._skip(url, "budget: no files left for the source map", partial=True)
            return
        result = _fetch(self.script_prober, url)
        if result.get("outcome") != "ok" or result.get("status_code") != 200:
            self._skip(url, "source map not fetched")
            return
        try:
            data = json.loads((result.get("body") or b"")[:MAX_SOURCE_MAP_BYTES])
            names, contents = data.get("sources") or [], data.get("sourcesContent") or []
        except (ValueError, AttributeError):
            self._skip(url, "source map is not valid JSON")
            return
        for name, text in zip(names, contents):
            if not isinstance(text, str) or self.files >= self.settings.max_files:
                continue
            content = redact(text)
            source_id = uuid4()
            analysis = analyze_script(content.text, source_id=str(source_id), url=str(name))
            facts = analysis["facts"] + secret_facts(content.secrets(), content.text, source_id=str(source_id))
            self._save(source_id=source_id, origin="source_map", kind="source_map_source", url=f"{url}#{str(name)[:300]}",
                       content=content, size_bytes=len(text.encode("utf-8", "surrogatepass")),
                       details={"map_url": url, "generated": generated, "used_source_map": True},
                       preanalysis={"facts": facts, "libraries": analysis["libraries"],
                                    "endpoints": analysis["endpoints"][:200]})
            self.files += 1
            self.report["source_map_files"] += 1

    def run(self) -> dict[str, Any]:
        queue: list[tuple[str, int, str, str]] = []
        for url in self.pages():
            self.token.check()
            if self._out_of_time():
                self._skip(url, "time limit reached", partial=True)
                continue
            queue += self.page(url)
        while queue:
            self.token.check()
            url, depth, parent, integrity = queue.pop(0)
            if url in self.seen:
                continue
            self.seen.add(url)
            if url in self.done:
                continue
            if self._out_of_time():
                self._skip(url, "time limit reached", partial=True)
                continue
            queue += self.script(url, depth, parent, integrity)
        if not self.report["pages"] and not self.done:
            self.report["partial"] = True
        self.report["skipped"] = self.report["skipped"][:200]
        return self.report


def run_collection(pipeline: Any, job: Any, policy: Any, token: Any) -> dict[str, Any]:
    return Collector(pipeline, job, policy, token).run()


def describe_origin(source: Mapping[str, Any]) -> str:
    """How a source was obtained, in words for the UI."""
    origin, kind = source["origin"], source["kind"]
    if origin == "scan_evidence":
        return "stored scan evidence (URLs, status, titles, retained headers, findings)"
    if origin == "retained_body":
        return "page HTML kept because response-body retention is on" if kind == "html" else \
            "inline script from a kept page"
    if origin == "source_map":
        return "original source recovered from an in-scope source map"
    if origin == "reference":
        return "reference only (not fetched: third-party or out of scope)"
    return "page headers from a collection run (HTML not kept)" if kind == "html" else \
        "in-scope script fetched by a Collect for AI review run"
