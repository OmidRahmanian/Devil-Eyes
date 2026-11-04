"""The ``ai.analyze`` job: pre-analysis, chunking, model review, citation checks, cache.

It runs only in the AI analysis worker, which can reach the database and the
configured local model and nothing else. Pre-analysis is written first, so it
is visible even if the model is disabled, unavailable or fails. Chunks are
reviewed one at a time; results are stored after each chunk, so cancellation
(checked between chunks) and the time limit keep what was done, and a retried
job resumes where it stopped.

Model output only ever becomes stored data: candidates with verified (or
removed) citations. Nothing here starts requests, changes scope, or touches a
finding's status. Cache keys combine the chunk hash, model, prompt version,
analysis configuration and the exact example revisions retrieved, so unchanged
code is not sent to the model again.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID

from watchtower.adapters.ai.ollama import AiUnavailable, OllamaClient
from watchtower.domain.models import AssetKind, JobStatus
from watchtower.services.ai import memory, store
from watchtower.services.ai.chunking import CHARS_PER_TOKEN, Chunk, chunk_source, estimate_tokens, select_chunks
from watchtower.services.ai.collect import describe_origin
from watchtower.services.ai.endpoint import EndpointRefused
from watchtower.services.ai.output import OutputError, parse_output, verify
from watchtower.services.ai.preanalysis import match_advisories
from watchtower.services.ai.prompts import OUTPUT_SCHEMA, PROMPT_VERSION, build_messages, repair_messages
from watchtower.services.jobs import JobCancelled

PROMPT_OVERHEAD_TOKENS = 1400  # system prompt, instructions and facts
CATEGORY_CHECKS = {"outdated_library": {"vulnerable-component"},
                   "sensitive_data_in_client": {"exposed-env-file", "exposed-git-config"},
                   "debug_artifact": {"exposed-git-config", "exposed-env-file", "directory-listing"},
                   "exposed_endpoint": {"directory-listing"}}


def config_hash(settings: Any) -> str:
    material = {"num_ctx": settings.num_ctx, "max_output_tokens": settings.max_output_tokens,
                "temperature": settings.temperature, "thinking": settings.thinking, "max_chars": max_chunk_chars(settings),
                "max_examples": settings.max_examples, "example_token_budget": settings.example_token_budget}
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()[:16]


def max_chunk_chars(settings: Any) -> int:
    """Characters of code per chunk so prompt + examples + output fit ``num_ctx`` (line numbers included)."""
    tokens = settings.num_ctx - settings.max_output_tokens - PROMPT_OVERHEAD_TOKENS - settings.example_token_budget
    return max(800, int(tokens * CHARS_PER_TOKEN * 0.8))


def visibility(sources: Sequence[Mapping[str, Any]]) -> str:
    """What a review can see, in one sentence."""
    pages = sum(s["kind"] == "html" and bool(s.get("storage_uri")) for s in sources)
    header_pages = sum(s["kind"] == "html" and not s.get("storage_uri") for s in sources)
    scripts = sum(s["kind"] == "script" for s in sources)
    inline = sum(s["kind"] == "inline_script" for s in sources)
    mapped = sum(s["kind"] == "source_map_source" for s in sources)
    references = sum(s["kind"] == "reference" for s in sources)
    summary = sum(s["kind"] == "scan_summary" for s in sources)
    parts = []
    if pages:
        parts.append(f"the HTML of {pages} page{'s' * (pages > 1)}")
    if header_pages:
        parts.append(f"the security headers of {header_pages} page{'s' * (header_pages > 1)} (HTML not kept)")
    if scripts:
        parts.append(f"{scripts} in-scope script{'s' * (scripts > 1)}")
    if inline:
        parts.append(f"{inline} inline script{'s' * (inline > 1)}")
    if mapped:
        parts.append(f"{mapped} file{'s' * (mapped > 1)} recovered from source maps")
    if summary:
        parts.append("stored scan evidence (URLs, status codes, titles, retained headers and findings)")
    text = "This review is based on " + (", ".join(parts) if parts else "no stored content") + "."
    if references:
        text += f" {references} third-party or out-of-scope script{'s were' if references > 1 else ' was'} recorded but not fetched."
    return text


class Analyzer:
    def __init__(self, pipeline: Any, job: Any, token: Any) -> None:
        self.pipeline, self.job, self.token = pipeline, job, token
        self.db, self.project_id = pipeline.db, job.project_id
        self.ai = pipeline.settings.ai
        self.blobs = pipeline._blobs()
        self.analysis_id = UUID(job.payload["ai"]["analysis_id"])
        self.deadline = time.monotonic() + self.ai.max_review_seconds
        self.coverage: dict[str, Any] = {}

    # state

    def _update(self, **values: Any) -> None:
        with self.db.project(self.project_id) as uow:
            store.update_analysis(uow, self.analysis_id, **values)

    def _finish(self, status: str, *, error: str | None = None) -> dict[str, Any]:
        self._update(status=status, coverage=self.coverage, error=error, finished_at=store.now())
        return {"analysis_id": str(self.analysis_id), "status": status, "partial": status != "completed"}

    # preparation

    def _load(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        with self.db.project(self.project_id) as uow:
            record = store.analysis(uow, self.analysis_id)
            ids = record["source_ids"]
            rows = store.sources(uow, ids=ids) if ids else store.sources(uow, run_id=record["run_id"] or self.job.run_id)
            if record["status"] not in store.FINISHED:
                store.update_analysis(uow, self.analysis_id, status="running", started_at=record["started_at"] or store.now(),
                                      source_ids=[str(row["id"]) for row in rows])
        return record, rows

    def _advisories(self) -> list[dict[str, Any]]:
        intelligence = self.pipeline.settings.intelligence
        if not (intelligence.advisory_file or intelligence.advisory_url):
            return []
        try:
            from watchtower.services.intelligence import IntelligenceService
            return list(IntelligenceService(self.pipeline.settings).store.records("advisories"))
        except Exception:  # an unreadable cache makes advisory matching unavailable, never the review
            return []

    def prepare(self, rows: list[dict[str, Any]]) -> tuple[list[Chunk], dict[str, Any], dict[str, Any]]:
        texts: dict[str, Any] = {}
        facts: list[dict[str, Any]] = []
        libraries: list[dict[str, Any]] = []
        expired = []
        for row in rows:
            pre = row.get("preanalysis") or {}
            facts += pre.get("facts", [])
            libraries += pre.get("libraries", [])
            try:
                content = store.read_content(row, self.blobs)
            except Exception:
                content = None
                expired.append(str(row["id"]))
            if row.get("storage_uri") and content is None:
                expired.append(str(row["id"]))
            if content is not None:
                texts[str(row["id"])] = (row, content)
        chunks: list[Chunk] = []
        limit = max_chunk_chars(self.ai)
        for source_id, (row, content) in texts.items():
            own = [f for f in facts if f.get("source_id") == source_id]
            chunks += chunk_source(content.text, source_id=source_id, url=row.get("final_url") or row["url"],
                                   kind=row["kind"], max_chars=limit, truncated=row["truncated"],
                                   redacted=[(r.out_start, r.out_end) for r in content.replacements], facts=own)
        selection = select_chunks(chunks, max_chunks=self.ai.max_chunks, max_total_chars=self.ai.max_total_bytes)
        advisories = match_advisories(libraries, self._advisories())
        preanalysis = {"facts": facts[:2000], "libraries": libraries[:200], "advisories": advisories[:200],
                       "counts": _count(facts)}
        self.coverage = {
            "visible": visibility(rows), "not_visible": ["Server-side code is not visible to scans."],
            "sources": [{"id": str(r["id"]), "kind": r["kind"], "url": r["url"], "origin": describe_origin(r),
                         "size_bytes": r["size_bytes"], "redactions": r["redactions"], "truncated": r["truncated"],
                         "sha256": r["sha256"], "redacted_sha256": r["redacted_sha256"],
                         "used_source_map": bool((r.get("details") or {}).get("used_source_map"))} for r in rows],
            "expired_sources": expired, "chunks": [dict(c.describe(), status="pending") for c in selection.chunks],
            "skipped": selection.skipped, "redaction_note": _redaction_note(rows), "conflicting_examples": [],
            "token_estimate": sum(c.tokens for c in selection.chunks), "model_notes": [],
        }
        if expired:
            self.coverage["not_visible"].append(f"{len(expired)} source(s) passed their retention period and were not read.")
        if any(r["kind"] == "scan_summary" for r in rows) and not any(r["kind"] == "html" for r in rows):
            self.coverage["not_visible"].append("Scans keep only a few headers; CSP, framing and CORS headers need a "
                                                "Collect for AI review run.")
        self.texts = texts
        return selection.chunks, preanalysis, texts

    # model

    def _requester_may_use_memory(self, record: Mapping[str, Any]) -> bool:
        principal = record.get("requested_by")
        if principal is None:
            return False
        with self.db.system() as system:
            memberships = dict(system.auth.memberships(principal))
            account = system.auth.get_principal(principal)
        return self.project_id in memberships and account is not None and not account.disabled

    def _chat(self, client: Any, messages: list[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str], int]:
        options = {"schema": OUTPUT_SCHEMA, "num_ctx": self.ai.num_ctx, "max_output_tokens": self.ai.max_output_tokens,
                   "temperature": self.ai.temperature, "thinking": self.ai.thinking}
        reply = client.chat(self.ai.model, messages, **options)
        try:
            if reply.truncated:
                raise OutputError("the answer was cut off at the output token limit; be shorter")
            return parse_output(reply.content)
        except OutputError as problem:
            second = client.chat(self.ai.model, repair_messages(messages, reply.content, str(problem)), **options)
            if second.truncated:
                raise OutputError("the repaired answer was also cut off at the output token limit") from None
            return parse_output(second.content)

    def run(self) -> dict[str, Any]:
        record, rows = self._load()
        if record["status"] in store.FINISHED:
            return {"analysis_id": str(self.analysis_id), "status": record["status"], "recorded": True}
        previous = record.get("coverage") or {}
        chunks, preanalysis, texts = self.prepare(rows)
        done = {(c["source_id"], c["sha256"]): c for c in previous.get("chunks", []) if c.get("status") in ("analyzed", "cached", "failed")}
        for entry in self.coverage["chunks"]:
            if (entry["source_id"], entry["sha256"]) in done:
                entry.update(status=done[(entry["source_id"], entry["sha256"])]["status"],
                             reason=done[(entry["source_id"], entry["sha256"])].get("reason", ""))
        self._update(preanalysis=preanalysis, coverage=self.coverage, model=self.ai.model if record["mode"] == "model" else "")
        if record["mode"] == "preanalysis_only":
            self.coverage["model_notes"].append("Pre-analysis only: no model was used.")
            return self._finish("completed")
        if not self.ai.enabled:
            self.coverage["model_notes"].append("AI review is disabled; only pre-analysis is shown.")
            return self._finish("partial")
        if not chunks:
            self.coverage["model_notes"].append("No stored code or content to send to the model.")
            return self._finish("partial" if rows else "failed", error=None if rows else "no sources to review")
        client = self.pipeline.adapters.ai_client or OllamaClient.from_settings(self.ai)
        try:
            installed = client.models()
        except (AiUnavailable, EndpointRefused) as error:
            self.coverage["model_notes"].append(f"Model not used: {error}")
            return self._finish("failed", error=f"model unavailable: {error}; pre-analysis results are shown")
        if self.ai.model not in installed:
            message = f"model {self.ai.model} is not installed (installed: {', '.join(installed) or 'none'})"
            self.coverage["model_notes"].append(message)
            return self._finish("failed", error=message + "; pre-analysis results are shown")
        use_memory = self.ai.max_examples > 0 and self._requester_may_use_memory(record)
        with self.db.project(self.project_id) as uow:
            pool = memory.eligible(uow) if use_memory else []
        if not use_memory and self.ai.max_examples > 0:
            self.coverage["model_notes"].append("Project memory was not used: the requester no longer has access.")
        settings_hash = config_hash(self.ai)
        failures = 0
        try:
            for chunk, entry in zip(chunks, self.coverage["chunks"]):
                if entry["status"] != "pending":
                    continue
                self.token.check()
                if time.monotonic() > self.deadline:
                    entry.update(status="skipped", reason=f"time limit of {self.ai.max_review_seconds}s reached")
                    continue
                if failures >= 2:
                    entry.update(status="skipped", reason="model unavailable")
                    continue
                failures = self._review_chunk(client, chunk, entry, texts, preanalysis, pool, settings_hash, failures)
                self._update(coverage=self.coverage)
        except JobCancelled as stop:
            if not (stop.shutdown or stop.lease_lost):
                for entry in self.coverage["chunks"]:
                    if entry["status"] == "pending":
                        entry.update(status="skipped", reason="cancelled")
                self._finish("cancelled")
            else:
                self._update(coverage=self.coverage)  # requeued: the next attempt resumes from here
            raise
        statuses = {entry["status"] for entry in self.coverage["chunks"]}
        if statuses <= {"analyzed", "cached"} and not self.coverage["skipped"] and not self.coverage["expired_sources"]:
            return self._finish("completed")
        if statuses & {"analyzed", "cached"}:
            return self._finish("partial")
        return self._finish("failed", error="no chunk could be reviewed by the model; pre-analysis results are shown")

    def _review_chunk(self, client: Any, chunk: Chunk, entry: dict[str, Any], texts: Mapping[str, Any],
                      preanalysis: Mapping[str, Any], pool: list[dict[str, Any]], settings_hash: str, failures: int) -> int:
        row, content = texts[chunk.source_id]
        chunk_facts = [f for f in preanalysis["facts"] if f.get("source_id") == chunk.source_id
                       and f.get("start") is not None and chunk.start <= f["start"] < chunk.end]
        libraries = [lib for lib in preanalysis["libraries"] if lib.get("source_id") == chunk.source_id]
        examples, conflicts = memory.retrieve(pool, memory.chunk_context(text=chunk.text, url=chunk.url, facts=chunk_facts,
                                                                         libraries=libraries),
                                              limit=self.ai.max_examples, token_budget=self.ai.example_token_budget)
        if conflicts:
            known = {tuple(c["examples"]) for c in self.coverage["conflicting_examples"]}
            self.coverage["conflicting_examples"] += [c for c in conflicts if tuple(c["examples"]) not in known]
        key = store.cache_key(chunk_sha256=chunk.sha256, model=self.ai.model, prompt_version=PROMPT_VERSION,
                              config_hash=settings_hash, examples=[(e["id"], e["revision"]) for e in examples])
        with self.db.project(self.project_id) as uow:
            hit = store.cached(uow, key)
        if hit is not None:
            result, status = hit, "cached"
        else:
            source = {"kind": row["kind"], "url": chunk.url, "origin_label": describe_origin(row)}
            messages = build_messages(chunk=chunk, source=source, facts=chunk_facts, examples=examples,
                                      visibility=self.coverage["visible"])
            if estimate_tokens("".join(m["content"] for m in messages)) + self.ai.max_output_tokens > self.ai.num_ctx:
                entry.update(status="skipped", reason="does not fit the model's context window (ai.num_ctx)")
                return failures
            try:
                candidates, not_visible, dropped = self._chat(client, messages)
            except AiUnavailable as error:
                entry.update(status="failed", reason=f"model error: {error}")
                return failures + 1
            except OutputError as error:
                entry.update(status="failed", reason=f"invalid model output after one repair: {error}")
                return failures
            result, status = {"candidates": candidates, "not_visible": not_visible, "dropped": dropped}, "analyzed"
            with self.db.project(self.project_id) as uow:
                store.store_cache(uow, key, model=self.ai.model, prompt_version=PROMPT_VERSION, result=result)
        self._store(chunk, row, content, result, examples)
        for note in result.get("not_visible", []):
            if note not in self.coverage["not_visible"]:
                self.coverage["not_visible"].append(note)
        entry.update(status=status, reason="", examples=[{"id": e["id"], "revision": e["revision"], "why": e["why"]}
                                                          for e in examples],
                     dropped=result.get("dropped", 0))
        return 0

    def _store(self, chunk: Chunk, row: Mapping[str, Any], content: Any, result: Mapping[str, Any],
               examples: list[dict[str, Any]]) -> None:
        with self.db.project(self.project_id) as uow:
            store.record_usage(uow, self.analysis_id, examples)
            ordinal = store.next_ordinal(uow, self.analysis_id)
            for raw in result.get("candidates", []):
                candidate = verify(raw, chunk=chunk, source_text=content.text, redacted=content,
                                   source_id=chunk.source_id, examples=examples)
                candidate["affected"] = candidate.get("affected") or chunk.url
                finding = _matching_finding(uow, candidate, row)
                if finding is not None:
                    candidate["claims"].append({"text": f"An existing check ({finding[1]}) reported a related finding.",
                                                "claim_type": "verified_by_check"})
                store.add_candidate(uow, self.analysis_id, ordinal, candidate, finding[0] if finding else None)
                ordinal += 1


def _count(facts: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in facts:
        counts[item["category"]] = counts.get(item["category"], 0) + 1
    return counts


def _redaction_note(rows: Sequence[Mapping[str, Any]]) -> str:
    total = sum(row["redactions"] for row in rows)
    if not total:
        return ""
    return (f"{total} secret-like value(s) were redacted before storage; the review cannot see them, which may "
            "limit what it can say about how they are used.")


def _matching_finding(uow: Any, candidate: Mapping[str, Any], row: Mapping[str, Any]) -> tuple[UUID, str] | None:
    checks = CATEGORY_CHECKS.get(candidate["category"])
    if not checks:
        return None
    from urllib.parse import urlsplit
    host = urlsplit(candidate.get("affected") if "://" in str(candidate.get("affected")) else row["url"]).hostname
    asset = uow.assets.find(AssetKind.HOSTNAME, host) if host else None
    if asset is None:
        return None
    for finding in uow.findings.list(asset_id=asset.id, limit=200):
        check = finding.details.get("check_id", finding.source)
        if check in checks:
            return finding.id, check
    return None


def run_analysis(pipeline: Any, job: Any, token: Any) -> dict[str, Any]:
    return Analyzer(pipeline, job, token).run()


def settle_run(uow: Any, run_jobs: Sequence[Any]) -> None:
    """Close analyses of an AI run that stopped before its analysis job could finish them."""
    statuses = {job.status for job in run_jobs}
    if JobStatus.CANCELLED in statuses:
        status, error = "cancelled", None
    elif JobStatus.FAILED in statuses:
        errors = [job.last_error for job in run_jobs if job.last_error]
        status, error = "failed", "the run stopped before the analysis finished: " + (errors[-1] or "")[:300] if errors else \
            "the run stopped before the analysis finished"
    else:
        return
    for record in store.analyses(uow, run_id=run_jobs[0].run_id):
        if record["status"] in ("queued", "running"):
            store.update_analysis(uow, record["id"], status=status, error=error, finished_at=store.now())
