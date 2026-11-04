"""``AiService``: what the API, CLI and terminal call for AI review, feedback and memory.

Every method checks the caller's permission here, in the backend, and records
an audit event for each change (and for connection checks, without content):

* viewer: read analyses, evidence summaries and approved memory;
* operator: request reviews and collections (within scope) and submit feedback;
* owner: approve, reject, edit, disable and re-enable memory examples, and
  change AI and retention settings (including source maps and body retention).

Approving one's own submission is a separate, explicit action recorded as
self-approved, and the project can require a second reviewer instead.
Feedback never changes a finding's workflow status; AI candidates are never
promoted to findings.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from watchtower.config.settings import Settings
from watchtower.domain.errors import AiDisabled, AiInvalidAction, NotFound, PermissionDenied, ScopeViolation
from watchtower.domain.models import AssetKind
from watchtower.persistence.database import Database
from watchtower.persistence.repositories.audit import record_audit
from watchtower.security.auth import Permission, ProjectContext
from watchtower.services.ai import MEMORY_SENTENCE, memory, store
from watchtower.services.ai.analyze import config_hash, max_chunk_chars, visibility
from watchtower.services.ai.chunking import chunk_source, select_chunks
from watchtower.services.ai.collect import describe_origin
from watchtower.services.ai.preanalysis import CATEGORIES
from watchtower.services.ai.prompts import PROMPT_VERSION
from watchtower.services.ai.redaction import LineIndex, redact
from watchtower.services.ai.status import connection_check

FEEDBACK_KINDS = ("looks_correct", "false_positive", "edit")
VERDICTS = {"looks_correct": "looks_correct", "false_positive": "false_positive", "edit": "corrected"}


def _require(actor: ProjectContext, project_id: UUID, permission: Permission) -> None:
    if actor.project_id != project_id:
        raise PermissionDenied(f"credentials are for project {actor.project_id}, not {project_id}")
    actor.require(permission)


def scan_summary(uow: Any, *, finding_id: UUID | None = None) -> tuple[str, list[dict[str, Any]]]:
    """Stored scan evidence as reviewable text, with the facts it supports (no new requests)."""
    lines = ["# Stored scan evidence (URLs, status codes, titles, retained headers, findings)"]
    pending: list[tuple[str, str, str]] = []  # (needle, category, detail)
    findings = [uow.findings.get(finding_id)] if finding_id else list(uow.findings.list(limit=200))
    findings = [f for f in findings if f is not None]
    if finding_id and not findings:
        raise NotFound(f"finding {finding_id} not found")
    hosts = {f.asset_id for f in findings} if finding_id else None
    for asset in uow.assets.list(kind=AssetKind.HOSTNAME, limit=500):
        if hosts is not None and asset.id not in hosts:
            continue
        http = (asset.attributes or {}).get("last_http") or {}
        if not http.get("url"):
            continue
        headers = {str(k).lower(): str(v) for k, v in (http.get("headers") or {}).items()}
        lines.append(f"## {http['url']}  status {http.get('status_code')}  title {http.get('title', '')!r}")
        for name in ("server", "x-powered-by", "strict-transport-security", "location", "content-type"):
            if name in headers:
                lines.append(f"{name}: {headers[name]}")
        if str(http["url"]).startswith("https://") and http.get("status_code") and "strict-transport-security" not in headers:
            needle = f"## {http['url']}"
            pending.append((needle, "other", "Strict-Transport-Security (HSTS) header is missing on an HTTPS page"))
        if "x-powered-by" in headers:
            pending.append((f"x-powered-by: {headers['x-powered-by']}", "debug_artifact",
                            "X-Powered-By discloses the server technology"))
    if findings:
        lines.append("## Findings from existing checks")
        for finding in findings:
            check = finding.details.get("check_id", finding.source)
            lines.append(f"- [{finding.severity.value}] {finding.title} (check {check}, status {finding.status.value}, "
                         f"finding {finding.id})")
            excerpt = (finding.details.get("evidence_excerpt") or finding.details.get("detail") or "")
            if excerpt:
                lines.append(f"  detail: {str(excerpt)[:500]}")
    text = "\n".join(lines) + "\n"
    return text, pending


def _summary_facts(text: str, pending: Sequence[tuple[str, str, str]], source_id: str) -> list[dict[str, Any]]:
    index = LineIndex(text)
    facts = []
    for needle, category, detail in pending:
        start = text.find(needle)
        if start < 0:
            continue
        facts.append({"kind": "header", "category": category, "detail": detail, "source_id": source_id,
                      "line": index.line(start), "start": start, "end": start + len(needle),
                      "excerpt": needle[:240], "weight": 1})
    return facts


class AiService:
    def __init__(self, database: Database, scope: Any, settings: Settings | None = None, *, blobs: Any = None,
                 runs: Any = None, client: Any = None) -> None:
        self.db = database
        self.scope = scope
        self.settings = settings or Settings()
        self.ai = self.settings.ai
        self._blobs = blobs
        self._runs = runs
        self.client = client

    @property
    def blobs(self) -> Any:
        if self._blobs is None:
            from watchtower.api.storage import default_evidence_root
            from watchtower.services.evidence_store import FilesystemBlobStore
            self._blobs = FilesystemBlobStore(default_evidence_root(self.settings))
        return self._blobs

    @property
    def runs(self) -> Any:
        if self._runs is None:
            from watchtower.services.jobs import RunService
            self._runs = RunService(self.db, self.scope, settings=self.settings)
        return self._runs

    def _audit(self, uow: Any, action: str, subject: Any, actor: ProjectContext, details: Mapping[str, Any]) -> None:
        record_audit(uow.connection, action, str(subject), project_id=uow.project_id, actor=actor.principal.id,
                     details=dict(details))

    # -- status and settings -------------------------------------------------

    def status(self, project_id: UUID, *, actor: ProjectContext) -> dict[str, Any]:
        _require(actor, project_id, Permission.VIEW)
        with self.db.project(project_id) as uow:
            switches = store.project_settings(uow)
            recent = store.analyses(uow, limit=1)
            pending = len(memory.examples(uow, statuses=["submitted"])) if actor.can(Permission.MANAGE_MEMORY) else None
            approved = len(memory.examples(uow, statuses=["approved"]))
        return {"enabled": self.ai.enabled, "endpoint": self.ai.endpoint, "model": self.ai.model,
                "num_ctx": self.ai.num_ctx, "allow_private_endpoint": self.ai.allow_private_endpoint,
                "project": {k: v for k, v in switches.items() if k in store.PROJECT_SWITCHES},
                "latest_analysis": _analysis_summary(recent[0]) if recent else None,
                "memory": {"approved": approved, "awaiting_approval": pending, "explanation": MEMORY_SENTENCE},
                "advanced": self.ai.model_dump(), "can_manage_memory": actor.can(Permission.MANAGE_MEMORY),
                "can_change_settings": actor.can(Permission.MANAGE_PROJECT), "can_operate": actor.can(Permission.OPERATE)}

    def check(self, project_id: UUID, *, actor: ProjectContext) -> dict[str, Any]:
        _require(actor, project_id, Permission.VIEW)
        report = connection_check(self.ai, client=self.client)
        with self.db.project(project_id) as uow:
            self._audit(uow, "ai.connection_checked", "ai", actor, {"outcome": report.outcome})
        return report.as_dict()

    def update_settings(self, project_id: UUID, changes: Mapping[str, bool], *, actor: ProjectContext) -> dict[str, Any]:
        _require(actor, project_id, Permission.MANAGE_PROJECT)
        unknown = set(changes) - set(store.PROJECT_SWITCHES)
        if unknown:
            raise AiInvalidAction(f"unknown AI setting: {', '.join(sorted(unknown))}")
        with self.db.project(project_id) as uow:
            before = store.project_settings(uow)
            after = store.save_project_settings(uow, changes, actor.principal.id)
            changed = {k: {"from": before[k], "to": after[k]} for k in store.PROJECT_SWITCHES if before[k] != after[k]}
            self._audit(uow, "ai.settings_changed", "ai", actor, {"changes": changed})
        return {k: after[k] for k in store.PROJECT_SWITCHES}

    # -- collection and review -------------------------------------------------

    def _enabled(self) -> None:
        if not self.ai.enabled:
            raise AiDisabled("AI review is disabled (ai.enabled is false); scans and findings are unaffected")

    def request_collection(self, project_id: UUID, *, actor: ProjectContext, targets: list[str] | None = None,
                           urls: list[str] | None = None, review: bool = False, use_model: bool = True,
                           idempotency_key: str | None = None, reason: str = "") -> dict[str, Any]:
        _require(actor, project_id, Permission.OPERATE)
        self._enabled()
        policy = self.scope.current_policy(project_id)
        for url in urls or []:
            decision = policy.check_url(url)
            if not decision:
                raise ScopeViolation(decision)
        run_id = self._run_id(project_id, actor, "collect", idempotency_key)
        analysis_id = None
        if review:
            analysis_id = self._new_analysis(project_id, actor, run_id=run_id, source_ids=[], use_model=use_model)
        extra = {"ai": {"urls": list(urls or []), **({"analysis_id": str(analysis_id)} if analysis_id else {})}}
        steps = ["ai.collect", "ai.analyze"] if review else ["ai.collect"]
        try:
            run = self.runs.start_ai_run(project_id, actor=actor, kind="ai.collect", steps=steps, targets=targets,
                                         extra=extra, reason=reason or "collect for AI review", run_id=run_id)
        except Exception:
            self._abandon(project_id, analysis_id)
            raise
        with self.db.project(project_id) as uow:
            self._audit(uow, "ai.collection_requested", run.run_id, actor,
                        {"targets": list(run.targets), "urls": len(urls or []), "review": review})
            if analysis_id is not None:
                self._audit(uow, "ai.review_requested", analysis_id, actor,
                            {"after_collection": str(run.run_id), "use_model": use_model})
        return {"run": run, "analysis_id": analysis_id}

    def _run_id(self, project_id: UUID, actor: ProjectContext, label: str, key: str | None) -> UUID:
        from uuid import uuid4
        if key is None:
            return uuid4()
        if not 1 <= len(key) <= 200:
            raise ValueError("idempotency key must contain 1-200 characters")
        return uuid5(NAMESPACE_URL, f"watchtower:{project_id}:ai:{label}:{actor.principal.id}:{key}")

    def _new_analysis(self, project_id: UUID, actor: ProjectContext, *, run_id: UUID, source_ids: Sequence[str],
                      use_model: bool, reanalysis_of: UUID | None = None) -> UUID:
        analysis_id = uuid5(run_id, "analysis")
        with self.db.project(project_id) as uow:
            try:
                store.analysis(uow, analysis_id)
                return analysis_id  # a retried request with the same idempotency key
            except NotFound:
                pass
            store.create_analysis(uow, run_id=run_id, requested_by=actor.principal.id,
                                  mode="model" if use_model else "preanalysis_only", source_ids=list(source_ids),
                                  model=self.ai.model if use_model else "", prompt_version=PROMPT_VERSION,
                                  config_hash=config_hash(self.ai), reanalysis_of=reanalysis_of, analysis_id=analysis_id)
        return analysis_id

    def _abandon(self, project_id: UUID, analysis_id: UUID | None) -> None:
        if analysis_id is None:
            return
        with self.db.project(project_id) as uow:
            record = store.analysis(uow, analysis_id)
            if record["status"] == "queued":
                store.update_analysis(uow, analysis_id, status="failed", error="the run could not be queued",
                                      finished_at=store.now())

    def _review_sources(self, uow: Any, *, run_id: UUID | None, source_ids: Sequence[str] | None,
                        include_scan: bool, finding_id: UUID | None) -> tuple[list[dict[str, Any]], tuple[str, list]]:
        if source_ids:
            rows = store.sources(uow, ids=source_ids)
            if len(rows) != len(set(source_ids)):
                raise NotFound("one or more sources were not found in this project")
        else:
            run = run_id or (None if finding_id else store.latest_collection_run(uow))
            rows = store.sources(uow, run_id=run) if run else []
        summary = scan_summary(uow, finding_id=finding_id) if include_scan or finding_id else ("", [])
        return rows, summary

    def preview(self, project_id: UUID, *, actor: ProjectContext, run_id: UUID | None = None,
                source_ids: Sequence[str] | None = None, include_scan: bool = True,
                finding_id: UUID | None = None) -> dict[str, Any]:
        """What a review would send: files, sizes, redactions and a token estimate. Sends nothing."""
        _require(actor, project_id, Permission.OPERATE)
        with self.db.project(project_id) as uow:
            rows, (summary_text, _) = self._review_sources(uow, run_id=run_id, source_ids=source_ids,
                                                           include_scan=include_scan, finding_id=finding_id)
        files, chunks = [], []
        limit = max_chunk_chars(self.ai)
        for row in rows:
            content = None
            try:
                content = store.read_content(row, self.blobs)
            except Exception:
                content = None
            files.append({"id": str(row["id"]), "kind": row["kind"], "url": row["url"], "origin": describe_origin(row),
                          "size_bytes": row["size_bytes"], "redactions": row["redactions"],
                          "sent": content is not None, "truncated": row["truncated"]})
            if content is not None:
                chunks += chunk_source(content.text, source_id=str(row["id"]), url=row["url"], kind=row["kind"],
                                       max_chars=limit, facts=(row.get("preanalysis") or {}).get("facts", []))
        if summary_text:
            redacted = redact(summary_text)
            files.append({"id": "scan-summary", "kind": "scan_summary", "url": "stored scan evidence",
                          "origin": "stored scan evidence (URLs, status, titles, retained headers, findings)",
                          "size_bytes": len(summary_text.encode()), "redactions": redacted.count, "sent": True,
                          "truncated": False})
            chunks += chunk_source(redacted.text, source_id="scan-summary", url="", kind="scan_summary", max_chars=limit)
        selection = select_chunks(chunks, max_chunks=self.ai.max_chunks, max_total_chars=self.ai.max_total_bytes)
        shown = rows + ([{"kind": "scan_summary", "storage_uri": "x"}] if summary_text else [])
        return {"files": files, "chunks": len(selection.chunks), "skipped": selection.skipped,
                "token_estimate": sum(c.tokens for c in selection.chunks), "redactions": sum(f["redactions"] for f in files),
                "visible": visibility(shown) + " Server-side code is not visible to scans.",
                "model": self.ai.model, "num_ctx": self.ai.num_ctx, "enabled": self.ai.enabled,
                "memory": MEMORY_SENTENCE}

    def request_review(self, project_id: UUID, *, actor: ProjectContext, run_id: UUID | None = None,
                       source_ids: Sequence[str] | None = None, include_scan: bool = True, use_model: bool = True,
                       idempotency_key: str | None = None, reanalysis_of: UUID | None = None,
                       finding_id: UUID | None = None) -> dict[str, Any]:
        """Queue an analysis. Pre-analysis-only reviews (``use_model=False``) work even while AI is disabled."""
        _require(actor, project_id, Permission.OPERATE)
        if use_model:
            self._enabled()
        if reanalysis_of is not None:
            with self.db.project(project_id) as uow:
                previous = store.analysis(uow, reanalysis_of)
            source_ids = source_ids or [s for s in previous["source_ids"]]
            include_scan = False
        new_run = self._run_id(project_id, actor, "review", idempotency_key)
        with self.db.project(project_id) as uow:
            rows, (summary_text, pending) = self._review_sources(uow, run_id=run_id, source_ids=source_ids,
                                                                 include_scan=include_scan, finding_id=finding_id)
            ids = [str(row["id"]) for row in rows]
            if summary_text:
                source_id = uuid5(new_run, "scan-summary")
                if not store.sources(uow, ids=[source_id]):
                    content = redact(summary_text)
                    store.add_source(uow, origin="scan_evidence", kind="scan_summary", url="stored scan evidence",
                                     blobs=self.blobs, content=content, size_bytes=len(summary_text.encode()),
                                     preanalysis={"facts": _summary_facts(content.text, pending, str(source_id))},
                                     details={"finding_id": str(finding_id) if finding_id else None},
                                     retention_days=self.ai.retention_days, source_id=source_id)
                ids.append(str(source_id))
        if not ids:
            raise AiInvalidAction("nothing to review: run a scan or Collect for AI review first")
        analysis_id = self._new_analysis(project_id, actor, run_id=new_run, source_ids=ids, use_model=use_model,
                                         reanalysis_of=reanalysis_of)
        try:
            run = self.runs.start_ai_run(project_id, actor=actor, kind="ai.analyze", steps=["ai.analyze"],
                                         extra={"ai": {"analysis_id": str(analysis_id)}}, run_id=new_run,
                                         reason="AI review" + (" (pre-analysis only)" if not use_model else ""))
        except Exception:
            self._abandon(project_id, analysis_id)
            raise
        with self.db.project(project_id) as uow:
            action = "ai.reanalysis_requested" if reanalysis_of else "ai.review_requested"
            self._audit(uow, action, analysis_id, actor, {"sources": len(ids), "use_model": use_model,
                                                          "reanalysis_of": str(reanalysis_of) if reanalysis_of else None,
                                                          "finding_id": str(finding_id) if finding_id else None})
        return {"run": run, "analysis_id": analysis_id}

    # -- results ---------------------------------------------------------------

    def results(self, project_id: UUID, *, actor: ProjectContext, limit: int = 20) -> list[dict[str, Any]]:
        _require(actor, project_id, Permission.VIEW)
        with self.db.project(project_id) as uow:
            rows = store.analyses(uow, limit=limit)
            counts = store.candidate_counts(uow, [row["id"] for row in rows])
        return [{**_analysis_summary(row), "candidates": counts.get(row["id"], {"supported": 0, "unsupported": 0})}
                for row in rows]

    def result(self, project_id: UUID, analysis_id: UUID, *, actor: ProjectContext) -> dict[str, Any]:
        _require(actor, project_id, Permission.VIEW)
        with self.db.project(project_id) as uow:
            record = store.analysis(uow, analysis_id)
            rows = store.candidates(uow, record["id"])
            feedback = store.feedback_for(uow, [row["id"] for row in rows])
            examples = store.examples_for_feedback(uow, [f["id"] for items in feedback.values() for f in items])
            used = store.usage(uow, record["id"])
        candidates = []
        for row in rows:
            items = feedback.get(row["id"], [])
            data = dict(row["data"])
            if any(f["kind"] == "looks_correct" for f in items):
                data.setdefault("claims", []).append({"text": "A user reviewed this candidate and marked it as looking "
                                                              "correct (not a verification).",
                                                      "claim_type": "user_reviewed"})
            candidates.append({"id": str(row["id"]), "ordinal": row["ordinal"], "category": row["category"],
                               "title": row["title"], "supported": row["supported"],
                               "citation_status": row["citation_status"], "confidence": row["confidence"],
                               "matched_finding_id": str(row["matched_finding_id"]) if row["matched_finding_id"] else None,
                               "data": data, "feedback": [_feedback_out(f, examples.get(f["id"])) for f in items]})
        return {**_analysis_summary(record), "preanalysis": record["preanalysis"], "coverage": record["coverage"],
                "candidates": candidates,
                "examples_used": [{"id": str(u["example_id"]), "revision": u["revision"], "score": u["score"],
                                   "why": u["reason"]} for u in used],
                "memory_note": MEMORY_SENTENCE}

    # -- feedback --------------------------------------------------------------

    def submit_feedback(self, project_id: UUID, candidate_id: UUID, *, actor: ProjectContext, kind: str,
                        reason: str = "", corrected: Mapping[str, Any] | None = None, submit_memory: bool = False,
                        context: str = "") -> dict[str, Any]:
        _require(actor, project_id, Permission.OPERATE)
        if kind not in FEEDBACK_KINDS:
            raise AiInvalidAction(f"feedback must be one of {', '.join(FEEDBACK_KINDS)}")
        reason = redact(reason.strip()[:2000]).text
        if kind == "false_positive" and not reason:
            raise AiInvalidAction("a false positive needs a reason: why does it not apply here?")
        corrected = dict(corrected or {})
        if kind == "edit":
            corrected = {k: redact(str(v)[:2000]).text for k, v in corrected.items()
                         if k in ("explanation", "category", "applicability", "title") and str(v).strip()}
            if not corrected:
                raise AiInvalidAction("an edit needs a corrected explanation, category or applicability")
            if "category" in corrected and corrected["category"] not in CATEGORIES:
                raise AiInvalidAction(f"category must be one of {', '.join(CATEGORIES)}")
        from uuid import uuid4
        from watchtower.persistence.tables import ai_feedback
        with self.db.project(project_id) as uow:
            candidate = store.candidate(uow, candidate_id)
            record = store.analysis(uow, candidate["analysis_id"])
            data = candidate["data"]
            evidence = [{"source_id": c["source_id"], "redacted_sha256": c.get("redacted_sha256"),
                         "original_sha256": c.get("original_sha256"), "lines": [c["line"], c["line_end"]]}
                        for c in data.get("citations", [])]
            feedback_id = uuid4()
            uow.connection.execute(ai_feedback.insert().values(
                id=feedback_id, project_id=project_id, analysis_id=record["id"], candidate_id=candidate["id"], kind=kind,
                reason=reason, corrected=corrected, evidence=evidence, submitted_for_memory=submit_memory,
                author=actor.principal.id))
            self._audit(uow, "ai.feedback_submitted", feedback_id, actor,
                        {"candidate": str(candidate_id), "kind": kind, "memory": submit_memory})
            example_id = None
            if submit_memory:
                snippet = (data.get("citations") or [{}])[0].get("quote", "")
                source_id = (data.get("chunk") or {}).get("source_id")
                rows = store.sources(uow, ids=[source_id]) if source_id else []
                url = (rows[0].get("final_url") or rows[0]["url"]) if rows else ""
                libraries = [lib for lib in (record["preanalysis"] or {}).get("libraries", [])
                             if lib.get("source_id") == source_id]
                category = corrected.get("category", candidate["category"])
                content = {"title": corrected.get("title", candidate["title"]), "category": category,
                           "verdict": VERDICTS[kind], "explanation": corrected.get("explanation", data.get("explanation", "")),
                           "reason": reason, "snippet": snippet, "applicability": corrected.get("applicability", context)}
                conditions = memory.derive_conditions(category=category, snippet=snippet, url=url, libraries=libraries,
                                                      context=context or corrected.get("applicability", ""),
                                                      title=content["title"])
                example_id = memory.create_example(uow, content=content, conditions=conditions,
                                                   author=actor.principal.id, feedback_id=feedback_id, note=reason)
        return {"feedback_id": feedback_id, "example_id": example_id, "memory_note": MEMORY_SENTENCE if submit_memory else ""}

    # -- memory ----------------------------------------------------------------

    def memory(self, project_id: UUID, *, actor: ProjectContext, status: str | None = None) -> list[dict[str, Any]]:
        _require(actor, project_id, Permission.VIEW)
        if status is not None and status not in memory.STATUSES:
            raise AiInvalidAction(f"status must be one of {', '.join(memory.STATUSES)}")
        with self.db.project(project_id) as uow:
            if actor.can(Permission.MANAGE_MEMORY):
                rows = memory.examples(uow, statuses=[status] if status else None)
            else:
                rows = memory.examples(uow, statuses=["approved"])
                if actor.can(Permission.OPERATE):
                    rows += [r for r in memory.examples(uow, submitted_by=actor.principal.id) if r["status"] != "approved"]
                if status:
                    rows = [r for r in rows if r["status"] == status]
        return [_example_out(row) for row in rows]

    def memory_example(self, project_id: UUID, example_id: UUID, *, actor: ProjectContext) -> dict[str, Any]:
        _require(actor, project_id, Permission.VIEW)
        with self.db.project(project_id) as uow:
            row = memory.example(uow, example_id)
            visible = row["status"] == "approved" or actor.can(Permission.MANAGE_MEMORY) or \
                (actor.can(Permission.OPERATE) and row["submitted_by"] == actor.principal.id)
            if not visible:
                raise NotFound(f"memory example {example_id} not found")
            current = memory.revision(uow, row["id"], row["current_revision"])
            log = memory.history(uow, row["id"])
        return {**_example_out({**row, "content": current["content"], "conditions": current["conditions"]}),
                "revisions": [{"revision": r["revision"], "content": r["content"], "conditions": r["conditions"],
                               "author": str(r["author"]) if r["author"] else None, "note": r["note"],
                               "created_at": r["created_at"]} for r in log["revisions"]],
                "events": [{"action": e["action"], "revision": e["revision"], "actor": str(e["actor"]) if e["actor"] else None,
                            "reason": e["reason"], "at": e["created_at"]} for e in log["events"]]}

    def _change(self, project_id: UUID, example_id: UUID, actor: ProjectContext,
                apply: Callable[[Any, dict[str, Any]], tuple[str, int | None, str]]) -> dict[str, Any]:
        _require(actor, project_id, Permission.MANAGE_MEMORY)
        with self.db.project(project_id) as uow:
            row = memory.example(uow, example_id)
            action, revision, reason = apply(uow, row)
            memory.event(uow, row["id"], action, revision, actor.principal.id, reason)
            outdated = store.mark_outdated(uow, row["id"], f"memory example {action.replace('_', ' ')}")
            self._audit(uow, f"ai.memory_{action}", row["id"], actor, {"revision": revision, "reason": reason[:500],
                                                                      "analyses_marked_outdated": outdated})
            row = memory.example(uow, example_id)
        return _example_out(row) | {"analyses_marked_outdated": outdated}

    def approve(self, project_id: UUID, example_id: UUID, *, actor: ProjectContext, self_approve: bool = False,
                note: str = "") -> dict[str, Any]:
        def apply(uow: Any, row: dict[str, Any]) -> tuple[str, int | None, str]:
            if row["status"] != "submitted":
                raise AiInvalidAction(f"only submitted examples can be approved (this one is {row['status']})")
            own = row["submitted_by"] == actor.principal.id
            if own and not self_approve:
                raise AiInvalidAction("you submitted this example; approving it yourself is a separate, explicit "
                                      "self-approve action")
            if own and store.project_settings(uow)["memory_require_second_reviewer"]:
                raise AiInvalidAction("this project requires a second reviewer for project memory")
            memory.set_state(uow, row["id"], status="approved", eligible=True, approved_revision=row["current_revision"],
                             reviewed_by=actor.principal.id, reviewed_at=store.now(), self_approved=own)
            return ("self_approved" if own else "approved"), row["current_revision"], note
        return self._change(project_id, example_id, actor, apply)

    def reject(self, project_id: UUID, example_id: UUID, *, actor: ProjectContext, reason: str) -> dict[str, Any]:
        def apply(uow: Any, row: dict[str, Any]) -> tuple[str, int | None, str]:
            if not reason.strip():
                raise AiInvalidAction("a rejection needs a reason")
            if row["status"] != "submitted":
                raise AiInvalidAction(f"only submitted examples can be rejected (this one is {row['status']})")
            memory.set_state(uow, row["id"], status="rejected", eligible=False, reviewed_by=actor.principal.id,
                             reviewed_at=store.now())
            return "rejected", row["current_revision"], reason
        return self._change(project_id, example_id, actor, apply)

    def edit(self, project_id: UUID, example_id: UUID, *, actor: ProjectContext, content: Mapping[str, Any] | None = None,
             conditions: Mapping[str, Any] | None = None, note: str = "") -> dict[str, Any]:
        def apply(uow: Any, row: dict[str, Any]) -> tuple[str, int | None, str]:
            if row["status"] in ("rejected", "superseded"):
                raise AiInvalidAction(f"a {row['status']} example cannot be edited")
            current = memory.revision(uow, row["id"], row["current_revision"])
            new_content = {**current["content"], **{k: v for k, v in (content or {}).items() if v is not None}}
            new_conditions = {**current["conditions"], **{k: v for k, v in (conditions or {}).items() if v is not None}}
            if new_content.get("category") not in CATEGORIES:
                raise AiInvalidAction(f"category must be one of {', '.join(CATEGORIES)}")
            try:
                number = memory.add_revision(uow, row["id"], content=new_content, conditions=new_conditions,
                                             author=actor.principal.id, note=note)
            except ValueError as error:
                raise AiInvalidAction(f"invalid conditions: {error}") from None
            # The owner's edit of an approved example is the approval of its new revision.
            values: dict[str, Any] = {"current_revision": number}
            if row["status"] == "approved":
                values.update(approved_revision=number, reviewed_by=actor.principal.id, reviewed_at=store.now())
            memory.set_state(uow, row["id"], **values)
            return "edited", number, note
        return self._change(project_id, example_id, actor, apply)

    def disable(self, project_id: UUID, example_id: UUID, *, actor: ProjectContext, reason: str = "") -> dict[str, Any]:
        def apply(uow: Any, row: dict[str, Any]) -> tuple[str, int | None, str]:
            if row["status"] != "approved":
                raise AiInvalidAction(f"only approved examples can be disabled (this one is {row['status']})")
            memory.set_state(uow, row["id"], status="disabled", eligible=False)
            return "disabled", row["approved_revision"], reason
        return self._change(project_id, example_id, actor, apply)

    def enable(self, project_id: UUID, example_id: UUID, *, actor: ProjectContext, reason: str = "") -> dict[str, Any]:
        def apply(uow: Any, row: dict[str, Any]) -> tuple[str, int | None, str]:
            if row["status"] != "disabled" or row["approved_revision"] is None:
                raise AiInvalidAction(f"only disabled, previously approved examples can be re-enabled "
                                      f"(this one is {row['status']})")
            memory.set_state(uow, row["id"], status="approved", eligible=True)
            return "re_enabled", row["approved_revision"], reason
        return self._change(project_id, example_id, actor, apply)

    def supersede(self, project_id: UUID, example_id: UUID, *, actor: ProjectContext, by: UUID,
                  reason: str = "") -> dict[str, Any]:
        def apply(uow: Any, row: dict[str, Any]) -> tuple[str, int | None, str]:
            replacement = memory.example(uow, by)
            if replacement["id"] == row["id"] or replacement["status"] != "approved":
                raise AiInvalidAction("an example can only be superseded by a different, approved example")
            if row["status"] in ("rejected", "superseded"):
                raise AiInvalidAction(f"a {row['status']} example cannot be superseded")
            memory.set_state(uow, row["id"], status="superseded", eligible=False, superseded_by=replacement["id"])
            return "superseded", row["current_revision"], reason or f"superseded by {replacement['id']}"
        return self._change(project_id, example_id, actor, apply)


def _analysis_summary(row: Mapping[str, Any]) -> dict[str, Any]:
    coverage = row.get("coverage") or {}
    return {"id": str(row["id"]), "run_id": str(row["run_id"]) if row.get("run_id") else None, "status": row["status"],
            "mode": row["mode"], "model": row["model"], "prompt_version": row["prompt_version"],
            "created_at": row["created_at"], "finished_at": row.get("finished_at"), "error": row.get("error"),
            "outdated": row.get("outdated_at") is not None, "outdated_reason": row.get("outdated_reason"),
            "reanalysis_of": str(row["reanalysis_of"]) if row.get("reanalysis_of") else None,
            "visible": coverage.get("visible", ""), "sources": len(row.get("source_ids") or [])}


def _feedback_out(row: Mapping[str, Any], example: Mapping[str, Any] | None) -> dict[str, Any]:
    state = example["status"] if example else ("submitted" if row["submitted_for_memory"] else "")
    return {"id": str(row["id"]), "kind": row["kind"], "reason": row["reason"], "corrected": row["corrected"],
            "author": str(row["author"]) if row["author"] else None, "created_at": row["created_at"],
            "memory_example_id": str(example["id"]) if example else None, "memory_state": state}


def _example_out(row: Mapping[str, Any]) -> dict[str, Any]:
    return {"id": str(row["id"]), "status": row["status"], "eligible": row["eligible"],
            "current_revision": row["current_revision"], "approved_revision": row["approved_revision"],
            "self_approved": row["self_approved"],
            "submitted_by": str(row["submitted_by"]) if row["submitted_by"] else None,
            "reviewed_by": str(row["reviewed_by"]) if row["reviewed_by"] else None,
            "superseded_by": str(row["superseded_by"]) if row["superseded_by"] else None,
            "created_at": row["created_at"], "updated_at": row["updated_at"],
            "content": row.get("content"), "conditions": row.get("conditions"), "memory_note": MEMORY_SENTENCE}
