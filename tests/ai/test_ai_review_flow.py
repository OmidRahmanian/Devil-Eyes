"""Phases 3-5 against PostgreSQL: collection, analysis jobs, cache, feedback, memory, retrieval, roles, isolation.

Everything runs through the real queue, leases and workers with a fake site and a fake model.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import select, text

from conftest import FakeModel, FakeSite, ai_settings, site_responses, unavailable
from watchtower.adapters.ai.ollama import ChatResult
from watchtower.domain.errors import AiDisabled, AiInvalidAction, NotFound, PermissionDenied, ScopeViolation
from watchtower.domain.models import JobStatus
from watchtower.persistence.tables import ai_sources, audit_events, findings, jobs
from watchtower.services.ai import MEMORY_SENTENCE
from watchtower.services.ai.analyze import Analyzer
from watchtower.services.ai.service import AiService
from watchtower.services.jobs import AI_JOB_KINDS, JOB_KINDS, CancelToken, JobCancelled, Pipeline, PipelineAdapters, RunService
from watchtower.services.scope import ScopeService
from watchtower.workers.runtime import Worker


@dataclass
class Env:
    database: Any
    scope: Any
    settings: Any
    blobs: Any
    project_id: UUID
    actors: dict
    model: FakeModel
    site: dict

    @property
    def service(self) -> AiService:
        return AiService(self.database, self.scope, self.settings, blobs=self.blobs, client=self.model)

    def adapters(self) -> PipelineAdapters:
        requests = self.site.setdefault("requests", [])
        responses = self.site.setdefault("responses", site_responses())

        def prober(policy):
            fake = FakeSite(policy, responses)
            fake.requests = requests
            return fake

        return PipelineAdapters(prober=prober, blobs=self.blobs, ai_client=self.model)

    def work(self) -> int:
        worker = Worker(self.database, self.scope, settings=self.settings, adapters=self.adapters(),
                        kinds=[*JOB_KINDS, *AI_JOB_KINDS], heartbeat_seconds=5, lease_seconds=60)
        return worker.run_until_idle()

    def with_settings(self, **ai) -> Env:
        settings = ai_settings(**ai)
        return Env(self.database, ScopeService(self.database, settings.scope), settings, self.blobs, self.project_id,
                   self.actors, self.model, self.site)


@pytest.fixture
def env(database, scope, settings, blobs, project_id, scoped, actors):
    scoped(project_id)
    return Env(database, scope, settings, blobs, project_id, actors(project_id), FakeModel(), {})


def collect(env: Env, *, review=False, actor="operator", **options) -> dict:
    return env.service.request_collection(env.project_id, actor=env.actors[actor], urls=["https://www.example.com/"],
                                          review=review, **options)


def sources(env: Env, run_id: UUID) -> list[dict]:
    with env.database.project(env.project_id) as uow:
        return [dict(r._mapping) for r in uow.connection.execute(select(ai_sources).where(ai_sources.c.run_id == run_id))]


def run_status(env: Env, run_id: UUID) -> str:
    return RunService(env.database, env.scope).get_run(env.project_id, run_id, actor=env.actors["viewer"]).summary.status


# -- collection ----------------------------------------------------------------


def test_collection_fetches_in_scope_scripts_and_records_third_party_references_only(env):
    requested = collect(env)
    assert env.work() >= 1
    run_id = requested["run"].run_id
    rows = sources(env, run_id)
    kinds = sorted(r["kind"] for r in rows)
    assert kinds == ["html", "reference", "script"]
    assert not any("cdn.thirdparty.net" in url for url in env.site["requests"])  # never fetched
    reference = next(r for r in rows if r["kind"] == "reference")
    assert reference["details"]["integrity"] == "sha384-xyz" and reference["details"]["version_hints"] == ["1.2.3"]
    assert reference["storage_uri"] is None
    page = next(r for r in rows if r["kind"] == "html")
    assert page["storage_uri"] is None and page["details"]["body_retained"] is False  # body retention is off
    assert page["details"]["headers"]["content-security-policy"]
    assert any(f["detail"] == "CSP allows 'unsafe-inline' scripts" for f in page["preanalysis"]["facts"])
    script = next(r for r in rows if r["kind"] == "script")
    stored = env.blobs.get(script["storage_uri"]).decode()
    assert "AbC123def456ghi" not in stored and "[REDACTED]" in stored and script["redactions"] == 1
    assert script["sha256"] != script["redacted_sha256"] and script["expires_at"] is not None
    assert any(f["kind"] == "secret" for f in script["preanalysis"]["facts"])
    assert run_status(env, run_id) == "succeeded"
    detail = RunService(env.database, env.scope).get_run(env.project_id, run_id, actor=env.actors["viewer"])
    result = detail.jobs[0].result
    assert result["references"] == 1 and any("inline script" in note for note in result["notes"])
    assert any("allow_source_maps is off" in note for note in result["notes"])
    assert "https://www.example.com/static/app.js.map" not in env.site["requests"]


def test_owner_switches_enable_body_retention_source_maps_and_depth(env):
    with pytest.raises(PermissionDenied):
        env.service.update_settings(env.project_id, {"retain_response_bodies": True}, actor=env.actors["operator"])
    env.service.update_settings(env.project_id, {"retain_response_bodies": True, "allow_source_maps": True},
                                actor=env.actors["owner"])
    deeper = env.with_settings(max_fetch_depth=2)
    requested = collect(deeper)
    deeper.work()
    rows = sources(deeper, requested["run"].run_id)
    kinds = sorted(r["kind"] for r in rows)
    assert kinds == ["html", "inline_script", "reference", "script", "script", "source_map_source"]
    page = next(r for r in rows if r["kind"] == "html")
    assert page["origin"] == "retained_body" and page["storage_uri"]
    mapped = next(r for r in rows if r["kind"] == "source_map_source")
    assert mapped["details"]["used_source_map"] and any(f["kind"] == "redirect" for f in mapped["preanalysis"]["facts"])
    with deeper.database.project(deeper.project_id) as uow:
        audit = list(uow.connection.execute(select(audit_events.c.action, audit_events.c.details).where(
            audit_events.c.project_id == deeper.project_id, audit_events.c.action == "ai.settings_changed")))
    assert audit and audit[0].details["changes"]["retain_response_bodies"] == {"from": False, "to": True}


def test_collection_budgets_make_the_run_partial(env):
    small = env.with_settings(max_files=1, max_fetch_depth=2)
    small.service.update_settings(small.project_id, {"allow_source_maps": True}, actor=small.actors["owner"])
    requested = collect(small)
    small.work()
    result = RunService(small.database, small.scope).get_run(small.project_id, requested["run"].run_id,
                                                             actor=small.actors["viewer"]).jobs[0].result
    assert result["scripts"] == 1 and result["partial"]
    assert any(s["reason"].startswith("budget") for s in result["skipped"])
    assert run_status(small, requested["run"].run_id) == "partial"


def test_collection_refuses_out_of_scope_urls_and_needs_ai_enabled(env):
    with pytest.raises(ScopeViolation):
        env.service.request_collection(env.project_id, actor=env.actors["operator"], urls=["https://evil.test/"])
    with pytest.raises(PermissionDenied):
        collect(env, actor="viewer")
    with pytest.raises(AiDisabled):
        collect(env.with_settings(enabled=False))


def test_cancelled_collection_settles_its_analysis(env):
    requested = collect(env, review=True)
    RunService(env.database, env.scope).cancel_run(env.project_id, requested["run"].run_id, actor=env.actors["operator"],
                                                   reason="changed my mind")
    env.work()
    detail = env.service.result(env.project_id, requested["analysis_id"], actor=env.actors["viewer"])
    assert detail["status"] == "cancelled"


# -- analysis ------------------------------------------------------------------


def review(env: Env) -> dict:
    requested = collect(env, review=True)
    env.work()
    return env.service.result(env.project_id, requested["analysis_id"], actor=env.actors["viewer"])


def test_collect_then_review_stores_verified_candidates_and_flags_unsupported_ones(env):
    detail = review(env)
    assert detail["status"] == "completed", detail["coverage"]
    supported = [c for c in detail["candidates"] if c["supported"]]
    unsupported = [c for c in detail["candidates"] if not c["supported"]]
    assert [c["title"] for c in supported] == ["Query value written to innerHTML"]
    citation = supported[0]["data"]["citations"][0]
    assert citation["line"] == 5 and citation["original_sha256"] and citation["redacted_sha256"]
    assert unsupported and "citation not verified" in unsupported[0]["data"]["flags"]
    assert supported[0]["data"]["suggested_severity_note"].startswith("unverified")
    coverage = detail["coverage"]
    assert "1 in-scope script" in coverage["visible"] and "Server-side code is not visible to scans." in coverage["not_visible"]
    assert coverage["redaction_note"] and coverage["chunks"] and coverage["token_estimate"] > 0
    assert detail["preanalysis"]["facts"]
    # Untrusted content reached the model only as delimited, defused data.
    prompt = env.model.calls[0][-1]["content"]
    assert "AbC123def456ghi" not in prompt and "END-DATA." not in prompt and "END_DATA." in prompt
    with env.database.project(env.project_id) as uow:
        assert uow.connection.execute(select(findings.c.id)).first() is None  # never promoted to findings


def test_unchanged_evidence_is_served_from_the_cache(env):
    first = review(env)
    calls = len(env.model.calls)
    second = env.service.request_review(env.project_id, actor=env.actors["operator"],
                                        source_ids=[s["id"] for s in first["coverage"]["sources"]], include_scan=False)
    env.work()
    detail = env.service.result(env.project_id, second["analysis_id"], actor=env.actors["viewer"])
    assert len(env.model.calls) == calls  # no new model call
    assert {c["status"] for c in detail["coverage"]["chunks"]} == {"cached"}
    assert [c["title"] for c in detail["candidates"] if c["supported"]] == ["Query value written to innerHTML"]
    other_model = env.with_settings(model="qwen3:14b-q4_K_M")
    other_model.model.installed.append("qwen3:14b-q4_K_M")
    third = other_model.service.request_review(env.project_id, actor=env.actors["operator"],
                                               source_ids=[s["id"] for s in first["coverage"]["sources"]],
                                               include_scan=False)
    other_model.work()
    assert len(env.model.calls) > calls  # a different model is a cache miss
    assert other_model.service.result(env.project_id, third["analysis_id"], actor=env.actors["viewer"])["status"] == "completed"


def test_pre_analysis_only_works_while_ai_is_disabled(env):
    collect(env)
    env.work()
    off = env.with_settings(enabled=False)
    with pytest.raises(AiDisabled):
        off.service.request_review(off.project_id, actor=off.actors["operator"])
    requested = off.service.request_review(off.project_id, actor=off.actors["operator"], use_model=False)
    off.work()
    detail = off.service.result(off.project_id, requested["analysis_id"], actor=off.actors["viewer"])
    assert detail["status"] == "completed" and detail["mode"] == "preanalysis_only"
    assert detail["preanalysis"]["facts"] and detail["candidates"] == [] and env.model.calls == []


@pytest.mark.parametrize("error", [unavailable("unreachable"), unavailable("timeout")])
def test_unavailable_model_fails_the_analysis_but_keeps_pre_analysis(env, error):
    env.model.error = error
    detail = review(env)
    assert detail["status"] == "failed" and "pre-analysis results are shown" in detail["error"]
    assert detail["preanalysis"]["facts"]


def test_missing_model_is_reported_with_installed_models(env):
    env.model.installed = ["llama3:8b"]
    detail = review(env)
    assert detail["status"] == "failed" and "llama3:8b" in detail["error"]


def test_malformed_output_is_repaired_once(env):
    good = FakeModel.default

    def reply(messages, call):
        return "not json at all" if call == 1 else good(messages, call)

    env.model.reply = reply
    detail = review(env)
    assert detail["status"] == "completed" and len(env.model.calls) == 2
    assert "not valid" in env.model.calls[1][-1]["content"]


def test_output_that_stays_invalid_marks_the_chunk_failed(env):
    env.model.reply = lambda messages, call: ChatResult('{"candidates": [', "length", 1, 1)
    detail = review(env)
    assert detail["status"] == "failed"
    assert all(c["status"] == "failed" for c in detail["coverage"]["chunks"])
    assert len(env.model.calls) == 2 * len(detail["coverage"]["chunks"])


def test_thinking_blocks_never_reach_storage(env):
    good = FakeModel.default
    env.model.reply = lambda messages, call: "<think>secret reasoning</think>" + json.dumps(good(messages, call))
    env.model.chat = _strip_wrapper(env.model)
    detail = review(env)
    assert detail["status"] == "completed" and "secret reasoning" not in json.dumps(detail, default=str)


def _strip_wrapper(model):
    from watchtower.adapters.ai.ollama import strip_reasoning
    original = model.chat

    def chat(name, messages, **options):
        result = original(name, messages, **options)
        return ChatResult(strip_reasoning(result.content), result.done_reason)

    return chat


def test_cancellation_between_chunks_keeps_partial_results(env, database):
    small = env.with_settings(num_ctx=2048, max_output_tokens=128, example_token_budget=0)
    small.service.update_settings(small.project_id, {"retain_response_bodies": True}, actor=small.actors["owner"])
    requested = collect(small, review=True)
    worker = Worker(small.database, small.scope, settings=small.settings, adapters=small.adapters(), kinds=list(JOB_KINDS))
    worker.run_until_idle()  # collection only
    with database.project(small.project_id) as uow:
        job = next(j for j in uow.jobs.list_for_run(requested["run"].run_id) if j.kind == "ai.analyze")
    token = CancelToken()
    small.model.on_chat = lambda call: token.cancel("cancel requested") if call == 1 else None
    pipeline = Pipeline(small.database, small.scope, small.settings, small.adapters())
    with pytest.raises(JobCancelled):
        Analyzer(pipeline, job, token).run()
    detail = small.service.result(small.project_id, requested["analysis_id"], actor=small.actors["viewer"])
    assert detail["status"] == "cancelled"
    statuses = [c["status"] for c in detail["coverage"]["chunks"]]
    assert statuses.count("analyzed") == 1 and "skipped" in statuses


def test_scan_evidence_review_and_explain_finding(env, database):
    with database.project(env.project_id) as uow:
        uow.connection.execute(text("SELECT 1"))
    requested = env.service.request_review(env.project_id, actor=env.actors["operator"], include_scan=True)
    env.work()
    detail = env.service.result(env.project_id, requested["analysis_id"], actor=env.actors["viewer"])
    assert any(s["kind"] == "scan_summary" for s in detail["coverage"]["sources"])
    with pytest.raises(NotFound):
        env.service.request_review(env.project_id, actor=env.actors["operator"],
                                   finding_id=UUID("00000000-0000-0000-0000-000000000001"))


def test_preview_lists_what_will_be_sent_without_sending(env):
    collect(env)
    env.work()
    preview = env.service.preview(env.project_id, actor=env.actors["operator"])
    assert {f["kind"] for f in preview["files"]} >= {"html", "script", "reference", "scan_summary"}
    assert preview["token_estimate"] > 0 and preview["redactions"] >= 1 and preview["chunks"] >= 1
    assert "Server-side code is not visible" in preview["visible"] and env.model.calls == []
    with pytest.raises(PermissionDenied):
        env.service.preview(env.project_id, actor=env.actors["viewer"])


# -- feedback and memory ---------------------------------------------------------


def supported_candidate(env: Env) -> dict:
    return next(c for c in review(env)["candidates"] if c["supported"])


def test_feedback_rules_and_roles(env):
    candidate = supported_candidate(env)
    service = env.service
    with pytest.raises(PermissionDenied):
        service.submit_feedback(env.project_id, UUID(candidate["id"]), actor=env.actors["viewer"], kind="looks_correct")
    with pytest.raises(AiInvalidAction, match="reason"):
        service.submit_feedback(env.project_id, UUID(candidate["id"]), actor=env.actors["operator"], kind="false_positive")
    with pytest.raises(AiInvalidAction):
        service.submit_feedback(env.project_id, UUID(candidate["id"]), actor=env.actors["operator"], kind="edit")
    done = service.submit_feedback(env.project_id, UUID(candidate["id"]), actor=env.actors["operator"],
                                   kind="looks_correct")
    assert done["example_id"] is None
    detail = service.result(env.project_id, UUID(json.loads(json.dumps(candidate))["id"]) and
                            UUID(service.results(env.project_id, actor=env.actors["viewer"])[0]["id"]),
                            actor=env.actors["viewer"])
    reviewed = next(c for c in detail["candidates"] if c["id"] == candidate["id"])
    assert any(claim["claim_type"] == "user_reviewed" for claim in reviewed["data"]["claims"])
    with env.database.project(env.project_id) as uow:
        assert uow.connection.execute(select(findings.c.id)).first() is None  # feedback never touches findings


def submit_example(env: Env, *, actor="operator", kind="false_positive") -> UUID:
    candidate = supported_candidate(env)
    result = env.service.submit_feedback(env.project_id, UUID(candidate["id"]), actor=env.actors[actor], kind=kind,
                                         reason="name is sanitized by the server template; not reachable here",
                                         submit_memory=True, context="sanitized upstream")
    assert result["memory_note"] == MEMORY_SENTENCE
    return result["example_id"]


def test_memory_approval_rules_self_approval_and_second_reviewer(env):
    example_id = submit_example(env)
    service = env.service
    with pytest.raises(PermissionDenied):
        service.approve(env.project_id, example_id, actor=env.actors["operator"])
    assert service.memory(env.project_id, actor=env.actors["viewer"]) == []  # viewers see approved only
    assert [e["id"] for e in service.memory(env.project_id, actor=env.actors["operator"])] == [str(example_id)]
    approved = service.approve(env.project_id, example_id, actor=env.actors["owner"])
    assert approved["status"] == "approved" and approved["eligible"] and not approved["self_approved"]
    assert [e["status"] for e in service.memory(env.project_id, actor=env.actors["viewer"])] == ["approved"]
    own = submit_example(env, actor="owner")
    with pytest.raises(AiInvalidAction, match="self-approve"):
        service.approve(env.project_id, own, actor=env.actors["owner"])
    service.update_settings(env.project_id, {"memory_require_second_reviewer": True}, actor=env.actors["owner"])
    with pytest.raises(AiInvalidAction, match="second reviewer"):
        service.approve(env.project_id, own, actor=env.actors["owner"], self_approve=True)
    service.update_settings(env.project_id, {"memory_require_second_reviewer": False}, actor=env.actors["owner"])
    assert service.approve(env.project_id, own, actor=env.actors["owner"], self_approve=True)["self_approved"]
    events = service.memory_example(env.project_id, own, actor=env.actors["owner"])["events"]
    assert [e["action"] for e in events] == ["submitted", "self_approved"]


def test_memory_reject_edit_disable_enable_supersede_and_history(env):
    service = env.service
    first, second = submit_example(env), submit_example(env)
    with pytest.raises(AiInvalidAction):
        service.reject(env.project_id, first, actor=env.actors["owner"], reason=" ")
    service.reject(env.project_id, second, actor=env.actors["owner"], reason="too broad")
    with pytest.raises(AiInvalidAction):
        service.approve(env.project_id, second, actor=env.actors["owner"])
    service.approve(env.project_id, first, actor=env.actors["owner"])
    edited = service.edit(env.project_id, first, actor=env.actors["owner"],
                          content={"explanation": "sanitizeHtml escapes it"}, conditions={"context": "only on /shop"},
                          note="clarify")
    assert edited["current_revision"] == 2 and edited["approved_revision"] == 2
    disabled = service.disable(env.project_id, first, actor=env.actors["owner"], reason="re-check")
    assert disabled["status"] == "disabled" and not disabled["eligible"]
    enabled = service.enable(env.project_id, first, actor=env.actors["owner"])
    assert enabled["status"] == "approved" and enabled["eligible"]
    third = submit_example(env)
    service.approve(env.project_id, third, actor=env.actors["owner"])
    superseded = service.supersede(env.project_id, first, actor=env.actors["owner"], by=third)
    assert superseded["status"] == "superseded" and superseded["superseded_by"] == str(third)
    history = service.memory_example(env.project_id, first, actor=env.actors["owner"])
    assert [r["revision"] for r in history["revisions"]] == [1, 2]
    assert [e["action"] for e in history["events"]] == ["submitted", "approved", "edited", "disabled", "re_enabled",
                                                        "superseded"]
    with env.database.project(env.project_id) as uow:
        with pytest.raises(Exception):
            uow.connection.execute(text("UPDATE ai_memory_revisions SET note = 'x'"))  # history is append-only


def test_retrieval_uses_approved_examples_marks_outdated_and_never_leaks_across_projects(env, other_project_id, scoped,
                                                                                         actors):
    example_id = submit_example(env)
    service = env.service
    service.approve(env.project_id, example_id, actor=env.actors["owner"])
    calls_before = len(env.model.calls)
    detail = review(env)
    prompts = [call[-1]["content"] for call in env.model.calls[calls_before:]]
    assert any(str(example_id) in prompt for prompt in prompts)
    assert detail["examples_used"] and detail["examples_used"][0]["id"] == str(example_id)
    used = next(c for c in detail["candidates"] if c["supported"])["data"]["examples_used"]
    assert used and used[0]["effect"] == "lowered confidence" and used[0]["why_retrieved"]
    service.disable(env.project_id, example_id, actor=env.actors["owner"], reason="check")
    after = service.result(env.project_id, UUID(detail["id"]), actor=env.actors["viewer"])
    assert after["outdated"] and after["examples_used"]  # usage is kept forever
    # Another project never sees this project's memory.
    scoped(other_project_id)
    other = Env(env.database, env.scope, env.settings, env.blobs, other_project_id, actors(other_project_id),
                FakeModel(), {})
    calls_before = len(other.model.calls)
    review(other)
    assert not any(str(example_id) in call[-1]["content"] for call in other.model.calls[calls_before:])
    with pytest.raises(PermissionDenied):
        service.memory_example(env.project_id, example_id, actor=other.actors["owner"])
    with pytest.raises(NotFound):
        other.service.memory_example(other_project_id, example_id, actor=other.actors["owner"])
    with pytest.raises(NotFound):
        other.service.result(other_project_id, UUID(detail["id"]), actor=other.actors["owner"])


def test_requester_without_access_gets_no_memory(env, database):
    example_id = submit_example(env)
    env.service.approve(env.project_id, example_id, actor=env.actors["owner"])
    requested = collect(env, review=True)
    with database.system() as system:
        system.auth.remove_membership(env.project_id, env.actors["operator"].principal.id)
    calls_before = len(env.model.calls)
    env.work()
    assert not any(str(example_id) in call[-1]["content"] for call in env.model.calls[calls_before:])
    detail = env.service.result(env.project_id, requested["analysis_id"], actor=env.actors["viewer"])
    assert any("no longer has access" in note for note in detail["coverage"]["model_notes"])


def test_reanalysis_is_audited_and_does_not_rewrite_history(env):
    first = review(env)
    again = env.service.request_review(env.project_id, actor=env.actors["operator"], reanalysis_of=UUID(first["id"]))
    env.work()
    assert env.service.result(env.project_id, UUID(first["id"]), actor=env.actors["viewer"])["candidates"] == \
        first["candidates"]
    assert env.service.result(env.project_id, again["analysis_id"], actor=env.actors["viewer"])["reanalysis_of"] == first["id"]
    with env.database.project(env.project_id) as uow:
        actions = set(uow.connection.execute(select(audit_events.c.action).where(
            audit_events.c.project_id == env.project_id)).scalars())
    assert {"ai.collection_requested", "ai.review_requested", "ai.reanalysis_requested"} <= actions


def test_connection_check_is_audited_without_content(env):
    report = env.service.check(env.project_id, actor=env.actors["viewer"])
    assert report["outcome"] in ("ready", "model_missing", "unreachable", "refused_by_policy", "malformed", "timeout")
    with env.database.project(env.project_id) as uow:
        row = uow.connection.execute(select(audit_events.c.details).where(
            audit_events.c.action == "ai.connection_checked")).first()
    assert set(row.details) == {"outcome"}


def test_scans_are_unchanged_and_ai_jobs_are_routed_to_the_right_workers(env):
    assert "ai.analyze" not in JOB_KINDS and "ai.collect" in JOB_KINDS and AI_JOB_KINDS == ("ai.analyze",)
    requested = collect(env, review=True)
    Worker(env.database, env.scope, settings=env.settings, adapters=env.adapters(), kinds=list(JOB_KINDS)).run_until_idle()
    with env.database.project(env.project_id) as uow:
        states = {j.kind: j.status for j in uow.jobs.list_for_run(requested["run"].run_id)}
    assert states == {"ai.collect": JobStatus.SUCCEEDED, "ai.analyze": JobStatus.QUEUED}  # scan workers never analyze
    with env.database.project(env.project_id) as uow:
        keys = set(uow.connection.execute(select(jobs.c.concurrency_key).where(
            jobs.c.run_id == requested["run"].run_id)).scalars())
    assert keys == {"ai.collect", "ai.analyze"}


def test_ai_worker_installs_the_strict_guard_and_runs_only_analyses(env):
    from watchtower.services.ai.endpoint import ResolvedEndpoint, parse_endpoint
    from watchtower.workers.ai import serve_ai
    collect(env)  # an ai.collect job, which the AI worker must leave alone
    review = env.service.request_review(env.project_id, actor=env.actors["operator"], use_model=False)
    resolved = ResolvedEndpoint(parse_endpoint("http://windows-host:11434"), "172.24.160.1", "private")
    guarded = []
    ran = serve_ai(env.database, env.scope, env.settings, drain=True, client=env.model, resolved=resolved,
                   guard=lambda settings, endpoint: guarded.append(endpoint.pair))
    # Workers claim due jobs across projects; other tests in this database may have left analyses queued.
    assert guarded == [("172.24.160.1", 11434)] and ran >= 1
    with env.database.project(env.project_id) as uow:
        kinds = {j.kind: j.status for run in RunService(env.database, env.scope).list_runs(
            env.project_id, actor=env.actors["viewer"]) for j in uow.jobs.list_for_run(run.run_id)}
    assert kinds["ai.collect"] is JobStatus.QUEUED and kinds["ai.analyze"] is JobStatus.SUCCEEDED
    assert env.service.result(env.project_id, review["analysis_id"], actor=env.actors["viewer"])["status"] == "completed"
