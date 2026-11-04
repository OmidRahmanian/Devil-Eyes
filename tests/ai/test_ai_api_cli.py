"""Phase 6: the AI routes and CLI commands enforce the same roles, isolation and audit as the services."""

from __future__ import annotations

import io
import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from conftest import FakeModel, FakeSite, ai_settings, site_responses
from watchtower import cli
from watchtower.api import create_app
from watchtower.security.auth import ProjectRole
from watchtower.services.jobs import AI_JOB_KINDS, JOB_KINDS, PipelineAdapters
from watchtower.services.scope import ScopeService
from watchtower.workers.runtime import Worker


@pytest.fixture
def tokens(database, project_id, other_project_id, scoped):
    scoped(project_id)
    scoped(other_project_id)
    out = {}
    with database.system() as system:
        for project, prefix in ((project_id, ""), (other_project_id, "other_")):
            for role in ProjectRole:
                principal = system.auth.create_principal(f"{prefix}{role.value}-{uuid4().hex[:6]}")
                system.auth.set_membership(project, principal.id, role)
                out[prefix + role.value] = system.auth.issue_token(principal.id, "test").secret
    return out


def headers(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def api(database, blobs, tmp_path):
    def make(**ai):
        app = create_app(database, settings=ai_settings(**ai), blobs=blobs, runs=None, frontend=tmp_path / "none")
        return TestClient(app)
    return make


def drain(database, blobs, settings=None):
    settings = settings or ai_settings()
    scope = ScopeService(database, settings.scope)
    responses = site_responses()
    adapters = PipelineAdapters(prober=lambda policy: FakeSite(policy, responses), blobs=blobs, ai_client=FakeModel())
    Worker(database, scope, settings=settings, adapters=adapters, kinds=[*JOB_KINDS, *AI_JOB_KINDS]).run_until_idle()


def test_api_roles_and_full_feedback_and_memory_flow(api, tokens, project_id, database, blobs):
    client = api()
    base = f"/api/v1/projects/{project_id}/ai"
    assert client.get(base + "/status", headers=headers(tokens["viewer"])).status_code == 200
    body = {"urls": ["https://www.example.com/"], "review": True}
    assert client.post(base + "/collections", json=body, headers=headers(tokens["viewer"])).status_code == 403
    started = client.post(base + "/collections", json=body, headers=headers(tokens["operator"]))
    assert started.status_code == 202 and started.json()["run"]["kind"] == "ai.collect"
    assert client.post(base + "/collections", json={"urls": ["https://evil.test/"]},
                       headers=headers(tokens["operator"])).status_code == 409
    drain(database, blobs)
    analysis_id = started.json()["analysis_id"]
    detail = client.get(f"{base}/reviews/{analysis_id}", headers=headers(tokens["viewer"])).json()
    assert detail["status"] == "completed"
    candidate = next(c for c in detail["candidates"] if c["supported"])
    feedback_url = f"{base}/candidates/{candidate['id']}/feedback"
    assert client.post(feedback_url, json={"kind": "looks_correct"}, headers=headers(tokens["viewer"])).status_code == 403
    assert client.post(feedback_url, json={"kind": "false_positive"},
                       headers=headers(tokens["operator"])).status_code == 409  # a reason is required
    submitted = client.post(feedback_url, json={"kind": "false_positive", "reason": "escaped upstream",
                                                "submit_memory": True}, headers=headers(tokens["operator"]))
    assert submitted.status_code == 201
    example_id = submitted.json()["example_id"]
    approve = f"{base}/memory/{example_id}/approve"
    assert client.post(approve, json={}, headers=headers(tokens["operator"])).status_code == 403
    assert client.post(approve, json={}, headers=headers(tokens["owner"])).json()["status"] == "approved"
    listed = client.get(base + "/memory", headers=headers(tokens["viewer"])).json()
    assert [e["id"] for e in listed] == [example_id]
    assert client.post(f"{base}/memory/{example_id}/disable", json={"reason": "x"},
                       headers=headers(tokens["operator"])).status_code == 403
    assert client.post(f"{base}/memory/{example_id}/disable", json={"reason": "x"},
                       headers=headers(tokens["owner"])).json()["status"] == "disabled"
    assert client.patch(base + "/settings", json={"retain_response_bodies": True},
                        headers=headers(tokens["operator"])).status_code == 403
    assert client.patch(base + "/settings", json={"allow_source_maps": True},
                        headers=headers(tokens["owner"])).json()["allow_source_maps"] is True
    assert client.patch(base + "/settings", json={"unknown": True}, headers=headers(tokens["owner"])).status_code == 422
    preview = client.post(base + "/preview", json={}, headers=headers(tokens["operator"]))
    assert preview.status_code == 200 and preview.json()["files"]
    # Cross-project: another project's token sees nothing here.
    assert client.get(base + "/status", headers=headers(tokens["other_owner"])).status_code == 404
    assert client.get(f"{base}/reviews/{analysis_id}", headers=headers(tokens["other_owner"])).status_code == 404
    with database.project(project_id) as uow:
        from sqlalchemy import select
        from watchtower.persistence.tables import audit_events
        actions = set(uow.connection.execute(select(audit_events.c.action).where(
            audit_events.c.project_id == project_id)).scalars())
    assert {"ai.collection_requested", "ai.review_requested", "ai.feedback_submitted", "ai.memory_approved",
            "ai.memory_disabled", "ai.settings_changed"} <= actions


def test_api_reports_disabled_ai_and_still_allows_pre_analysis(api, tokens, project_id):
    client = api(enabled=False)
    base = f"/api/v1/projects/{project_id}/ai"
    response = client.post(base + "/collections", json={}, headers=headers(tokens["operator"]))
    assert response.status_code == 409 and response.json()["error"] == "ai_disabled"
    check = client.post(base + "/check", headers=headers(tokens["viewer"])).json()
    assert check["outcome"] == "disabled"
    pre = client.post(base + "/reviews", json={"use_model": False}, headers=headers(tokens["operator"]))
    assert pre.status_code == 202


def run_cli(monkeypatch, database, token, *args, **ai):
    monkeypatch.setenv("WATCHTOWER_TOKEN", token)
    monkeypatch.setenv("WATCHTOWER__AI__ENABLED", "true" if ai.get("enabled", True) else "false")
    monkeypatch.setenv("WATCHTOWER__SCOPE__POLICY_CACHE_SECONDS", "0")
    out = io.StringIO()
    code = cli.main(list(args), out=out, database=database)
    return code, out.getvalue()


def test_cli_uses_the_same_permission_checks(monkeypatch, database, tokens, project_id, blobs, tmp_path, capsys):
    monkeypatch.setenv("WATCHTOWER__PIPELINE__EVIDENCE_ROOT", str(tmp_path / "evidence"))
    project = str(project_id)
    code, output = run_cli(monkeypatch, database, tokens["viewer"], "--project", project, "ai", "status", "--json")
    assert code == 0 and json.loads(output)["enabled"] is True
    code, _ = run_cli(monkeypatch, database, tokens["viewer"], "--project", project, "ai", "collect",
                      "--url", "https://www.example.com/")
    assert code == 2 and "permission denied" in capsys.readouterr().err
    code, output = run_cli(monkeypatch, database, tokens["operator"], "--project", project, "ai", "collect",
                           "--url", "https://www.example.com/", "--review", "--json")
    assert code == 0
    analysis_id = json.loads(output)["analysis_id"]
    drain(database, blobs.__class__(tmp_path / "evidence"))
    code, output = run_cli(monkeypatch, database, tokens["viewer"], "--project", project, "ai", "show", analysis_id)
    assert code == 0 and "ISSUE CANDIDATE" in output and "UNSUPPORTED" in output and "\x1b]" not in output
    code, output = run_cli(monkeypatch, database, tokens["viewer"], "--project", project, "ai", "results", "--json")
    assert json.loads(output)[0]["id"] == analysis_id
    candidate = next(c for c in json.loads(run_cli(monkeypatch, database, tokens["viewer"], "--project", project, "ai",
                                                   "show", analysis_id, "--json")[1])["candidates"] if c["supported"])
    code, output = run_cli(monkeypatch, database, tokens["operator"], "--project", project, "ai", "feedback",
                           candidate["id"], "--kind", "false_positive", "--reason", "sanitized", "--memory", "--json")
    example_id = json.loads(output)["example_id"]
    code, _ = run_cli(monkeypatch, database, tokens["operator"], "--project", project, "ai", "memory", "approve", example_id)
    assert code == 2
    code, output = run_cli(monkeypatch, database, tokens["owner"], "--project", project, "ai", "memory", "approve",
                           example_id)
    assert code == 0 and "approved" in output
    code, _ = run_cli(monkeypatch, database, tokens["owner"], "--project", project, "ai", "check", enabled=False)
    assert code == 5
    code, _ = run_cli(monkeypatch, database, tokens["operator"], "--project", project, "ai", "settings",
                      "--retain-bodies", "on")
    assert code == 2


def test_dashboard_has_the_ai_review_area_and_renders_text_only():
    from pathlib import Path
    frontend = Path(__file__).resolve().parents[2] / "frontend"
    page, script = (frontend / "index.html").read_text(), (frontend / "app.js").read_text()
    assert 'data-view="ai"' in page
    for view in ("views.ai =", "views.aiReview =", "views.aiPending =", "views.aiMemory =", "views.aiAdvanced ="):
        assert view in script
    assert "Approved examples can guide future reviews in this project. This does not retrain the model." in script
    assert "Preview what will be sent" in script
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in script, sink
