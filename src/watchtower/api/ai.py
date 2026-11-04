"""AI review routes: status and connection check, collection, review, results, feedback and memory.

Every route authenticates like the rest of the API and goes through
``AiService``, which enforces the role for each action and writes the audit
trail. Results contain captured website content; the dashboard renders it as
text only.
"""
from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Query
from pydantic import Field

from watchtower.api import schemas
from watchtower.api.app import Context, Services
from watchtower.domain.errors import AiInvalidAction
from watchtower.services.ai.service import AiService

router = APIRouter(prefix="/api/v1/projects/{project_id}/ai")

Text = Annotated[str, Field(max_length=4000)]
Switch = bool | None


def _service(svc: Any) -> AiService:
    return AiService(svc.database, svc.scope, svc.settings, blobs=svc.blobs)


def _run(result: dict[str, Any]) -> dict[str, Any]:
    return {**result, "run": schemas.run_out(result["run"]).model_dump(mode="json")}


class SettingsIn(schemas._In):
    retain_response_bodies: Switch = None
    allow_source_maps: Switch = None
    memory_require_second_reviewer: Switch = None
    review_changed_scripts: Switch = None


class CollectIn(schemas._In):
    targets: list[Annotated[str, Field(max_length=253)]] | None = Field(default=None, max_length=50)
    urls: list[Annotated[str, Field(max_length=2000)]] | None = Field(default=None, max_length=5)
    review: bool = False
    use_model: bool = True
    idempotency_key: Annotated[str, Field(min_length=1, max_length=200)] | None = None


class ReviewIn(schemas._In):
    run_id: UUID | None = None
    source_ids: list[UUID] | None = Field(default=None, max_length=500)
    include_scan: bool = True
    use_model: bool = True
    finding_id: UUID | None = None
    reanalysis_of: UUID | None = None
    idempotency_key: Annotated[str, Field(min_length=1, max_length=200)] | None = None


class PreviewIn(schemas._In):
    run_id: UUID | None = None
    source_ids: list[UUID] | None = Field(default=None, max_length=500)
    include_scan: bool = True
    finding_id: UUID | None = None


class FeedbackIn(schemas._In):
    kind: Literal["looks_correct", "false_positive", "edit"]
    reason: Text = ""
    explanation: Text | None = None
    category: Annotated[str, Field(max_length=64)] | None = None
    applicability: Text | None = None
    submit_memory: bool = False
    context: Text = ""


class ApproveIn(schemas._In):
    self_approve: bool = False
    note: Text = ""


class ReasonIn(schemas._In):
    reason: Text = ""


class EditIn(schemas._In):
    content: dict[str, Annotated[str, Field(max_length=4000)]] | None = None
    conditions: dict[str, Any] | None = None
    note: Text = ""


class SupersedeIn(schemas._In):
    by: UUID
    reason: Text = ""


@router.get("/status")
def status(project_id: UUID, ctx: Context, svc: Services) -> dict[str, Any]:
    return _service(svc).status(project_id, actor=ctx)


@router.post("/check")
def check(project_id: UUID, ctx: Context, svc: Services) -> dict[str, Any]:
    """Connection check: lists models and reads the chosen model's details. Sends no prompt."""
    return _service(svc).check(project_id, actor=ctx)


@router.patch("/settings")
def update_settings(project_id: UUID, body: SettingsIn, ctx: Context, svc: Services) -> dict[str, Any]:
    return _service(svc).update_settings(project_id, body.model_dump(exclude_none=True), actor=ctx)


@router.post("/collections", status_code=202)
def collect(project_id: UUID, body: CollectIn, ctx: Context, svc: Services) -> dict[str, Any]:
    try:
        return _run(_service(svc).request_collection(project_id, actor=ctx, targets=body.targets, urls=body.urls,
                                                     review=body.review, use_model=body.use_model,
                                                     idempotency_key=body.idempotency_key))
    except ValueError as error:
        raise AiInvalidAction(str(error)) from None


@router.post("/preview")
def preview(project_id: UUID, body: PreviewIn, ctx: Context, svc: Services) -> dict[str, Any]:
    """What a review would send to the model. Sends nothing."""
    return _service(svc).preview(project_id, actor=ctx, run_id=body.run_id,
                                 source_ids=[str(s) for s in body.source_ids] if body.source_ids else None,
                                 include_scan=body.include_scan, finding_id=body.finding_id)


@router.post("/reviews", status_code=202)
def request_review(project_id: UUID, body: ReviewIn, ctx: Context, svc: Services) -> dict[str, Any]:
    try:
        return _run(_service(svc).request_review(
            project_id, actor=ctx, run_id=body.run_id, source_ids=[str(s) for s in body.source_ids] if body.source_ids else None,
            include_scan=body.include_scan, use_model=body.use_model, idempotency_key=body.idempotency_key,
            reanalysis_of=body.reanalysis_of, finding_id=body.finding_id))
    except ValueError as error:
        raise AiInvalidAction(str(error)) from None


@router.get("/reviews")
def results(project_id: UUID, ctx: Context, svc: Services,
            limit: Annotated[int, Query(ge=1, le=200)] = 20) -> list[dict[str, Any]]:
    return _service(svc).results(project_id, actor=ctx, limit=limit)


@router.get("/reviews/{analysis_id}")
def result(project_id: UUID, analysis_id: UUID, ctx: Context, svc: Services) -> dict[str, Any]:
    return _service(svc).result(project_id, analysis_id, actor=ctx)


@router.post("/candidates/{candidate_id}/feedback", status_code=201)
def feedback(project_id: UUID, candidate_id: UUID, body: FeedbackIn, ctx: Context, svc: Services) -> dict[str, Any]:
    corrected = {k: v for k, v in {"explanation": body.explanation, "category": body.category,
                                   "applicability": body.applicability}.items() if v}
    return _service(svc).submit_feedback(project_id, candidate_id, actor=ctx, kind=body.kind, reason=body.reason,
                                         corrected=corrected, submit_memory=body.submit_memory, context=body.context)


@router.get("/memory")
def memory(project_id: UUID, ctx: Context, svc: Services,
           status: Annotated[str | None, Query(max_length=20)] = None) -> list[dict[str, Any]]:
    return _service(svc).memory(project_id, actor=ctx, status=status)


@router.get("/memory/{example_id}")
def memory_example(project_id: UUID, example_id: UUID, ctx: Context, svc: Services) -> dict[str, Any]:
    return _service(svc).memory_example(project_id, example_id, actor=ctx)


@router.post("/memory/{example_id}/approve")
def approve(project_id: UUID, example_id: UUID, body: ApproveIn, ctx: Context, svc: Services) -> dict[str, Any]:
    return _service(svc).approve(project_id, example_id, actor=ctx, self_approve=body.self_approve, note=body.note)


@router.post("/memory/{example_id}/reject")
def reject(project_id: UUID, example_id: UUID, body: ReasonIn, ctx: Context, svc: Services) -> dict[str, Any]:
    return _service(svc).reject(project_id, example_id, actor=ctx, reason=body.reason)


@router.post("/memory/{example_id}/edit")
def edit(project_id: UUID, example_id: UUID, body: EditIn, ctx: Context, svc: Services) -> dict[str, Any]:
    return _service(svc).edit(project_id, example_id, actor=ctx, content=body.content, conditions=body.conditions,
                              note=body.note)


@router.post("/memory/{example_id}/disable")
def disable(project_id: UUID, example_id: UUID, body: ReasonIn, ctx: Context, svc: Services) -> dict[str, Any]:
    return _service(svc).disable(project_id, example_id, actor=ctx, reason=body.reason)


@router.post("/memory/{example_id}/enable")
def enable(project_id: UUID, example_id: UUID, body: ReasonIn, ctx: Context, svc: Services) -> dict[str, Any]:
    return _service(svc).enable(project_id, example_id, actor=ctx, reason=body.reason)


@router.post("/memory/{example_id}/supersede")
def supersede(project_id: UUID, example_id: UUID, body: SupersedeIn, ctx: Context, svc: Services) -> dict[str, Any]:
    return _service(svc).supersede(project_id, example_id, actor=ctx, by=body.by, reason=body.reason)
