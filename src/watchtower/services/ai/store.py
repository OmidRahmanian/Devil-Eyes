"""Reading and writing AI review rows inside a project-scoped unit of work.

Every function takes a ``ProjectUnitOfWork`` (row-level security confines it to
one project) and filters on ``project_id`` as well. Content blobs are redacted
before they are stored and read back with digest verification.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert

from watchtower.domain.errors import NotFound
from watchtower.persistence.tables import (
    ai_analyses, ai_candidates, ai_chunk_cache, ai_feedback, ai_memory_examples, ai_memory_usage,
    ai_project_settings, ai_sources,
)
from watchtower.services.ai.redaction import Redacted

TEXT_MEDIA_TYPE = "text/plain; charset=utf-8"
PROJECT_SWITCHES = ("retain_response_bodies", "allow_source_maps", "memory_require_second_reviewer",
                    "review_changed_scripts")
FINISHED = ("completed", "partial", "failed", "cancelled")


def now() -> datetime:
    return datetime.now(timezone.utc)


def row_dict(row: Any) -> dict[str, Any]:
    return dict(row._mapping)


# -- per-project switches ----------------------------------------------------


def project_settings(uow: Any) -> dict[str, Any]:
    row = uow.connection.execute(select(ai_project_settings).where(
        ai_project_settings.c.project_id == uow.project_id)).one_or_none()
    if row is None:
        return {key: False for key in PROJECT_SWITCHES} | {"updated_at": None, "updated_by": None}
    return {key: getattr(row, key) for key in (*PROJECT_SWITCHES, "updated_at", "updated_by")}


def save_project_settings(uow: Any, changes: Mapping[str, bool], actor: UUID | None) -> dict[str, Any]:
    values = {key: bool(value) for key, value in changes.items() if key in PROJECT_SWITCHES}
    statement = insert(ai_project_settings).values(project_id=uow.project_id, updated_by=actor, updated_at=now(), **values)
    uow.connection.execute(statement.on_conflict_do_update(
        index_elements=[ai_project_settings.c.project_id], set_={**values, "updated_by": actor, "updated_at": now()}))
    return project_settings(uow)


# -- sources -----------------------------------------------------------------


def add_source(uow: Any, *, origin: str, kind: str, url: str, blobs: Any = None, content: Redacted | None = None,
               run_id: UUID | None = None, final_url: str | None = None, status_code: int | None = None,
               content_type: str = "", size_bytes: int = 0, truncated: bool = False,
               details: Mapping[str, Any] | None = None, preanalysis: Mapping[str, Any] | None = None,
               retention_days: int | None = None, source_id: UUID | None = None) -> UUID:
    source_id = source_id or uuid4()
    storage_uri = redacted_sha = original_sha = None
    redactions = 0
    details = dict(details or {})
    if content is not None:
        blob = blobs.put(uow.project_id, content.text.encode("utf-8", "surrogatepass"), media_type=TEXT_MEDIA_TYPE)
        storage_uri, redacted_sha, original_sha = blob.uri, blob.sha256, content.original_sha256
        redactions = content.count
        details["offset_map"] = content.offset_map()
    uow.connection.execute(ai_sources.insert().values(
        id=source_id, project_id=uow.project_id, run_id=run_id, origin=origin, kind=kind, url=url[:2000],
        final_url=(final_url or None) and final_url[:2000], status_code=status_code, content_type=content_type[:200],
        size_bytes=size_bytes, sha256=original_sha, redacted_sha256=redacted_sha, storage_uri=storage_uri,
        truncated=truncated, redactions=redactions, details=details, preanalysis=dict(preanalysis or {}),
        expires_at=now() + timedelta(days=retention_days) if retention_days and storage_uri else None,
    ))
    return source_id


def sources(uow: Any, *, run_id: UUID | None = None, ids: Iterable[UUID] | None = None) -> list[dict[str, Any]]:
    query = select(ai_sources).where(ai_sources.c.project_id == uow.project_id)
    if run_id is not None:
        query = query.where(ai_sources.c.run_id == run_id)
    if ids is not None:
        query = query.where(ai_sources.c.id.in_([UUID(str(i)) for i in ids]))
    return [row_dict(row) for row in uow.connection.execute(query.order_by(ai_sources.c.created_at, ai_sources.c.id))]


def latest_collection_run(uow: Any) -> UUID | None:
    return uow.connection.execute(
        select(ai_sources.c.run_id).where(ai_sources.c.project_id == uow.project_id, ai_sources.c.run_id.is_not(None),
                                          ai_sources.c.origin.in_(["collected", "retained_body", "source_map"]))
        .order_by(ai_sources.c.created_at.desc()).limit(1)).scalar_one_or_none()


def read_content(source: Mapping[str, Any], blobs: Any, *, at: datetime | None = None) -> Redacted | None:
    """The stored redacted text of a source, or ``None`` when it has none or its retention expired."""
    if not source.get("storage_uri"):
        return None
    if source.get("expires_at") and source["expires_at"] <= (at or now()):
        return None
    data = blobs.get(source["storage_uri"])
    return Redacted.from_map(data.decode("utf-8", "surrogatepass"), source.get("sha256") or "",
                             (source.get("details") or {}).get("offset_map", []))


# -- analyses ----------------------------------------------------------------


def create_analysis(uow: Any, *, run_id: UUID | None, requested_by: UUID | None, mode: str, source_ids: Sequence[str],
                    model: str, prompt_version: str, config_hash: str, reanalysis_of: UUID | None = None,
                    analysis_id: UUID | None = None) -> UUID:
    analysis_id = analysis_id or uuid4()
    uow.connection.execute(ai_analyses.insert().values(
        id=analysis_id, project_id=uow.project_id, run_id=run_id, requested_by=requested_by, mode=mode,
        source_ids=[str(s) for s in source_ids], model=model, prompt_version=prompt_version, config_hash=config_hash,
        reanalysis_of=reanalysis_of))
    return analysis_id


def analysis(uow: Any, analysis_id: UUID) -> dict[str, Any]:
    row = uow.connection.execute(select(ai_analyses).where(
        ai_analyses.c.project_id == uow.project_id, ai_analyses.c.id == UUID(str(analysis_id)))).one_or_none()
    if row is None:
        raise NotFound(f"analysis {analysis_id} not found")
    return row_dict(row)


def analyses(uow: Any, *, limit: int = 50, run_id: UUID | None = None) -> list[dict[str, Any]]:
    query = select(ai_analyses).where(ai_analyses.c.project_id == uow.project_id)
    if run_id is not None:
        query = query.where(ai_analyses.c.run_id == run_id)
    query = query.order_by(ai_analyses.c.created_at.desc(), ai_analyses.c.id.desc()).limit(max(1, min(limit, 500)))
    return [row_dict(row) for row in uow.connection.execute(query)]


def update_analysis(uow: Any, analysis_id: UUID, **values: Any) -> None:
    uow.connection.execute(update(ai_analyses).where(
        ai_analyses.c.project_id == uow.project_id, ai_analyses.c.id == analysis_id).values(**values))


def add_candidate(uow: Any, analysis_id: UUID, ordinal: int, data: Mapping[str, Any],
                  matched_finding_id: UUID | None) -> UUID:
    candidate_id = uuid4()
    uow.connection.execute(ai_candidates.insert().values(
        id=candidate_id, project_id=uow.project_id, analysis_id=analysis_id, ordinal=ordinal, category=data["category"],
        title=data["title"], supported=data["supported"], citation_status=data["citation_status"],
        confidence=data["confidence"], data=json.loads(json.dumps(data, default=str)),
        matched_finding_id=matched_finding_id))
    return candidate_id


def candidates(uow: Any, analysis_id: UUID) -> list[dict[str, Any]]:
    query = select(ai_candidates).where(ai_candidates.c.project_id == uow.project_id,
                                        ai_candidates.c.analysis_id == analysis_id).order_by(ai_candidates.c.ordinal)
    return [row_dict(row) for row in uow.connection.execute(query)]


def candidate(uow: Any, candidate_id: UUID) -> dict[str, Any]:
    row = uow.connection.execute(select(ai_candidates).where(
        ai_candidates.c.project_id == uow.project_id, ai_candidates.c.id == UUID(str(candidate_id)))).one_or_none()
    if row is None:
        raise NotFound(f"candidate {candidate_id} not found")
    return row_dict(row)


def next_ordinal(uow: Any, analysis_id: UUID) -> int:
    return (uow.connection.execute(select(func.max(ai_candidates.c.ordinal)).where(
        ai_candidates.c.project_id == uow.project_id, ai_candidates.c.analysis_id == analysis_id)).scalar() or 0) + 1


def candidate_counts(uow: Any, analysis_ids: Sequence[UUID]) -> dict[UUID, dict[str, int]]:
    if not analysis_ids:
        return {}
    query = (select(ai_candidates.c.analysis_id, ai_candidates.c.supported, func.count())
             .where(ai_candidates.c.project_id == uow.project_id, ai_candidates.c.analysis_id.in_(list(analysis_ids)))
             .group_by(ai_candidates.c.analysis_id, ai_candidates.c.supported))
    counts: dict[UUID, dict[str, int]] = {}
    for analysis_id, supported, count in uow.connection.execute(query):
        counts.setdefault(analysis_id, {"supported": 0, "unsupported": 0})["supported" if supported else "unsupported"] += count
    return counts


# -- cache -------------------------------------------------------------------


def cache_key(*, chunk_sha256: str, model: str, prompt_version: str, config_hash: str,
              examples: Sequence[tuple[str, int]]) -> str:
    material = json.dumps({"chunk": chunk_sha256, "model": model, "prompt": prompt_version, "config": config_hash,
                           "examples": sorted(f"{i}:{r}" for i, r in examples)}, sort_keys=True)
    return hashlib.sha256(material.encode()).hexdigest()


def cached(uow: Any, key: str) -> dict[str, Any] | None:
    return uow.connection.execute(select(ai_chunk_cache.c.result).where(
        ai_chunk_cache.c.project_id == uow.project_id, ai_chunk_cache.c.cache_key == key)).scalar_one_or_none()


def store_cache(uow: Any, key: str, *, model: str, prompt_version: str, result: Mapping[str, Any]) -> None:
    uow.connection.execute(insert(ai_chunk_cache).values(
        project_id=uow.project_id, cache_key=key, model=model, prompt_version=prompt_version,
        result=json.loads(json.dumps(result, default=str))).on_conflict_do_nothing())


# -- feedback and usage ------------------------------------------------------


def feedback_for(uow: Any, candidate_ids: Sequence[UUID]) -> dict[UUID, list[dict[str, Any]]]:
    if not candidate_ids:
        return {}
    query = select(ai_feedback).where(ai_feedback.c.project_id == uow.project_id,
                                      ai_feedback.c.candidate_id.in_(list(candidate_ids))).order_by(ai_feedback.c.created_at)
    grouped: dict[UUID, list[dict[str, Any]]] = {}
    for row in uow.connection.execute(query):
        grouped.setdefault(row.candidate_id, []).append(row_dict(row))
    return grouped


def examples_for_feedback(uow: Any, feedback_ids: Sequence[UUID]) -> dict[UUID, dict[str, Any]]:
    if not feedback_ids:
        return {}
    query = select(ai_memory_examples).where(ai_memory_examples.c.project_id == uow.project_id,
                                             ai_memory_examples.c.feedback_id.in_(list(feedback_ids)))
    return {row.feedback_id: row_dict(row) for row in uow.connection.execute(query)}


def record_usage(uow: Any, analysis_id: UUID, used: Sequence[Mapping[str, Any]]) -> None:
    for item in used:
        uow.connection.execute(insert(ai_memory_usage).values(
            project_id=uow.project_id, analysis_id=analysis_id, example_id=UUID(str(item["id"])),
            revision=int(item["revision"]), score=dict(item.get("score") or {}), reason=str(item.get("why", ""))[:1000],
        ).on_conflict_do_nothing())


def usage(uow: Any, analysis_id: UUID) -> list[dict[str, Any]]:
    query = select(ai_memory_usage).where(ai_memory_usage.c.project_id == uow.project_id,
                                          ai_memory_usage.c.analysis_id == analysis_id)
    return [row_dict(row) for row in uow.connection.execute(query)]


def mark_outdated(uow: Any, example_id: UUID, reason: str) -> int:
    """Flag (never rewrite) the analyses that used ``example_id``."""
    used = select(ai_memory_usage.c.analysis_id).where(ai_memory_usage.c.project_id == uow.project_id,
                                                       ai_memory_usage.c.example_id == example_id)
    result = uow.connection.execute(update(ai_analyses).where(
        ai_analyses.c.project_id == uow.project_id, ai_analyses.c.id.in_(used), ai_analyses.c.outdated_at.is_(None)
    ).values(outdated_at=now(), outdated_reason=reason[:500]))
    return result.rowcount or 0
