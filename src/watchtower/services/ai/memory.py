"""Project memory: owner-approved examples retrieved into later reviews of the same project.

Approved examples can guide future reviews in this project. This does not
retrain the model. Retrieval is simple and explainable: an example is scored
against the code under review by category, technology and version range, path
pattern, code fingerprint, identifier overlap and context keywords, and the
score breakdown is stored. To avoid over-generalizing, an example applies only
when its category matches *and* at least one specific condition matches (the
same code, most of its identifiers, its path pattern, or a compatible library
version). Approved examples that match the same code but disagree are not used
and are flagged for the owner. Retrieval returns at most ``ai.max_examples``
examples within ``ai.example_token_budget``.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import date, datetime, timezone
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from sqlalchemy import select, update

from watchtower.adapters.intelligence.applicability import compare, parse_version
from watchtower.domain.errors import NotFound
from watchtower.persistence.tables import ai_memory_events, ai_memory_examples, ai_memory_revisions
from watchtower.services.ai.chunking import estimate_tokens
from watchtower.services.ai.jslex import tokenize
from watchtower.services.ai.redaction import redact

STATUSES = ("submitted", "approved", "rejected", "superseded", "disabled")
JS_WORDS = frozenset("""break case catch class const continue debugger default delete do else export extends false
finally for function if import in instanceof let new null return super switch this throw true try typeof undefined
var void while with yield async await of get set static window document console length prototype""".split())
MIN_SCORE = 5.0


def now() -> datetime:
    return datetime.now(timezone.utc)


# -- conditions --------------------------------------------------------------


def normalize_code(text: str) -> str:
    """Code without comments and whitespace, so formatting changes keep the same fingerprint."""
    return "".join(t.text for t in tokenize(text) if t.kind != "comment")


def fingerprint(text: str) -> str:
    normalized = normalize_code(text)
    return hashlib.sha256(normalized.encode("utf-8", "surrogatepass")).hexdigest() if normalized else ""


def identifiers(text: str, limit: int = 12) -> list[str]:
    names = {t.text for t in tokenize(text) if t.kind == "ident" and len(t.text) > 2 and t.text not in JS_WORDS}
    return sorted(names, key=lambda name: (-len(name), name))[:limit]


def keywords(text: str, limit: int = 12) -> list[str]:
    words = {w.lower() for w in re.findall(r"[A-Za-z][A-Za-z0-9_]{3,}", text)} - JS_WORDS
    return sorted(words)[:limit]


def path_pattern(url: str) -> str:
    """A glob for the file's path with build hashes generalized: ``/static/js/app.3f9c1a2b.js`` -> ``/static/js/app.*.js``."""
    path = urlsplit(url).path or "/"
    return re.sub(r"([._-])[0-9a-f]{6,}(?=[._-]|\.js$|$)", r"\1*", path)


def version_in_range(version: str, spec: str) -> bool | None:
    """``spec`` like ``>=3.0,<3.5`` or ``3.4.1``; ``None`` when either side is not comparable."""
    parsed = parse_version(version or "")[0]
    if parsed is None or not spec:
        return None
    for part in [p.strip() for p in spec.split(",") if p.strip()]:
        match = re.match(r"^(>=|<=|>|<|==|=)?\s*(.+)$", part)
        operator, bound = match.group(1) or "==", parse_version(match.group(2))[0]
        if bound is None:
            return None
        result = compare(parsed, bound)
        if not {">=": result >= 0, "<=": result <= 0, ">": result > 0, "<": result < 0,
                "==": result == 0, "=": result == 0}[operator]:
            return False
    return True


def derive_conditions(*, category: str, snippet: str, url: str, libraries: Sequence[Mapping[str, Any]],
                      context: str = "", title: str = "", review_by: str | None = None) -> dict[str, Any]:
    technologies = [{"name": lib["name"], "version_range": f"=={lib['version']}" if lib.get("version") else ""}
                    for lib in libraries][:5]
    return {"category": category, "technologies": technologies, "path_pattern": path_pattern(url) if url else "",
            "fingerprint": fingerprint(snippet), "identifiers": identifiers(snippet),
            "context": context[:1000], "keywords": keywords(f"{title} {context}"), "review_by": review_by}


def clean_conditions(conditions: Mapping[str, Any]) -> dict[str, Any]:
    """Owner-edited conditions, bounded and redacted."""
    out = {
        "category": str(conditions.get("category", ""))[:64],
        "technologies": [{"name": str(t.get("name", ""))[:64], "version_range": str(t.get("version_range", ""))[:64]}
                         for t in (conditions.get("technologies") or [])[:5] if isinstance(t, Mapping)],
        "path_pattern": str(conditions.get("path_pattern", ""))[:300],
        "fingerprint": str(conditions.get("fingerprint", ""))[:64],
        "identifiers": [str(i)[:100] for i in (conditions.get("identifiers") or [])[:20]],
        "context": redact(str(conditions.get("context", ""))[:1000]).text,
        "keywords": [str(k)[:64] for k in (conditions.get("keywords") or [])[:20]],
        "review_by": str(conditions["review_by"])[:10] if conditions.get("review_by") else None,
    }
    if out["review_by"]:
        date.fromisoformat(out["review_by"])  # raises ValueError for a bad date
    return out


def clean_content(content: Mapping[str, Any]) -> dict[str, Any]:
    """Example content, bounded and redacted before storage (never raw secrets or cookies)."""
    def text(key: str, limit: int) -> str:
        return redact(str(content.get(key, ""))[:limit]).text
    return {"title": text("title", 200), "category": str(content.get("category", "other"))[:64],
            "verdict": str(content.get("verdict", ""))[:32], "explanation": text("explanation", 2000),
            "reason": text("reason", 2000), "snippet": text("snippet", 600), "applicability": text("applicability", 1000)}


# -- storage -----------------------------------------------------------------


def create_example(uow: Any, *, content: Mapping[str, Any], conditions: Mapping[str, Any], author: UUID | None,
                   feedback_id: UUID | None = None, note: str = "") -> UUID:
    example_id = uuid4()
    uow.connection.execute(ai_memory_examples.insert().values(
        id=example_id, project_id=uow.project_id, status="submitted", eligible=False, current_revision=1,
        feedback_id=feedback_id, submitted_by=author))
    uow.connection.execute(ai_memory_revisions.insert().values(
        project_id=uow.project_id, example_id=example_id, revision=1, content=clean_content(content),
        conditions=clean_conditions(conditions), author=author, note=note[:1000]))
    event(uow, example_id, "submitted", 1, author, note)
    return example_id


def event(uow: Any, example_id: UUID, action: str, revision: int | None, actor: UUID | None, reason: str = "") -> None:
    uow.connection.execute(ai_memory_events.insert().values(
        project_id=uow.project_id, example_id=example_id, action=action, revision=revision, actor=actor,
        reason=reason[:2000]))


def example(uow: Any, example_id: UUID) -> dict[str, Any]:
    row = uow.connection.execute(select(ai_memory_examples).where(
        ai_memory_examples.c.project_id == uow.project_id, ai_memory_examples.c.id == UUID(str(example_id)))).one_or_none()
    if row is None:
        raise NotFound(f"memory example {example_id} not found")
    return dict(row._mapping)


def revision(uow: Any, example_id: UUID, number: int) -> dict[str, Any]:
    row = uow.connection.execute(select(ai_memory_revisions).where(
        ai_memory_revisions.c.project_id == uow.project_id, ai_memory_revisions.c.example_id == example_id,
        ai_memory_revisions.c.revision == number)).one()
    return dict(row._mapping)


def history(uow: Any, example_id: UUID) -> dict[str, Any]:
    revisions = [dict(r._mapping) for r in uow.connection.execute(select(ai_memory_revisions).where(
        ai_memory_revisions.c.project_id == uow.project_id, ai_memory_revisions.c.example_id == example_id)
        .order_by(ai_memory_revisions.c.revision))]
    events = [dict(r._mapping) for r in uow.connection.execute(select(ai_memory_events).where(
        ai_memory_events.c.project_id == uow.project_id, ai_memory_events.c.example_id == example_id)
        .order_by(ai_memory_events.c.id))]
    return {"revisions": revisions, "events": events}


def add_revision(uow: Any, example_id: UUID, *, content: Mapping[str, Any], conditions: Mapping[str, Any],
                 author: UUID | None, note: str) -> int:
    current = example(uow, example_id)
    number = current["current_revision"] + 1
    uow.connection.execute(ai_memory_revisions.insert().values(
        project_id=uow.project_id, example_id=example_id, revision=number, content=clean_content(content),
        conditions=clean_conditions(conditions), author=author, note=note[:1000]))
    return number


def set_state(uow: Any, example_id: UUID, **values: Any) -> None:
    uow.connection.execute(update(ai_memory_examples).where(
        ai_memory_examples.c.project_id == uow.project_id, ai_memory_examples.c.id == example_id
    ).values(updated_at=now(), **values))


def examples(uow: Any, *, statuses: Iterable[str] | None = None, submitted_by: UUID | None = None) -> list[dict[str, Any]]:
    """Examples with their current revision's content and conditions."""
    query = select(ai_memory_examples, ai_memory_revisions.c.content, ai_memory_revisions.c.conditions).join(
        ai_memory_revisions, (ai_memory_revisions.c.example_id == ai_memory_examples.c.id)
        & (ai_memory_revisions.c.revision == ai_memory_examples.c.current_revision)
        & (ai_memory_revisions.c.project_id == ai_memory_examples.c.project_id)
    ).where(ai_memory_examples.c.project_id == uow.project_id)
    if statuses is not None:
        query = query.where(ai_memory_examples.c.status.in_(list(statuses)))
    if submitted_by is not None:
        query = query.where(ai_memory_examples.c.submitted_by == submitted_by)
    query = query.order_by(ai_memory_examples.c.created_at.desc())
    return [dict(row._mapping) for row in uow.connection.execute(query)]


def eligible(uow: Any) -> list[dict[str, Any]]:
    """Approved, eligible examples with their *approved* revision (never an unapproved edit)."""
    query = select(ai_memory_examples.c.id, ai_memory_examples.c.approved_revision, ai_memory_revisions.c.content,
                   ai_memory_revisions.c.conditions).join(
        ai_memory_revisions, (ai_memory_revisions.c.example_id == ai_memory_examples.c.id)
        & (ai_memory_revisions.c.revision == ai_memory_examples.c.approved_revision)
        & (ai_memory_revisions.c.project_id == ai_memory_examples.c.project_id)
    ).where(ai_memory_examples.c.project_id == uow.project_id, ai_memory_examples.c.status == "approved",
            ai_memory_examples.c.eligible.is_(True))
    return [dict(row._mapping) for row in uow.connection.execute(query)]


# -- retrieval ---------------------------------------------------------------


def chunk_context(*, text: str, url: str, facts: Sequence[Mapping[str, Any]],
                  libraries: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    tokens = tokenize(text)
    return {"categories": sorted({f["category"] for f in facts}), "url": url, "path": urlsplit(url).path,
            "normalized": "".join(t.text for t in tokens if t.kind != "comment"),
            "identifiers": {t.text for t in tokens if t.kind == "ident" and len(t.text) > 2 and t.text not in JS_WORDS},
            "keywords": set(keywords(" ".join(f.get("detail", "") for f in facts), limit=50)),
            "libraries": {lib["name"]: lib.get("version", "") for lib in libraries}}


def score(conditions: Mapping[str, Any], context: Mapping[str, Any], *, today: date | None = None) -> dict[str, Any]:
    """Score breakdown for one example; ``applies`` says whether it may be used."""
    parts: dict[str, float] = {}
    reasons: list[str] = []
    blocked = ""
    if conditions.get("review_by") and date.fromisoformat(conditions["review_by"]) < (today or date.today()):
        blocked = "its review-by date has passed; the owner should review it"
    category_match = bool(conditions.get("category")) and conditions["category"] in context["categories"]
    if category_match:
        parts["category"] = 3.0
        reasons.append(f"same category ({conditions['category']})")
    specific = False
    for tech in conditions.get("technologies") or []:
        if tech["name"] in context["libraries"]:
            verdict = version_in_range(context["libraries"][tech["name"]], tech.get("version_range", ""))
            if verdict is False:
                blocked = blocked or f"{tech['name']} version is outside the example's range {tech['version_range']}"
            elif verdict:
                parts["technology"] = parts.get("technology", 0) + 2.0
                reasons.append(f"compatible {tech['name']} version")
                specific = True
            else:
                parts["technology"] = parts.get("technology", 0) + 0.5
    if conditions.get("path_pattern") and fnmatch.fnmatchcase(context["path"], conditions["path_pattern"]):
        parts["path"] = 2.0
        reasons.append(f"path matches {conditions['path_pattern']}")
        specific = True
    snippet_normalized = conditions.get("_normalized", "")
    if conditions.get("fingerprint") and snippet_normalized and snippet_normalized in context["normalized"]:
        parts["fingerprint"] = 4.0
        reasons.append("the same code appears here")
        specific = True
    names = set(conditions.get("identifiers") or [])
    if names:
        overlap = len(names & context["identifiers"]) / len(names)
        if overlap >= 0.6:
            parts["identifiers"] = round(3.0 * overlap, 2)
            reasons.append(f"{round(overlap * 100)}% of its identifiers appear here")
            specific = True
    words = set(conditions.get("keywords") or [])
    if words and words & context["keywords"]:
        parts["keywords"] = min(1.0, 0.25 * len(words & context["keywords"]))
    total = round(sum(parts.values()), 2)
    applies = not blocked and category_match and specific and total >= MIN_SCORE
    if not blocked and not applies:
        blocked = "conditions do not match closely enough (needs the same category and a specific match)"
    return {"total": total, "parts": parts, "applies": applies, "why": "; ".join(reasons), "blocked": blocked}


def retrieve(candidates: Sequence[Mapping[str, Any]], context: Mapping[str, Any], *, limit: int, token_budget: int,
             today: date | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """``(selected, conflicts)`` from eligible examples (each with ``content`` and ``conditions``)."""
    scored = []
    for item in candidates:
        conditions = dict(item["conditions"])
        conditions["_normalized"] = normalize_code(item["content"].get("snippet", ""))
        result = score(conditions, context, today=today)
        if result["applies"]:
            scored.append((result, item))
    scored.sort(key=lambda pair: (-pair[0]["total"], str(pair[1]["id"])))
    conflicts, excluded = [], set()
    for i, (left_score, left) in enumerate(scored):
        for right_score, right in scored[i + 1:]:
            same_code = {"fingerprint", "identifiers"} & set(left_score["parts"]) & set(right_score["parts"])
            if left["content"].get("category") == right["content"].get("category") and same_code \
                    and left["content"].get("verdict") != right["content"].get("verdict"):
                conflicts.append({"examples": [str(left["id"]), str(right["id"])],
                                  "reason": "approved examples match the same code but disagree"})
                excluded |= {str(left["id"]), str(right["id"])}
    selected, used_tokens = [], 0
    for result, item in scored:
        if str(item["id"]) in excluded or len(selected) >= limit:
            continue
        payload = prompt_example(item)
        cost = estimate_tokens(json.dumps(payload))
        if used_tokens + cost > token_budget:
            continue
        used_tokens += cost
        selected.append({**payload, "revision": item["approved_revision"], "score": result, "why": result["why"]})
    return selected, conflicts


def prompt_example(item: Mapping[str, Any]) -> dict[str, Any]:
    content, conditions = item["content"], item["conditions"]
    return {"id": str(item["id"]), "verdict": content.get("verdict", ""), "category": content.get("category", ""),
            "explanation": content.get("explanation", "") or content.get("reason", ""),
            "snippet": content.get("snippet", ""),
            "conditions": {key: conditions.get(key) for key in ("path_pattern", "technologies", "context") if conditions.get(key)}}
