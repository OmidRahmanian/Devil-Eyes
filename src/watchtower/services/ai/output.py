"""Validate the model's answer and verify every citation against stored content.

The answer must be a JSON object matching ``prompts.OUTPUT_SCHEMA``. A
structural problem raises ``OutputError`` (the caller repairs once, then marks
the chunk failed); a malformed individual candidate is dropped and counted.

Citations are verified, never trusted: each quote must occur in the redacted
stored content of the chunk's source. The stored location is the one found
(line, character and UTF-8 byte offsets), with the redacted content's SHA-256
and, through the redaction offset map, the matching range of the original
content and its SHA-256. A quote that is not there is removed and the candidate
is flagged "citation not verified"; a candidate left with no verified evidence
is unsupported and is never presented as an issue.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from watchtower.services.ai.preanalysis import CATEGORIES
from watchtower.services.ai.prompts import LIMITS
from watchtower.services.ai.redaction import REDACTED, LineIndex, Redacted

CLAIM_TYPES = ("observed_fact", "model_inference")
CONFIDENCE = ("low", "medium", "high")
SEVERITIES = ("none", "info", "low", "medium", "high", "critical")
GUTTER = re.compile(r"(?m)^[ \t]*\d+ \| ?")
PAYLOAD = re.compile(r"(?i)<\s*script|javascript:|on(?:error|load|mouseover)\s*=|\balert\s*\(|document\.cookie|"
                     r"\beval\s*\(|<\s*img[^>]+src\s*=")
MIN_QUOTE = 6


class OutputError(ValueError):
    """The answer as a whole is unusable (not JSON, wrong shape)."""


def _json(content: str) -> Any:
    text = content.strip()
    fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.S)
    if fenced:
        text = fenced.group(1)
    try:
        return json.loads(text)
    except ValueError:
        raise OutputError("the answer is not valid JSON") from None


def _text(value: Any, limit: int) -> str:
    return " ".join(str(value).split())[:limit] if isinstance(value, (str, int, float)) else ""


def _strings(value: Any, limit: int, count: int = 6) -> list[str]:
    if not isinstance(value, list):
        return []
    return [text for text in (_text(item, limit) for item in value[:count]) if text]


def parse_output(content: str) -> tuple[list[dict[str, Any]], list[str], int]:
    """``(candidates, not_visible, dropped)`` from the model's answer; raises ``OutputError``."""
    data = _json(content)
    if not isinstance(data, dict):
        raise OutputError("the answer is not a JSON object")
    raw = data.get("candidates")
    if not isinstance(raw, list):
        raise OutputError("the answer has no 'candidates' list")
    candidates, dropped = [], 0
    for item in raw[:8]:
        candidate = _candidate(item)
        if candidate is None:
            dropped += 1
        else:
            candidates.append(candidate)
    dropped += max(0, len(raw) - 8)
    return candidates, _strings(data.get("not_visible"), LIMITS["item"]), dropped


def _candidate(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    title, explanation = _text(item.get("title"), LIMITS["title"]), _text(item.get("explanation"), LIMITS["explanation"])
    confidence = item.get("confidence")
    if not title or not explanation or confidence not in CONFIDENCE or not isinstance(item.get("evidence"), list):
        return None
    category = item.get("category") if item.get("category") in CATEGORIES else "other"
    evidence = []
    for entry in item["evidence"][:5]:
        if isinstance(entry, dict) and isinstance(entry.get("quote"), str):
            line = entry.get("line")
            evidence.append({"quote": entry["quote"][:LIMITS["quote"]],
                             "line": line if isinstance(line, int) and not isinstance(line, bool) else None})
    claims = []
    for claim in item.get("claims") or []:
        if isinstance(claim, dict) and claim.get("claim_type") in CLAIM_TYPES and _text(claim.get("text"), LIMITS["text"]):
            claims.append({"text": _text(claim["text"], LIMITS["text"]), "claim_type": claim["claim_type"]})
    steps = _strings(item.get("validation_steps"), LIMITS["item"])
    safe_steps = [step for step in steps if not PAYLOAD.search(step)]
    severity = item.get("suggested_severity") if item.get("suggested_severity") in SEVERITIES else "none"
    used = []
    for entry in item.get("examples_used") or []:
        if isinstance(entry, dict) and _text(entry.get("id"), LIMITS["id"]):
            used.append({"id": _text(entry["id"], LIMITS["id"]), "effect": _text(entry.get("effect"), LIMITS["effect"])})
    return {
        "title": title, "category": category, "category_given": item.get("category") in CATEGORIES,
        "explanation": explanation, "affected": _text(item.get("affected"), LIMITS["affected"]),
        "evidence": evidence, "claims": claims[:8],
        "assumptions": _strings(item.get("assumptions"), LIMITS["item"]),
        "missing_context": _strings(item.get("missing_context"), LIMITS["item"]),
        "validation_steps": safe_steps, "steps_removed": len(steps) - len(safe_steps),
        "confidence": confidence, "confidence_reason": _text(item.get("confidence_reason"), LIMITS["confidence_reason"]),
        "suggested_severity": severity, "examples_used": used[:5],
    }


def _normalized(text: str) -> tuple[str, list[int]]:
    """Whitespace-collapsed text and, for each kept character, its index in ``text``."""
    out, index, space = [], [], False
    for i, char in enumerate(text):
        if char.isspace():
            if not space and out:
                out.append(" ")
                index.append(i)
            space = True
            continue
        space = False
        out.append(char)
        index.append(i)
    return "".join(out), index


def locate(quote: str, text: str) -> list[tuple[int, int]]:
    """Character ranges of ``quote`` in ``text``: exact matches, else whitespace-insensitive ones."""
    quote = GUTTER.sub("", quote).strip()
    if len(quote.replace(" ", "")) < MIN_QUOTE:
        return []
    found, start = [], text.find(quote)
    while start >= 0 and len(found) < 50:
        found.append((start, start + len(quote)))
        start = text.find(quote, start + 1)
    if found:
        return found
    flat_text, index = _normalized(text)
    flat_quote, _ = _normalized(quote)
    start = flat_text.find(flat_quote)
    while start >= 0 and len(found) < 50:
        end = start + len(flat_quote) - 1
        found.append((index[start], index[end] + 1))
        start = flat_text.find(flat_quote, start + 1)
    return found


def verify(candidate: Mapping[str, Any], *, chunk: Any, source_text: str, redacted: Redacted | None,
           source_id: str, examples: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """The stored form of one candidate: verified citations, removed ones, and support status."""
    index = LineIndex(source_text)
    region = (chunk.start, chunk.end)
    citations, removed = [], []
    for entry in candidate["evidence"]:
        quote = GUTTER.sub("", entry["quote"]).strip()
        matches = [(region[0] + a, region[0] + b) for a, b in locate(quote, source_text[region[0]:region[1]])]
        if not matches:
            reason = "too short to verify" if len(quote.replace(" ", "")) < MIN_QUOTE else \
                "quote not found in the reviewed content"
            removed.append({"quote": quote[:160], "stated_line": entry["line"], "reason": reason})
            continue
        stated = entry["line"]
        start, end = min(matches, key=lambda m: abs(index.line(m[0]) - stated) if stated else 0)
        line = index.line(start)
        citation = {
            "source_id": source_id, "quote": source_text[start:end], "line": line, "line_end": index.line(max(start, end - 1)),
            "start": start, "end": end, "byte_start": index.byte(start), "byte_end": index.byte(end),
            "redacted_sha256": redacted.sha256 if redacted else None,
            "original_sha256": redacted.original_sha256 if redacted else None,
            "contains_redaction": REDACTED in source_text[start:end],
            "stated_line": stated, "location_corrected": bool(stated) and abs(stated - line) > 2,
        }
        if redacted is not None:
            citation["original_start"], citation["original_end"] = redacted.to_original(start, end)
        citations.append(citation)
    status = "verified" if citations and not removed else ("partial" if citations else "not_verified")
    provided = {str(example["id"]): example for example in examples}
    used = [{**entry, "revision": provided[entry["id"]].get("revision"), "why_retrieved": provided[entry["id"]].get("why", "")}
            for entry in candidate["examples_used"] if entry["id"] in provided]
    flags = []
    if status != "verified":
        flags.append("citation not verified")
    if not candidate.get("category_given", True):
        flags.append("category not in the fixed list; shown as Other")
    if candidate.get("steps_removed"):
        flags.append("a suggested step was removed because it contained a payload")
    if len(used) < len(candidate["examples_used"]):
        flags.append("named an example that was not provided; ignored")
    stored = {key: value for key, value in candidate.items() if key not in ("evidence", "examples_used", "category_given")}
    return {**stored, "citations": citations, "removed_citations": removed, "citation_status": status,
            "supported": bool(citations), "flags": flags, "examples_used": used,
            "suggested_severity_note": "unverified suggestion; never written to findings",
            "chunk": {"source_id": source_id, "lines": [chunk.line_start, chunk.line_end], "sha256": chunk.sha256}}
