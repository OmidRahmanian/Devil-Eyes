"""Split review content into model-sized chunks and choose which ones fit the budget.

Chunks end at statement boundaries where possible (top level first, then one
level in, then the nearest separator). A chunk cut from inside a larger
statement carries that statement's opening line as context. Each chunk keeps
its source, URL, SHA-256, character, byte and line ranges, and whether it was
minified, truncated or redacted. Chunks around pre-analysis hits come first;
everything left out is reported with the reason.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from watchtower.services.ai.jslex import statement_ends, tokenize
from watchtower.services.ai.redaction import LineIndex

CHARS_PER_TOKEN = 3.0  # conservative for code; real tokenizers usually do better


def estimate_tokens(text: str) -> int:
    return math.ceil(len(text) / CHARS_PER_TOKEN)


@dataclass
class Chunk:
    source_id: str
    url: str
    text: str
    start: int
    end: int
    line_start: int
    line_end: int
    byte_start: int
    byte_end: int
    minified: bool = False
    truncated: bool = False
    redacted: bool = False
    context: str = ""
    score: int = 0
    fact_ids: list[int] = field(default_factory=list)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8", "surrogatepass")).hexdigest()

    @property
    def tokens(self) -> int:
        return estimate_tokens(self.context) + estimate_tokens(self.text)

    def describe(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("text")
        return {**data, "sha256": self.sha256, "tokens": self.tokens}


def minified(text: str) -> bool:
    lines = text.splitlines() or [""]
    return max(len(line) for line in lines) > 2000 or len(text) / len(lines) > 300


def _boundaries(text: str, kind: str) -> tuple[list[int], list[int]]:
    if kind not in ("script", "inline_script", "source_map_source"):
        lines = [i + 1 for i, char in enumerate(text) if char == "\n"]
        return lines, []
    tokens = tokenize(text)
    return statement_ends(tokens, depth=0), statement_ends(tokens, depth=1)


def _split(text: str, start: int, end: int, ends: Sequence[int], max_chars: int) -> list[tuple[int, int]]:
    """Group the segments between ``ends`` inside ``[start, end)`` into pieces of at most ``max_chars``."""
    pieces, piece_start, last = [], start, start
    for boundary in [b for b in ends if start < b < end] + [end]:
        if boundary - piece_start > max_chars and last > piece_start:
            pieces.append((piece_start, last))
            piece_start = last
        last = boundary
    pieces.append((piece_start, end))
    return pieces


def _hard_split(text: str, start: int, end: int, max_chars: int) -> list[tuple[int, int]]:
    pieces = []
    while end - start > max_chars:
        window = text[start:start + max_chars]
        cut = max(window.rfind(sep) for sep in (";", "\n", ",", " ", "}"))
        cut = start + (cut + 1 if cut > max_chars // 2 else max_chars)
        pieces.append((start, cut))
        start = cut
    pieces.append((start, end))
    return pieces


def chunk_source(text: str, *, source_id: str, url: str, kind: str = "script", max_chars: int,
                 truncated: bool = False, redacted: Iterable[tuple[int, int]] = (),
                 facts: Sequence[Mapping[str, Any]] = ()) -> list[Chunk]:
    """Chunks of one source's redacted text."""
    if not text:
        return []
    index = LineIndex(text)
    top, inner = _boundaries(text, kind)
    ranges: list[tuple[int, int, str]] = []
    for piece_start, piece_end in _split(text, 0, len(text), top, max_chars):
        if piece_end - piece_start <= max_chars:
            ranges.append((piece_start, piece_end, ""))
            continue
        statement_head = text[piece_start:piece_start + 400].split("\n", 1)[0][:200]
        for sub_start, sub_end in _split(text, piece_start, piece_end, inner, max_chars):
            subs = [(sub_start, sub_end)] if sub_end - sub_start <= max_chars else _hard_split(text, sub_start, sub_end, max_chars)
            for a, b in subs:
                ranges.append((a, b, statement_head if a > piece_start else ""))
    is_minified = minified(text)
    redacted = list(redacted)
    chunks = []
    for start, end, context in ranges:
        if not text[start:end].strip():
            continue
        within = [i for i, f in enumerate(facts) if f.get("start") is not None and start <= f["start"] < end]
        chunks.append(Chunk(
            source_id=source_id, url=url, text=text[start:end], start=start, end=end,
            line_start=index.line(start), line_end=index.line(max(start, end - 1)),
            byte_start=index.byte(start), byte_end=index.byte(end), minified=is_minified,
            truncated=truncated and end >= len(text), redacted=any(a < end and b > start for a, b in redacted),
            context=context, score=sum(int(facts[i].get("weight", 1)) for i in within), fact_ids=within,
        ))
    return chunks


@dataclass
class Selection:
    chunks: list[Chunk]
    skipped: list[dict[str, Any]]


def select_chunks(chunks: Sequence[Chunk], *, max_chunks: int, max_total_chars: int) -> Selection:
    """Highest-scoring chunks first (ties keep file order) within the budgets; report the rest."""
    order = sorted(range(len(chunks)), key=lambda i: (-chunks[i].score, i))
    chosen, skipped, total = set(), [], 0
    for i in order:
        chunk = chunks[i]
        if len(chosen) >= max_chunks:
            reason = f"budget: at most {max_chunks} chunks per review"
        elif total + len(chunk.text) > max_total_chars:
            reason = f"budget: at most {max_total_chars} characters per review"
        else:
            chosen.add(i)
            total += len(chunk.text)
            continue
        skipped.append({"source_id": chunk.source_id, "url": chunk.url, "lines": [chunk.line_start, chunk.line_end],
                        "score": chunk.score, "reason": reason})
    return Selection([chunks[i] for i in sorted(chosen, key=lambda i: (-chunks[i].score, i))], skipped)
