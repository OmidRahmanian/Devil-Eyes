"""Redaction for AI review content, with a map back to the original.

Everything stored for review, and everything sent to the model, is redacted
first: private keys, cloud and API key formats, JWTs, bearer tokens, URL
credentials, and literal values assigned to secret-like names (``apiKey:
"..."``). Unlike scan evidence, code that only *refers* to a secret
(``token = localStorage.getItem("token")``) stays readable, because that code
is what a review must see; literal values are what is removed. Each replacement is recorded, so a position in the redacted text can be
mapped back to the original content (identified only by its SHA-256; the
original is never stored). Secret-like values become pre-analysis facts with a
location and kind, never with the value.
"""

from __future__ import annotations

import bisect
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from watchtower.services.evidence import REDACTED, SENSITIVE_NAME

# (kind, pattern, group whose end starts the secret; 0 = whole match, -1 = up to the trailing "@")
SECRET_PATTERNS: tuple[tuple[str, re.Pattern, int], ...] = (
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S), 0),
    ("aws_access_key", re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"), 0),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), 0),
    ("google_api_key", re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"), 0),
    ("stripe_key", re.compile(r"(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"), 0),
    ("github_token", re.compile(r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{36,}"), 0),
    ("slack_token", re.compile(r"(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9-]{10,}"), 0),
    ("bearer_token", re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"), 1),
    ("url_credentials", re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://)[^/\s:@\"'`]+:[^/\s@\"'`]+@"), -1),
    ("named_secret", re.compile(r"(?i)([\"']?[A-Za-z0-9_.-]*" + SENSITIVE_NAME + r"[A-Za-z0-9_.-]*[\"']?\s*[:=]\s*)"
                                r"(\"[^\"\n]*\"|'[^'\n]*'|[^\s,;&<]+)"), 1),
)
_QUOTED = re.compile(r"""^(["'])(.*)\1$""", re.S)
_CODE = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[[^\]]*\]|\([^)]*\)?)*[)\]]*$")


_STRONG_NAME = re.compile(r"(?i)pass(?:word|wd|phrase)?|secret|credential|private[_-]?key")


def secret_value(value: str, name: str = "") -> bool:
    """Whether a value assigned to a secret-like name is a literal that may be a credential.

    Code (identifiers, member access, calls), short words and empty strings are
    not. For password, secret and credential names any literal of 4+ characters
    is; for other names (token, key, auth), literals of 8+ characters with a
    digit or symbol, or 20+ characters, are.
    """
    quoted = _QUOTED.match(value)
    if not quoted:
        if _CODE.match(value) or value.lower() in ("null", "undefined", "true", "false", "none"):
            return False
        literal = value
    else:
        literal = quoted.group(2)
    if REDACTED in literal or literal.startswith("${"):
        return False
    if _STRONG_NAME.search(name):
        return len(literal) >= 4
    if len(literal) < 8 or re.search(r"\s", literal):
        return False
    return len(literal) >= 20 or bool(re.search(r"\d", literal) and re.search(r"[A-Za-z]", literal)) or \
        bool(re.search(r"[^A-Za-z0-9_.-]", literal))


@dataclass(frozen=True, slots=True)
class Replacement:
    out_start: int
    out_end: int
    orig_start: int
    orig_end: int
    kind: str


@dataclass
class Redacted:
    """Redacted text plus how it relates to the original."""

    text: str
    original_sha256: str
    replacements: list[Replacement] = field(default_factory=list)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()

    @property
    def count(self) -> int:
        return len(self.replacements)

    def to_original(self, start: int, end: int) -> tuple[int, int]:
        """Character range in the original text for ``[start, end)`` of the redacted text."""
        return _map(self.replacements, start, end)

    def redacted_within(self, start: int, end: int) -> bool:
        return any(r.out_start < end and r.out_end > start for r in self.replacements)

    def secrets(self) -> list[dict[str, Any]]:
        """Secret-like values as facts: kind and location in the redacted text, never the value."""
        return [{"kind": r.kind, "start": r.out_start, "end": r.out_end, "line": line_of(self.text, r.out_start)}
                for r in self.replacements]

    def offset_map(self) -> list[list[Any]]:
        return [[r.out_start, r.out_end, r.orig_start, r.orig_end, r.kind] for r in self.replacements]

    @classmethod
    def from_map(cls, text: str, original_sha256: str, offset_map: list[list[Any]]) -> Redacted:
        return cls(text, original_sha256, [Replacement(*map(int, row[:4]), str(row[4])) for row in offset_map])


def _map(replacements: list[Replacement], start: int, end: int) -> tuple[int, int]:
    def one(position: int, *, is_end: bool) -> int:
        shift = 0
        for r in replacements:
            if position < r.out_start or (is_end and position == r.out_start):
                break
            if position < r.out_end or (is_end and position == r.out_end):
                return r.orig_end if is_end else r.orig_start
            shift = r.orig_end - r.out_end
        return position + shift
    return one(start, is_end=False), one(end, is_end=True)


def _spans(text: str) -> list[tuple[int, int, str]]:
    spans = []
    for kind, pattern, group in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            if group == -1:
                start, end = match.end(1), match.end() - 1
            elif group:
                start, end = match.end(group), match.end()
            else:
                start, end = match.start(), match.end()
            if end <= start:
                continue
            if kind == "named_secret":
                if not secret_value(text[start:end], match.group(1)):
                    continue
                if text[start] in "\"'":
                    start, end = start + 1, end - 1  # keep the quotes, so code stays readable
            spans.append((start, end, kind))
    return _merge(spans)


def redact(original: str) -> Redacted:
    """Redact ``original`` for storage and prompts."""
    digest = hashlib.sha256(original.encode("utf-8", "surrogatepass")).hexdigest()
    spans = _spans(original)
    for _ in range(3):  # a replacement can complete a new match; repeat until stable
        result = _apply(original, digest, spans)
        extra = [(*result.to_original(start, end), kind) for start, end, kind in _spans(result.text)
                 if not result.redacted_within(start, end)]
        if not extra:
            return result
        spans = _merge([*spans, *extra])
    return _apply(original, digest, spans)


_GENERIC = frozenset({"named_secret", "bearer_token", "url_credentials"})


def _merge(spans: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """Union overlapping spans; a specific kind (``jwt``) wins over a generic one (``bearer_token``)."""
    merged: list[tuple[int, int, str]] = []
    for start, end, kind in sorted(spans):
        if merged and start <= merged[-1][1]:
            previous = merged[-1][2]
            label = kind if previous in _GENERIC and kind not in _GENERIC else previous
            merged[-1] = (merged[-1][0], max(merged[-1][1], end), label)
        else:
            merged.append((start, end, kind))
    return merged


def _apply(original: str, digest: str, spans: list[tuple[int, int, str]]) -> Redacted:
    parts, replacements, cursor, out = [], [], 0, 0
    for start, end, kind in spans:
        parts.append(original[cursor:start])
        out += start - cursor
        parts.append(REDACTED)
        replacements.append(Replacement(out, out + len(REDACTED), start, end, kind))
        out += len(REDACTED)
        cursor = end
    parts.append(original[cursor:])
    return Redacted("".join(parts), digest, replacements)


class LineIndex:
    """Line numbers and UTF-8 byte offsets for character positions in one text."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line(self, position: int) -> int:
        return bisect.bisect_right(self.starts, position)

    def line_span(self, line: int) -> tuple[int, int]:
        start = self.starts[line - 1]
        end = self.starts[line] - 1 if line < len(self.starts) else len(self.text)
        return start, end

    def byte(self, position: int) -> int:
        return len(self.text[:position].encode("utf-8", "surrogatepass"))


def line_of(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1
