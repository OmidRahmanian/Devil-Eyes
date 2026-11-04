"""A small, tolerant JavaScript tokenizer for static pre-analysis.

It never evaluates anything. It splits source into identifiers, numbers,
strings, template-literal pieces, regular expressions, comments and
punctuation, with character offsets and line numbers, so pre-analysis can
tell code from comments and strings and chunking can cut at statement
boundaries. Malformed input never raises: an unterminated string or comment
simply runs to the end of the file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

IDENT = re.compile(r"[A-Za-z_$ -￿][\w$ -￿]*")
NUMBER = re.compile(r"(?:0[xXoObB][0-9a-fA-F_]+|(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?\d+)?)n?")
SPACE = re.compile(r"[ \t\r\n\f\v   ﻿]+")
PUNCT = re.compile(r">>>=|\.\.\.|===|!==|\*\*=|<<=|>>=|>>>|&&=|\|\|=|\?\?=|=>|==|!=|<=|>=|&&|\|\||\?\?|\?\.|\+\+|--|"
                   r"\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<|>>|\*\*|[{}()\[\];,<>+\-*/%&|^!~?:=.@#]")
# After these keywords a slash starts a regular expression, not a division.
REGEX_AFTER_KEYWORDS = frozenset({"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
                                  "case", "do", "else", "yield", "await"})


@dataclass(frozen=True, slots=True)
class Token:
    kind: str  # ident | number | string | template | regex | comment | punct
    text: str  # raw source text
    start: int
    end: int
    line: int

    @property
    def value(self) -> str:
        """String contents without quotes and simple escapes resolved (strings and templates only)."""
        if self.kind == "string":
            return _unescape(self.text[1:-1] if len(self.text) > 1 and self.text[-1] == self.text[0] else self.text[1:])
        if self.kind == "template":
            body = self.text
            body = body[1:] if body[:1] in "`}" else body
            if body.endswith("${"):
                body = body[:-2]
            elif body.endswith("`"):
                body = body[:-1]
            return _unescape(body)
        return self.text


def _unescape(text: str) -> str:
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t", "r": "\r"}.get(m.group(1), m.group(1)), text)


def _regex_allowed(previous: Token | None) -> bool:
    if previous is None:
        return True
    if previous.kind == "punct":
        return previous.text not in (")", "]", "}", "++", "--")
    if previous.kind == "ident":
        return previous.text in REGEX_AFTER_KEYWORDS
    return previous.kind == "comment"


def tokenize(source: str, *, max_tokens: int = 2_000_000) -> list[Token]:
    tokens: list[Token] = []
    i, line, length = 0, 1, len(source)
    braces: list[str] = []  # "{" for a block or object, "${" for a template substitution
    previous: Token | None = None

    def emit(kind: str, end: int) -> None:
        nonlocal i, line, previous
        token = Token(kind, source[i:end], i, end, line)
        tokens.append(token)
        line += source.count("\n", i, end)
        if kind != "comment":
            previous = token
        i = end

    def template_from(start: int) -> int:
        """End of a template piece starting at ``start`` (just after a backtick or closing brace)."""
        j = start
        while j < length:
            char = source[j]
            if char == "\\":
                j += 2
                continue
            if char == "`":
                return j + 1
            if char == "$" and j + 1 < length and source[j + 1] == "{":
                braces.append("${")
                return j + 2
            j += 1
        return length

    while i < length and len(tokens) < max_tokens:
        char = source[i]
        space = SPACE.match(source, i)
        if space:
            line += source.count("\n", i, space.end())
            i = space.end()
            continue
        if source.startswith("//", i) or (source.startswith("<!--", i)):
            end = source.find("\n", i)
            emit("comment", length if end < 0 else end)
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            emit("comment", length if end < 0 else end + 2)
            continue
        if char in "\"'":
            j = i + 1
            while j < length and source[j] != char and source[j] != "\n":
                j += 2 if source[j] == "\\" else 1
            emit("string", min(j + 1, length))
            continue
        if char == "`":
            emit("template", template_from(i + 1))
            continue
        if char == "}" and braces and braces[-1] == "${":
            braces.pop()
            emit("template", template_from(i + 1))
            continue
        if char == "/" and _regex_allowed(previous):
            j, in_class = i + 1, False
            while j < length and source[j] != "\n":
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == "[":
                    in_class = True
                elif source[j] == "]":
                    in_class = False
                elif source[j] == "/" and not in_class:
                    break
                j += 1
            if j < length and source[j] == "/":
                flags = IDENT.match(source, j + 1)
                emit("regex", flags.end() if flags else j + 1)
                continue
        ident = IDENT.match(source, i)
        if ident:
            emit("ident", ident.end())
            continue
        number = NUMBER.match(source, i)
        if number and number.end() > i and (char.isdigit() or (char == "." and i + 1 < length and source[i + 1].isdigit())):
            emit("number", number.end())
            continue
        punct = PUNCT.match(source, i)
        if punct:
            if punct.group() == "{":
                braces.append("{")
            elif punct.group() == "}" and braces:
                braces.pop()
            emit("punct", punct.end())
            continue
        emit("punct", i + 1)  # anything else: one character, never an error
    return tokens


def code_tokens(tokens: list[Token]) -> list[Token]:
    return [token for token in tokens if token.kind != "comment"]


def statement_ends(tokens: list[Token], *, depth: int = 0) -> list[int]:
    """Character offsets where a statement at brace ``depth`` ends (after ``;`` or a closing ``}``)."""
    ends, level, parens = [], 0, 0
    closed_at = -1  # index of a "}" that just ended a statement, so "};" counts once
    for i, token in enumerate(tokens):
        if token.kind == "comment":
            continue
        text = token.text
        if token.kind != "punct":
            closed_at = -1
            continue
        if text in "([":
            parens += 1
        elif text in ")]":
            parens = max(0, parens - 1)
        elif text == "{":
            level += 1
        elif text == "}":
            level = max(0, level - 1)
            if level == depth and parens == 0:
                ends.append(token.end)
                closed_at = i
                continue
        elif text == ";" and level == depth and parens == 0:
            if closed_at >= 0 and ends:
                ends[-1] = token.end
            else:
                ends.append(token.end)
        closed_at = -1
    return ends
