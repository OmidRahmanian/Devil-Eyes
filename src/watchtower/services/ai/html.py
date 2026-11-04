"""Static HTML reading for collection: script references, inline scripts, meta CSP.

Nothing is rendered or executed. ``html.parser`` tolerates broken markup.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from watchtower.services.ai.redaction import LineIndex

VERSION_HINT = r"(?:[@/-]v?|\bv=|\bver=|\bversion=)(\d+\.\d+(?:\.\d+)?)"


@dataclass
class ScriptRef:
    url: str  # absolute
    integrity: str = ""
    type: str = ""
    line: int = 0
    preload: bool = False


@dataclass
class InlineScript:
    text: str
    start: int  # character offset in the HTML
    line: int


@dataclass
class HtmlFacts:
    scripts: list[ScriptRef] = field(default_factory=list)
    inline: list[InlineScript] = field(default_factory=list)
    meta_csp: str = ""


class _Parser(HTMLParser):
    def __init__(self, base: str, index: LineIndex) -> None:
        super().__init__(convert_charrefs=True)
        self.base, self.index = base, index
        self.facts = HtmlFacts()
        self._inline_start: int | None = None
        self._inline_line = 0
        self._inline_parts: list[str] = []

    def _offset(self) -> int:
        line, column = self.getpos()
        return self.index.starts[line - 1] + column if line - 1 < len(self.index.starts) else len(self.index.text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): (value or "") for name, value in attrs}
        line = self.getpos()[0]
        if tag == "base" and values.get("href"):
            self.base = urljoin(self.base, values["href"])
        elif tag == "script":
            kind = values.get("type", "").lower()
            if kind and kind not in ("module", "text/javascript", "application/javascript", "text/ecmascript"):
                return  # JSON data blocks, templates and the like are not code
            if values.get("src"):
                self.facts.scripts.append(ScriptRef(urljoin(self.base, values["src"].strip()),
                                                    values.get("integrity", ""), kind, line))
            else:
                self._inline_start = self._offset() + len(self.get_starttag_text() or "")
                self._inline_line = line
                self._inline_parts = []
        elif tag == "link" and "modulepreload" in values.get("rel", "").lower() and values.get("href"):
            self.facts.scripts.append(ScriptRef(urljoin(self.base, values["href"].strip()),
                                                values.get("integrity", ""), "module", line, preload=True))
        elif tag == "meta" and values.get("http-equiv", "").lower() == "content-security-policy":
            self.facts.meta_csp = values.get("content", "")

    def handle_data(self, data: str) -> None:
        if self._inline_start is not None:
            self._inline_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._inline_start is not None:
            text = "".join(self._inline_parts)
            if text.strip():
                self.facts.inline.append(InlineScript(text, self._inline_start, self._inline_line))
            self._inline_start = None


def parse_html(text: str, base_url: str) -> HtmlFacts:
    parser = _Parser(base_url, LineIndex(text))
    try:
        parser.feed(text)
        parser.close()
    except Exception:  # malformed markup: keep what was read
        pass
    seen, unique = set(), []
    for ref in parser.facts.scripts:
        if urlsplit(ref.url).scheme in ("http", "https") and ref.url not in seen:
            seen.add(ref.url)
            unique.append(ref)
    parser.facts.scripts = unique
    return parser.facts


def static_imports(tokens: list, base_url: str) -> list[str]:
    """Absolute URLs of static ``import ... from "x"``/``import("x")`` specifiers that are paths or URLs."""
    urls = []
    for i, token in enumerate(tokens):
        if token.kind != "string":
            continue
        previous = tokens[i - 1].text if i else ""
        before = tokens[i - 2].text if i > 1 else ""
        if previous in ("from", "import") or (previous == "(" and before == "import"):
            value = token.value.strip()
            if value.startswith(("/", "./", "../", "http://", "https://")):
                urls.append(urljoin(base_url, value))
    return list(dict.fromkeys(urls))
