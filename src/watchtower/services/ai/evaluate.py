"""Evaluation harness for the AI review on controlled lab fixtures.

    python -m watchtower.services.ai.evaluate FIXTURES --recorded RESPONSES.json   # replay (CI, no model)
    python -m watchtower.services.ai.evaluate FIXTURES --record RESPONSES.json     # live local model, saves answers
    ... --memory                                                                   # also run with project memory

``FIXTURES`` holds lab scripts plus ``expected.json`` (``{file: [{category, line}]}``)
and optionally ``memory.json`` (approved examples). Expectations are never shown
to the model. The prompt uses a fixed delimiter tag so answers can be recorded
and replayed deterministically.

Metrics per mode: supported candidates that match an expected issue (same
category, cited within two lines), false positives (supported candidates that
match nothing), missed issues, unsupported candidates, and the share of model
citations that verified. Numbers come only from runs actually performed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from watchtower.services.ai import memory
from watchtower.services.ai.chunking import chunk_source
from watchtower.services.ai.output import OutputError, parse_output, verify
from watchtower.services.ai.preanalysis import analyze_script
from watchtower.services.ai.prompts import OUTPUT_SCHEMA, PROMPT_VERSION, build_messages, repair_messages
from watchtower.services.ai.redaction import redact

TAG = "evalfixture"


def key(messages: Sequence[Mapping[str, str]]) -> str:
    return hashlib.sha256(json.dumps([m["content"] for m in messages]).encode()).hexdigest()


class Recorded:
    """Replays answers saved by ``--record``; a missing answer is an error, never a guess."""

    def __init__(self, path: Path) -> None:
        self.answers = json.loads(path.read_text())

    def chat(self, model: str, messages: list[dict[str, str]], **options: Any) -> Any:
        from watchtower.adapters.ai.ollama import ChatResult
        answer = self.answers.get(key(messages))
        if answer is None:
            raise KeyError("no recorded answer for this prompt; re-record with --record")
        return ChatResult(answer["content"], answer.get("done_reason", "stop"))


class Recorder:
    def __init__(self, client: Any) -> None:
        self.client, self.answers = client, {}

    def chat(self, model: str, messages: list[dict[str, str]], **options: Any) -> Any:
        from watchtower.adapters.ai.ollama import ChatResult
        saved = self.answers.get(key(messages))
        if saved is not None:  # the same prompt (for example a file no example applies to) is asked once
            return ChatResult(saved["content"], saved["done_reason"])
        result = self.client.chat(model, messages, **options)
        self.answers[key(messages)] = {"content": result.content, "done_reason": result.done_reason}
        return result


def review_file(client: Any, model: str, name: str, text: str, settings: Any,
                examples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    content = redact(text)
    analysis = analyze_script(content.text, source_id=name, url=f"https://lab.example/{name}")
    chunks = chunk_source(content.text, source_id=name, url=f"https://lab.example/{name}", max_chars=6000,
                          facts=analysis["facts"])
    candidates, errors = [], []
    for chunk in chunks:
        facts = [f for f in analysis["facts"] if f.get("start") is not None and chunk.start <= f["start"] < chunk.end]
        context = memory.chunk_context(text=chunk.text, url=chunk.url, facts=facts, libraries=[])
        selected, _ = memory.retrieve(examples, context, limit=settings.max_examples,
                                      token_budget=settings.example_token_budget) if examples else ([], [])
        messages = build_messages(chunk=chunk, source={"kind": "script", "url": chunk.url, "origin_label": "lab fixture"},
                                  facts=facts, examples=selected, visibility="This review is based on 1 lab script.",
                                  tag=TAG)
        options = {"schema": OUTPUT_SCHEMA, "num_ctx": settings.num_ctx, "max_output_tokens": settings.max_output_tokens,
                   "temperature": settings.temperature, "thinking": settings.thinking}
        reply = client.chat(model, messages, **options)
        try:
            parsed, _, _ = parse_output(reply.content)
        except OutputError as problem:
            reply = client.chat(model, repair_messages(messages, reply.content, str(problem)), **options)
            try:
                parsed, _, _ = parse_output(reply.content)
            except OutputError as again:
                errors.append(str(again))
                continue
        for raw in parsed:
            candidates.append(verify(raw, chunk=chunk, source_text=content.text, redacted=content, source_id=name,
                                     examples=selected))
    return {"candidates": candidates, "errors": errors, "facts": len(analysis["facts"])}


def score(expected: Sequence[Mapping[str, Any]], candidates: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    supported = [c for c in candidates if c["supported"]]
    matched, used = 0, set()
    for item in expected:
        for i, candidate in enumerate(supported):
            if i in used or candidate["category"] != item["category"]:
                continue
            if any(abs(c["line"] - item["line"]) <= 2 for c in candidate["citations"]):
                matched += 1
                used.add(i)
                break
    citations = sum(len(c["citations"]) + len(c["removed_citations"]) for c in candidates)
    verified = sum(len(c["citations"]) for c in candidates)
    return {"expected": len(expected), "true_positives": matched, "missed": len(expected) - matched,
            "false_positives": len(supported) - len(used), "unsupported": len(candidates) - len(supported),
            "citations": citations, "verified_citations": verified}


def evaluate(fixtures: Path, client: Any, model: str, settings: Any, *, with_memory: bool) -> dict[str, Any]:
    expected = json.loads((fixtures / "expected.json").read_text())
    examples = json.loads((fixtures / "memory.json").read_text()) if with_memory and (fixtures / "memory.json").exists() else []
    files, totals = {}, {}
    started = time.monotonic()
    for name in sorted(expected):
        result = review_file(client, model, name, (fixtures / name).read_text(), settings, examples)
        metrics = score(expected[name], result["candidates"])
        files[name] = {**metrics, "errors": result["errors"],
                       "titles": [c["title"] for c in result["candidates"] if c["supported"]]}
        for metric, value in metrics.items():
            totals[metric] = totals.get(metric, 0) + value
    totals["citation_verification_rate"] = round(totals["verified_citations"] / totals["citations"], 3) \
        if totals.get("citations") else None
    return {"mode": "with memory" if with_memory else "without memory", "model": model, "prompt_version": PROMPT_VERSION,
            "seconds": round(time.monotonic() - started, 1), "totals": totals, "files": files}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m watchtower.services.ai.evaluate", description=__doc__.split("\n\n")[0])
    parser.add_argument("fixtures", type=Path)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--recorded", type=Path, help="replay answers from this file (no model)")
    source.add_argument("--record", type=Path, help="ask the configured local model and save its answers here")
    parser.add_argument("--memory", action="store_true", help="also evaluate with the fixtures' memory examples")
    parser.add_argument("--profile")
    args = parser.parse_args(argv)
    from watchtower.config import load_settings
    settings = load_settings(args.profile).ai
    if args.recorded:
        client: Any = Recorded(args.recorded)
    else:
        from watchtower.adapters.ai.ollama import OllamaClient
        client = Recorder(OllamaClient.from_settings(settings))
    reports = [evaluate(args.fixtures, client, settings.model, settings, with_memory=False)]
    if args.memory:
        reports.append(evaluate(args.fixtures, client, settings.model, settings, with_memory=True))
    if args.record:
        args.record.write_text(json.dumps(client.answers, indent=1, sort_keys=True))
    json.dump(reports, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
