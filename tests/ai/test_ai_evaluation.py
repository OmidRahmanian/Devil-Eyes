"""Phase 7: the evaluation harness replays recorded local-model answers for the lab fixtures (no model needed)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from watchtower.config.settings import AiSettings
from watchtower.services.ai.evaluate import Recorded, evaluate, score

EVAL = Path(__file__).resolve().parent / "eval"
FIXTURES = EVAL / "fixtures"
RECORDINGS = sorted(EVAL.glob("recorded-*.json"))


def test_expectations_are_never_inside_the_fixtures():
    expected = json.loads((FIXTURES / "expected.json").read_text())
    for name in expected:
        text = (FIXTURES / name).read_text().lower()
        assert "expect" not in text and "vuln" not in text and "false positive" not in text


@pytest.mark.parametrize("recording", RECORDINGS, ids=[p.stem for p in RECORDINGS])
def test_replay_reproduces_the_recorded_run(recording):
    report = json.loads((EVAL / recording.name.replace("recorded-", "report-")).read_text())
    client = Recorded(recording)
    settings = AiSettings()
    for mode, with_memory in (("without memory", False), ("with memory", True)):
        replay = evaluate(FIXTURES, client, report[0]["model"], settings, with_memory=with_memory)
        recorded = next(r for r in report if r["mode"] == mode)
        assert replay["totals"] == recorded["totals"]
        assert {name: f["titles"] for name, f in replay["files"].items()} == \
            {name: f["titles"] for name, f in recorded["files"].items()}


def test_scoring_counts_matches_misses_false_positives_and_unsupported():
    expected = [{"category": "dom_xss_sink", "line": 4}, {"category": "open_redirect", "line": 9}]
    candidates = [
        {"category": "dom_xss_sink", "supported": True, "citations": [{"line": 5}], "removed_citations": []},
        {"category": "weak_csp", "supported": True, "citations": [{"line": 1}], "removed_citations": [{}]},
        {"category": "open_redirect", "supported": False, "citations": [], "removed_citations": [{}]},
    ]
    assert score(expected, candidates) == {"expected": 2, "true_positives": 1, "missed": 1, "false_positives": 1,
                                           "unsupported": 1, "citations": 4, "verified_citations": 2}
