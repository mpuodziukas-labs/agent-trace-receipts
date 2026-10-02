"""Evaluation tests: results, README parity, and planted-RED mutation tests."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

import evaluate
import verify

ROOT = Path(__file__).resolve().parent.parent
CLASSES = ["edit_line", "delete_step", "reorder_steps", "approve_after_failure",
           "approve_open_flag", "missing_end_time"]


def test_baseline_all_n_of_n():
    res = evaluate.run()
    assert res.ok
    assert res.caught == (11, 11)
    assert res.clean_accepted == (19, 19)
    assert list(res.tamper) == CLASSES
    for cls, (refused, total) in res.tamper.items():
        assert total > 0 and refused == total, cls


def test_cli_exit_zero_and_help(capsys):
    assert evaluate.main([]) == 0
    assert "11/11" in capsys.readouterr().out
    with pytest.raises(SystemExit) as e:
        evaluate.main(["--help"])
    assert e.value.code == 0


def test_readme_results_table_equals_evaluate_output(capsys):
    evaluate.main([])
    out = capsys.readouterr().out.strip()
    readme = (ROOT / "README.md").read_text()
    m = re.search(r"<!-- results:start -->\n```\n(.*?)\n```\n<!-- results:end -->", readme, re.S)
    assert m, "README results block markers missing"
    assert m.group(1).strip() == out


def test_readme_sample_excerpt_is_real_trace_lines():
    readme = (ROOT / "README.md").read_text()
    m = re.search(r"<!-- sample:start -->\n```json\n(.*?)\n```\n<!-- sample:end -->", readme, re.S)
    assert m
    rows = [json.loads(x) for x in m.group(1).splitlines()]
    assert len(rows) >= 2 and all("prev_hash" in r and "output_sha256" in r for r in rows)


def test_mutation_chain_check_dropped_is_caught(monkeypatch):
    assert evaluate.run().ok  # control first
    monkeypatch.setattr(verify, "check_chain", lambda *a, **k: [])
    res = evaluate.run()
    assert not res.ok
    refused, total = res.tamper["edit_line"]
    assert refused < total


def test_mutation_approve_after_failure_check_dropped_is_caught(monkeypatch):
    assert evaluate.run().ok
    monkeypatch.setattr(verify, "check_approve_after_failure", lambda *a, **k: [])
    res = evaluate.run()
    assert not res.ok
    refused, total = res.tamper["approve_after_failure"]
    assert refused < total
    assert res.tamper["approve_open_flag"][0] == res.tamper["approve_open_flag"][1]


def test_mutation_exit_code_nonzero(monkeypatch, capsys):
    monkeypatch.setattr(verify, "check_approve_after_failure", lambda *a, **k: [])
    assert evaluate.main([]) == 1
