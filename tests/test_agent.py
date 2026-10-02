"""Unit tests for the scripted reconciliation agent and its data."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import agent

DATA = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture(scope="module")
def data():
    return agent.Data.load(DATA)


def run(data, invoice_id, tmp_path):
    out = agent.reconcile(data, invoice_id, tmp_path / f"{invoice_id}.jsonl")
    steps = [json.loads(x) for x in (tmp_path / f"{invoice_id}.jsonl").read_text().splitlines()]
    return out, steps


def test_data_is_labeled_synthetic():
    for name in ("invoices.json", "purchase_orders.json", "expected.json"):
        assert "SYNTHETIC" in json.loads((DATA / name).read_text())["_synthetic"]


def test_clean_invoice_is_approved(data, tmp_path):
    out, steps = run(data, "INV-1001", tmp_path)
    assert out["outcome"] == "approved"
    assert [s["tool"] for s in steps] == ["load_invoice", "load_po", "compare_lines", "approve"]


@pytest.mark.parametrize("iid,reason", [
    ("INV-1009", "price"), ("INV-1012", "quantity"),
    ("INV-1015", "duplicate"), ("INV-1017", "missing_po"),
])
def test_planted_mismatch_is_flagged_not_approved(data, tmp_path, iid, reason):
    out, steps = run(data, iid, tmp_path)
    assert out == {"invoice_id": iid, "outcome": "flagged", "reason": reason}
    tools = [s["tool"] for s in steps]
    assert "flag_mismatch" in tools and "approve" not in tools


def test_missing_po_step_has_rc1(data, tmp_path):
    _, steps = run(data, "INV-1017", tmp_path)
    assert [s["rc"] for s in steps if s["tool"] == "load_po"] == [1]


def test_every_expected_outcome_matches(data, tmp_path):
    assert len(data.expected) == len(data.invoices) >= 15
    for iid, exp in data.expected.items():
        out, _ = run(data, iid, tmp_path)
        assert out["outcome"] == exp["outcome"]
        assert out.get("reason") == exp.get("reason")


def test_cli_help_and_usage(capsys):
    with pytest.raises(SystemExit) as e:
        agent.main(["--help"])
    assert e.value.code == 0
    with pytest.raises(SystemExit) as e:
        agent.main(["--invoice", "INV-NOPE", "--out", "x"])
    assert e.value.code == 2


def test_cli_runs_all(tmp_path, capsys):
    assert agent.main(["--data", str(DATA), "--out", str(tmp_path)]) == 0
    assert len(list(tmp_path.glob("*.jsonl"))) == 19
