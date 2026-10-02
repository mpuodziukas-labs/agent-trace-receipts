"""Unit tests for the verifier: clean traces accepted, each tamper refused."""

from __future__ import annotations

from pathlib import Path

import pytest

import agent
import evaluate
import verify

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture(scope="module")
def data():
    return agent.Data.load(DATA_DIR)


@pytest.fixture()
def clean(tmp_path, data):
    d = tmp_path / "clean"
    d.mkdir()
    for iid in data.invoices:
        agent.reconcile(data, iid, d / f"run-{iid}.jsonl")
    return d


def tampered(clean, tmp_path, data, cls, iid):
    dst = tmp_path / "bad.jsonl"
    ok = evaluate.TAMPERS[cls](clean / f"run-{iid}.jsonl", dst, data)
    assert ok, "tamper not applicable to this trace"
    return verify.verify_trace(dst, data)


def test_all_clean_traces_accepted(clean, data):
    paths = sorted(clean.glob("*.jsonl"))
    assert len(paths) == 19
    assert all(verify.verify_trace(p, data).ok for p in paths)


@pytest.mark.parametrize("cls,iid,needle", [
    ("edit_line", "INV-1001", "hash chain"),
    ("delete_step", "INV-1001", "hash chain"),
    ("reorder_steps", "INV-1001", "hash chain"),
    ("approve_after_failure", "INV-1017", "approve after failed step"),
    ("approve_open_flag", "INV-1009", "open mismatch flag"),
    ("missing_end_time", "INV-1001", "end time"),
])
def test_each_tamper_refused_with_cause(clean, tmp_path, data, cls, iid, needle):
    res = tampered(clean, tmp_path, data, cls, iid)
    assert not res.ok
    assert any(needle in e for e in res.errors), res.errors


def test_deleting_last_step_caught_by_head_anchor(clean, tmp_path, data):
    src = clean / "run-INV-1001.jsonl"
    dst = tmp_path / "t.jsonl"
    lines = src.read_text().splitlines()
    dst.write_text("\n".join(lines[:-1]) + "\n")
    (tmp_path / "t.jsonl.head").write_text((clean / "run-INV-1001.jsonl.head").read_text())
    res = verify.verify_trace(dst, data)
    assert not res.ok and any("head" in e for e in res.errors)


def test_missing_head_refused(clean, tmp_path, data):
    dst = tmp_path / "t.jsonl"
    dst.write_text((clean / "run-INV-1001.jsonl").read_text())
    assert not verify.verify_trace(dst, data).ok


def test_empty_trace_refused(tmp_path, data):
    p = tmp_path / "e.jsonl"
    p.write_text("")
    assert not verify.verify_trace(p, data).ok


def test_replay_catches_forged_output_with_valid_chain(clean, tmp_path, data):
    import json
    import trace as tr
    recs = [json.loads(x) for x in (clean / "run-INV-1001.jsonl").read_text().splitlines()]
    recs[0]["output"]["lines"][0]["qty"] += 1
    recs[0]["output_sha256"] = tr.sha256_json(recs[0]["output"])
    dst = tmp_path / "f.jsonl"
    evaluate.write_rechained(dst, recs)
    res = verify.verify_trace(dst, data)
    assert not res.ok and any("replay" in e for e in res.errors)


def test_cli_exit_codes(clean, tmp_path, capsys):
    assert verify.main([str(clean), "--data", str(DATA_DIR)]) == 0
    out = capsys.readouterr().out
    assert "p50" in out and "max" in out and "mismatches caught: 11/11" in out
    bad = tmp_path / "bad.jsonl"
    d = agent.Data.load(DATA_DIR)
    assert evaluate.TAMPERS["edit_line"](clean / "run-INV-1001.jsonl", bad, d)
    assert verify.main([str(bad), "--data", str(DATA_DIR)]) == 1
    assert "REFUSED" in capsys.readouterr().out
    with pytest.raises(SystemExit) as e:
        verify.main([])
    assert e.value.code == 2
    with pytest.raises(SystemExit) as e:
        verify.main(["--help"])
    assert e.value.code == 0
