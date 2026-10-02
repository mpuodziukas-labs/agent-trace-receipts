"""Unit tests for the trace recorder."""

from __future__ import annotations

import json

import pytest

import trace as tr

FIELDS = {
    "run_id", "step", "parent", "tool", "input", "input_sha256",
    "output", "output_sha256", "rc", "start_ms", "end_ms", "prev_hash",
}


def read_lines(path):
    return path.read_text().splitlines()


def test_step_writes_all_fields(tmp_path):
    p = tmp_path / "t.jsonl"
    rec = tr.Recorder(p, "run-x")
    with rec.step("tool_a", {"k": 1}) as s:
        s.output = {"v": 2}
    rec_line = json.loads(read_lines(p)[0])
    assert set(rec_line) == FIELDS
    assert rec_line["run_id"] == "run-x"
    assert rec_line["step"] == 0 and rec_line["parent"] is None
    assert rec_line["input_sha256"] == tr.sha256_json({"k": 1})
    assert rec_line["output_sha256"] == tr.sha256_json({"v": 2})
    assert rec_line["rc"] == 0
    assert rec_line["end_ms"] >= rec_line["start_ms"]


def test_hash_chain_links_previous_raw_line(tmp_path):
    p = tmp_path / "t.jsonl"
    rec = tr.Recorder(p, "r")
    for i in range(3):
        with rec.step("t", {"i": i}) as s:
            s.output = i
    lines = read_lines(p)
    recs = [json.loads(x) for x in lines]
    assert recs[0]["prev_hash"] == tr.GENESIS
    assert recs[1]["prev_hash"] == tr.sha256_text(lines[0])
    assert recs[2]["prev_hash"] == tr.sha256_text(lines[1])
    assert [r["step"] for r in recs] == [0, 1, 2]


def test_exception_records_rc1_and_reraises(tmp_path):
    p = tmp_path / "t.jsonl"
    rec = tr.Recorder(p, "r")
    with pytest.raises(LookupError):
        with rec.step("boom", {}) as s:
            raise LookupError("nope")
    r = json.loads(read_lines(p)[0])
    assert r["rc"] == 1
    assert r["output"] == {"error": "LookupError: nope"}
    assert s.step == 0


def test_parent_is_recorded(tmp_path):
    p = tmp_path / "t.jsonl"
    rec = tr.Recorder(p, "r")
    with rec.step("a", {}) as a:
        a.output = 1
    with rec.step("b", {}, parent=a.step) as b:
        b.output = 2
    assert json.loads(read_lines(p)[1])["parent"] == 0


def test_head_anchor_matches_last_line(tmp_path):
    p = tmp_path / "t.jsonl"
    rec = tr.Recorder(p, "r")
    for i in range(2):
        with rec.step("t", {}) as s:
            s.output = i
    head = json.loads(tr.head_path(p).read_text())
    assert head["steps"] == 2
    assert head["last_hash"] == tr.sha256_text(read_lines(p)[-1])


def test_canonical_is_key_order_independent():
    assert tr.sha256_json({"a": 1, "b": 2}) == tr.sha256_json({"b": 2, "a": 1})
