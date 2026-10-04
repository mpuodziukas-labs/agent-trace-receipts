"""Hostile review 2026-10-04: one test per finding (T1-T7), each reproducing the attack
on a temporary copy. Each was run against the unfixed code first and failed."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import agent
import evaluate
import trace as tr
import verify

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
KEY = os.environ.get("TRACE_KEY", "unit-test-key-0123456789")


@pytest.fixture(scope="module")
def data():
    return agent.Data.load(DATA_DIR)


@pytest.fixture()
def traces(tmp_path, data):
    d = tmp_path / "t"
    d.mkdir()
    for iid in sorted(data.invoices):
        agent.reconcile(data, iid, d / f"run-{iid}.jsonl")
    return d


def cli(*args, key="unit-test-key-0123456789", script="verify.py"):
    env = {k: v for k, v in os.environ.items() if k != "TRACE_KEY"}
    env["TRACE_KEY"] = key
    return subprocess.run([sys.executable, str(ROOT / script), *map(str, args)],
                          capture_output=True, text=True, env=env, cwd=ROOT, timeout=120)


# ---- T1: the head signs itself --------------------------------------------------

def forge_truncation(src: Path, dst: Path) -> list[str]:
    """review attack: drop the last step, head last_hash = the dropped line's prev_hash. No key."""
    raw = src.read_text().splitlines()
    dst.write_text("\n".join(raw[:-1]) + "\n")
    head = {"run_id": json.loads(raw[0])["run_id"], "steps": len(raw) - 1,
            "last_hash": json.loads(raw[-1])["prev_hash"]}
    if hasattr(tr, "head_mac"):  # fixed format: the outsider can only guess a MAC
        head["mac"] = json.loads(raw[-1])["prev_hash"]
    tr.head_path(dst).write_text(tr.canonical(head) + "\n")
    return raw


def test_t1_truncate_unkeyed_refused_by_head_check_alone(traces, tmp_path, data, monkeypatch):
    dst = tmp_path / "forged.jsonl"
    forge_truncation(traces / "run-INV-1001.jsonl", dst)
    # replay-style checks off: the chain/head check itself must refuse
    monkeypatch.setattr(verify, "check_expected_run", lambda *a, **k: [])
    monkeypatch.setattr(verify, "check_replay", lambda *a, **k: [])
    res = verify.verify_trace(dst, data)
    assert not res.ok
    assert any("head" in e for e in res.errors), res.errors


def test_t1_head_mac_never_equals_a_chain_value(traces):
    raw = (traces / "run-INV-1001.jsonl").read_text().splitlines()
    head = json.loads((traces / "run-INV-1001.jsonl.head").read_text())
    prevs = {json.loads(x)["prev_hash"] for x in raw}
    assert head["mac"] not in prevs and head["mac"] != head["last_hash"]


# ---- T2 / T3: the expected run set -----------------------------------------------

def test_t2_copied_trace_under_another_name_refused(traces):
    shutil.copy(traces / "run-INV-1001.jsonl", traces / "run-INV-1015.jsonl")
    shutil.copy(traces / "run-INV-1001.jsonl.head", traces / "run-INV-1015.jsonl.head")
    r = cli(traces)
    assert r.returncode == 1, r.stdout
    assert "REFUSED run-INV-1015.jsonl" in r.stdout and "duplicate run_id" in r.stdout


def test_t2_mismatch_denominator_comes_from_expected_json(traces):
    shutil.copy(traces / "run-INV-1001.jsonl", traces / "run-INV-1015.jsonl")
    shutil.copy(traces / "run-INV-1001.jsonl.head", traces / "run-INV-1015.jsonl.head")
    r = cli(traces, "--expect")
    assert r.returncode == 1
    assert "mismatches caught: 10/11" in r.stdout, r.stdout


def test_t3_renamed_trace_refused_with_expect(traces):
    (traces / "run-INV-1003.jsonl").rename(traces / "run-INV-1003.jsonl.bak")
    r = cli(traces, "--expect")
    assert r.returncode == 1, r.stdout
    assert "MISSING run-INV-1003.jsonl" in r.stdout and "EXTRA run-INV-1003.jsonl.bak" in r.stdout


def test_t3_extra_trace_refused_with_expect(traces):
    shutil.copy(traces / "run-INV-1001.jsonl", traces / "run-INV-9999.jsonl")
    shutil.copy(traces / "run-INV-1001.jsonl.head", traces / "run-INV-9999.jsonl.head")
    r = cli(traces, "--expect")
    assert r.returncode == 1 and "EXTRA run-INV-9999.jsonl" in r.stdout


def test_t3_full_set_passes_with_expect(traces):
    r = cli(traces, "--expect")
    assert r.returncode == 0, r.stdout
    assert "mismatches caught: 11/11" in r.stdout and "verified 19/19" in r.stdout


# ---- T4: each row proves the check it names ---------------------------------------

SIX = [("shape", "noncanonical_with_key"), ("head", "truncate_unkeyed"),
       ("sequence", "bad_sequence_with_key"), ("replay", "forge_output_with_key"),
       ("approve_after_failure", "approve_after_failure"),
       ("approve_open_flag", "approve_open_flag")]


@pytest.mark.parametrize("check,cls", SIX)
def test_t4_disabling_a_check_drops_its_row(monkeypatch, check, cls):
    base = evaluate.run()
    assert base.ok and base.tamper[cls][0] == base.tamper[cls][1] > 0  # control first
    monkeypatch.setattr(verify, "check_" + check, lambda *a, **k: [])
    res = evaluate.run()
    refused, total = res.tamper[cls]
    assert refused < total, (check, cls, refused, total)


def test_t4_every_class_has_an_owner_check():
    assert set(evaluate.OWNER) == set(evaluate.TAMPERS)
    assert set(evaluate.OWNER.values()) <= set(verify.CHECK_NAMES) | {"shape"}


# ---- T5: crash between the line write and the head write ---------------------------

def test_t5_crash_before_head_write_is_labelled_not_tampering(tmp_path, data, monkeypatch):
    p = tmp_path / "run-INV-1001.jsonl"
    real, calls = tr.write_head, []

    def crashing(*a, **k):
        calls.append(1)
        if len(calls) == 3:  # init head + first line ok, second line crashes
            raise OSError("simulated crash")
        return real(*a, **k)

    monkeypatch.setattr(tr, "write_head", crashing)
    with pytest.raises(OSError):
        agent.reconcile(data, "INV-1001", p)
    assert json.loads(tr.head_path(p).read_text())["steps"] == 1  # old head intact, parseable
    res = verify.verify_trace(p, data)
    assert not res.ok
    assert any("one line behind" in e and "not proof of tampering" in e for e in res.errors), res.errors


def test_t5_head_write_is_atomic(tmp_path, monkeypatch):
    p = tmp_path / "t.jsonl"
    rec = tr.Recorder(p, "r")
    with rec.step("a", {}) as s:
        s.output = {}
    before = tr.head_path(p).read_bytes()
    monkeypatch.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("crash")))
    with pytest.raises(OSError):
        with rec.step("b", {}) as s:
            s.output = {}
    assert tr.head_path(p).read_bytes() == before  # never an empty or half-written head


def test_t5_fsync_line_before_head(tmp_path, monkeypatch):
    order = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (order.append("fsync"), real(fd))[1])
    rec = tr.Recorder(tmp_path / "t.jsonl", "r")
    order.clear()
    with rec.step("a", {}) as s:
        s.output = {}
    assert order == ["fsync", "fsync"]  # line, then head temp file


# ---- T6: weak keys ------------------------------------------------------------------

@pytest.mark.parametrize("weak", [" " * 16, "k" * 24, "ab" * 12, "\t" * 20])
def test_t6_low_entropy_key_refused(weak):
    with pytest.raises(tr.KeyConfigError):
        tr.get_key({"TRACE_KEY": weak})


def test_t6_whitespace_key_refused_by_agent_cli(tmp_path):
    r = cli("--out", tmp_path / "o", "--invoice", "INV-1001", key=" " * 16, script="agent.py")
    assert r.returncode == 2 and "weak" in r.stderr
    assert not (tmp_path / "o").exists()


def test_t6_normal_keys_still_accepted():
    for ok in ("demo-key-not-secret-0", "unit-test-key-0123456789", "Zq9!x-4kLm#2pRt8"):
        assert tr.get_key({"TRACE_KEY": ok}) == ok.encode()


# ---- T7: no silent overwrite ----------------------------------------------------------

def test_t7_recorder_refuses_to_overwrite(tmp_path):
    p = tmp_path / "t.jsonl"
    rec = tr.Recorder(p, "r")
    with rec.step("a", {}) as s:
        s.output = {}
    before = p.read_bytes()
    with pytest.raises(FileExistsError):
        tr.Recorder(p, "r")
    assert p.read_bytes() == before
    tr.Recorder(p, "r", force=True)
    assert p.read_bytes() == b""


def test_t7_agent_cli_refuses_then_force(tmp_path):
    out = tmp_path / "o"
    assert cli("--out", out, "--invoice", "INV-1001", script="agent.py").returncode == 0
    before = (out / "run-INV-1001.jsonl").read_bytes()
    r = cli("--out", out, "--invoice", "INV-1001", script="agent.py")
    assert r.returncode == 2 and "--force" in r.stderr
    assert (out / "run-INV-1001.jsonl").read_bytes() == before
    assert cli("--out", out, "--invoice", "INV-1001", "--force", script="agent.py").returncode == 0
