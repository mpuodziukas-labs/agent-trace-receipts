"""Red-team tests. Each attack builds a hostile trace and expects verify to refuse it.

Attackers come in two kinds. "Outsider": cannot read TRACE_KEY, so recomputes
the chain unkeyed (plain SHA-256) or with a guessed key. "Insider": holds the
key and recomputes a perfectly valid keyed chain, so only the semantic checks
(replay, workflow, times) can stop the forgery. The chain link used here is
the documented format: HMAC-SHA256(key, raw previous line), hex.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

import agent
import evaluate
import verify

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
GENESIS = "0" * 64
DUP, PRICE, MISSING, OK = "INV-1015", "INV-1009", "INV-1017", "INV-1001"


def link(key, line):
    if key is None:  # outsider with no key: plain SHA-256, the old unkeyed scheme
        return hashlib.sha256(line.encode()).hexdigest()
    return hmac.new(key, line.encode(), hashlib.sha256).hexdigest()


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"))


def write_chain(dst, recs, key, renumber=True):
    prev, lines = GENESIS, []
    for i, r in enumerate(recs):
        if renumber:
            r["step"] = i
        r["prev_hash"] = prev
        line = canon(r)
        lines.append(line)
        prev = link(key, line)
    Path(dst).write_text("\n".join(lines) + "\n")
    mac_in = f"head\0{recs[0]['run_id']}\0{len(recs)}\0{lines[-1]}".encode()
    mac = (hashlib.sha256(mac_in) if key is None else hmac.new(key, mac_in, hashlib.sha256)).hexdigest()
    Path(str(dst) + ".head").write_text(
        canon({"run_id": recs[0]["run_id"], "steps": len(recs), "last_hash": prev, "mac": mac}) + "\n")


@pytest.fixture(scope="module")
def data():
    return agent.Data.load(DATA_DIR)


@pytest.fixture()
def key():
    return os.environ["TRACE_KEY"].encode()


@pytest.fixture()
def legit(tmp_path, data):
    def make(iid):
        p = tmp_path / f"legit-{iid}.jsonl"
        agent.reconcile(data, iid, p)
        return [json.loads(x) for x in p.read_text().splitlines()]
    return make


def refused(path, data):
    res = verify.verify_trace(path, data)
    assert not res.ok, "verify ACCEPTED a forged trace"
    return res


def test_control_legit_traces_accepted(tmp_path, data, legit):
    p = tmp_path / "c.jsonl"
    agent.reconcile(data, OK, p)
    assert verify.verify_trace(p, data).ok


# ---- 1/2: unkeyed recompute (outsider) ---------------------------------------

def edit_time(recs):
    recs[0]["end_ms"] += 5
    return recs


def flip_flag_to_approve(recs):
    recs[1] = {**recs[1], "tool": "approve", "input": {"invoice_id": DUP},
               "input_sha256": evaluate.sha256_json({"invoice_id": DUP}),
               "output": {"invoice_id": DUP, "status": "approved"},
               "output_sha256": evaluate.sha256_json({"invoice_id": DUP, "status": "approved"})}
    return recs


def truncate_last(recs):
    return recs[:-1]


@pytest.mark.parametrize("attacker", [None, b"guessed-key-0123456789"], ids=["no-key", "wrong-key"])
@pytest.mark.parametrize("mut", [edit_time, flip_flag_to_approve, truncate_last])
def test_full_recompute_without_key_refused(tmp_path, data, legit, attacker, mut):
    recs = mut(legit(DUP))
    dst = tmp_path / "forged.jsonl"
    write_chain(dst, recs, attacker)  # chain AND .head fully recomputed
    refused(dst, data)


def test_verify_with_wrong_key_refuses_clean_trace(tmp_path, data, monkeypatch):
    p = tmp_path / "c.jsonl"
    agent.reconcile(data, OK, p)
    monkeypatch.setenv("TRACE_KEY", "a-different-key-0123456789")
    refused(p, data)


def run_cli(*args, env=None):
    e = {k: v for k, v in os.environ.items() if k != "TRACE_KEY"}
    e.update(env or {})
    return subprocess.run([sys.executable, str(ROOT / "verify.py"), *map(str, args)],
                          capture_output=True, text=True, env=e, cwd=ROOT, timeout=60)


def test_missing_key_is_refused_with_clear_message(tmp_path, data):
    p = tmp_path / "c.jsonl"
    agent.reconcile(data, OK, p)
    r = run_cli(p)
    assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)
    assert "TRACE_KEY" in r.stderr and "Traceback" not in r.stderr


def test_short_key_rejected(tmp_path, data):
    p = tmp_path / "c.jsonl"
    agent.reconcile(data, OK, p)
    r = run_cli(p, env={"TRACE_KEY": "short"})
    assert r.returncode == 2 and "TRACE_KEY" in r.stderr


# ---- 2/3/4: insider forgeries (valid keyed chain, hostile content) ------------

def drop_flag(recs):
    return recs[:-1]


def approve_instead_of_flag(recs):  # duplicate invoice, no compare step at all
    return flip_flag_to_approve(recs)


def approve_twice(recs):
    recs.append({**recs[-1], "parent": len(recs) - 1})
    return recs


def approve_then_flag(recs):  # flag raised AFTER the approve, so no flag is open at approve time
    flag = recs[1]
    appr = flip_flag_to_approve([recs[0], dict(recs[1])])[1]
    return [recs[0], appr, {**flag, "parent": 1}]


def approve_wrong_invoice(recs):
    inp, out = {"invoice_id": "INV-1002"}, {"invoice_id": "INV-1002", "status": "approved"}
    recs[-1].update(input=inp, input_sha256=evaluate.sha256_json(inp),
                    output=out, output_sha256=evaluate.sha256_json(out))
    return recs


def forge_compare_input(recs):
    """Price mismatch hidden by editing the PO embedded in compare_lines' input."""
    cmp = recs[2]
    for ln in cmp["input"]["po"]["lines"]:
        for iv in cmp["input"]["invoice"]["lines"]:
            if iv["sku"] == ln["sku"]:
                ln["unit_price_cents"], ln["qty"] = iv["unit_price_cents"], iv["qty"]
    out = {"mismatches": []}
    cmp.update(input_sha256=evaluate.sha256_json(cmp["input"]), output=out,
               output_sha256=evaluate.sha256_json(out))
    inp, out2 = {"invoice_id": PRICE}, {"invoice_id": PRICE, "status": "approved"}
    recs[3] = {**recs[3], "tool": "approve", "input": inp, "input_sha256": evaluate.sha256_json(inp),
               "output": out2, "output_sha256": evaluate.sha256_json(out2)}
    return recs


def splice_other_run_relabelled(recs, other):
    tail = [dict(r, run_id=recs[0]["run_id"]) for r in other[2:]]
    return recs[:2] + tail


def splice_mixed_run_ids(recs, other):
    return recs[:2] + [dict(r) for r in other[2:]]


def dup_step_numbers(recs):
    recs[2]["step"] = 1
    return recs


def parent_nonexistent(recs):
    recs[1]["parent"] = 99
    return recs


def parent_self(recs):
    recs[1]["parent"] = 1
    return recs


def negative_time(recs):
    recs[0]["start_ms"], recs[0]["end_ms"] = -5.0, -4.0
    return recs


def reversed_time(recs):
    recs[0]["end_ms"] = recs[0]["start_ms"] - 1
    return recs


def nan_time(recs):
    recs[0]["end_ms"] = math.nan
    return recs


def overlapping_time(recs):
    recs[1]["start_ms"] = recs[0]["start_ms"] - 10
    recs[1]["end_ms"] = recs[1]["start_ms"] + 1
    return recs


def step_is_bool(recs):
    recs[1]["step"] = True
    return recs


def step_is_float(recs):
    recs[1]["step"] = 1.0
    return recs


def extra_key(recs):
    recs[0]["approved_by"] = "cfo"
    return recs


def missing_key(recs):
    del recs[0]["rc"]
    return recs


def tool_unicode_lookalike(recs):
    recs[-1]["tool"] = "approve\u200b"
    return recs


def run_id_wrong_for_invoice(recs):
    for r in recs:
        r["run_id"] = "run-INV-1002"
    return recs


def rc_false(recs):
    recs[0]["rc"] = False
    return recs


INSIDER = {
    "drop_flag": (DUP, drop_flag),
    "approve_instead_of_flag": (DUP, approve_instead_of_flag),
    "approve_twice": (OK, approve_twice),
    "approve_then_flag": (DUP, approve_then_flag),
    "approve_wrong_invoice": (OK, approve_wrong_invoice),
    "forge_compare_input": (PRICE, forge_compare_input),
    "dup_step_numbers": (OK, dup_step_numbers),
    "parent_nonexistent": (OK, parent_nonexistent),
    "parent_self": (OK, parent_self),
    "negative_time": (OK, negative_time),
    "reversed_time": (OK, reversed_time),
    "nan_time": (OK, nan_time),
    "overlapping_time": (OK, overlapping_time),
    "step_is_bool": (OK, step_is_bool),
    "step_is_float": (OK, step_is_float),
    "extra_key": (OK, extra_key),
    "missing_key": (OK, missing_key),
    "tool_unicode_lookalike": (OK, tool_unicode_lookalike),
    "run_id_wrong_for_invoice": (OK, run_id_wrong_for_invoice),
    "rc_is_bool": (OK, rc_false),
}


@pytest.mark.parametrize("name", sorted(INSIDER))
def test_insider_forgery_with_valid_keyed_chain_refused(tmp_path, data, legit, key, name):
    iid, mut = INSIDER[name]
    recs = mut(legit(iid))
    dst = tmp_path / "forged.jsonl"
    write_chain(dst, recs, key, renumber=name not in {"dup_step_numbers", "step_is_bool", "step_is_float"})
    refused(dst, data)


@pytest.mark.parametrize("name,fn", [("relabelled", splice_other_run_relabelled),
                                     ("mixed", splice_mixed_run_ids)])
def test_splice_from_another_run_refused(tmp_path, data, legit, key, name, fn):
    recs = fn(legit(PRICE), legit(OK))
    dst = tmp_path / "forged.jsonl"
    write_chain(dst, recs, key)
    refused(dst, data)


# ---- 5: malformed input never crashes, never exits 0 --------------------------

def deep(n):
    return ("[" * n + "]" * n + "\n").encode()


MALFORMED = {
    "invalid_json": b"{not json}\n",
    "empty_file": b"",
    "only_newline": b"\n",
    "invalid_utf8": b"\xff\xfe\x00{\n",
    "huge_line": b'{"a":"' + b"x" * 3_000_000 + b'"}\n',
    "deep_nesting": deep(100_000),
    "json_array": b"[1,2,3]\n",
    "null_line": b"null\n",
    "unhashable_tool": b'{"tool":["x"],"run_id":"r","step":0}\n',
    "unicode_tool": '{"tool":"\u0430pprove","run_id":"r","step":0}\n'.encode(),
    "missing_keys": b"{}\n",
    "nan_literal": b'{"end_ms":NaN}\n',
    "no_trailing_newline_garbage": b'{"a":1}\n{',
}


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_malformed_trace_refused_without_traceback(tmp_path, name):
    p = tmp_path / "bad.jsonl"
    p.write_bytes(MALFORMED[name])
    r = run_cli(p, env={"TRACE_KEY": os.environ["TRACE_KEY"]})
    assert r.returncode in (1, 2), (r.returncode, r.stderr[-300:])
    assert "Traceback" not in r.stderr, r.stderr[-400:]
    assert r.stdout.strip() or r.stderr.strip()


@pytest.mark.parametrize("head", [b"[]", b"null", b"\xff\xff", b'{"steps":true,"last_hash":1}', b""])
def test_malformed_head_refused_without_traceback(tmp_path, data, head):
    p = tmp_path / "t.jsonl"
    agent.reconcile(data, OK, p)
    Path(str(p) + ".head").write_bytes(head)
    r = run_cli(p, env={"TRACE_KEY": os.environ["TRACE_KEY"]})
    assert r.returncode == 1 and "Traceback" not in r.stderr and "REFUSED" in r.stdout


def test_head_run_id_must_match(tmp_path, data):
    p = tmp_path / "t.jsonl"
    agent.reconcile(data, OK, p)
    hp = Path(str(p) + ".head")
    h = json.loads(hp.read_text())
    h["run_id"] = "run-INV-1002"
    hp.write_text(canon(h) + "\n")
    refused(p, data)


# ---- 6: CLI contract -----------------------------------------------------------

def test_cli_help_exit_0():
    assert run_cli("--help").returncode == 0


def test_cli_no_args_exit_2():
    assert run_cli().returncode == 2


def test_cli_missing_path_exit_2(tmp_path):
    r = run_cli(tmp_path / "nope.jsonl", env={"TRACE_KEY": os.environ["TRACE_KEY"]})
    assert r.returncode == 2 and "Traceback" not in r.stderr


def test_cli_empty_directory_exit_2(tmp_path):
    r = run_cli(tmp_path, env={"TRACE_KEY": os.environ["TRACE_KEY"]})
    assert r.returncode == 2


def test_cli_path_is_directory_named_jsonl(tmp_path):
    d = tmp_path / "fake.jsonl"
    d.mkdir()
    r = run_cli(tmp_path, env={"TRACE_KEY": os.environ["TRACE_KEY"]})
    assert r.returncode == 1 and "Traceback" not in r.stderr and "REFUSED" in r.stdout


def test_cli_bad_data_dir_exit_2(tmp_path, data):
    p = tmp_path / "t.jsonl"
    agent.reconcile(data, OK, p)
    r = run_cli(p, "--data", tmp_path / "nodata", env={"TRACE_KEY": os.environ["TRACE_KEY"]})
    assert r.returncode == 2 and "Traceback" not in r.stderr


def test_cli_exit_1_when_any_trace_refused(tmp_path, data):
    agent.reconcile(data, OK, tmp_path / "a.jsonl")
    (tmp_path / "b.jsonl").write_text("garbage\n")
    r = run_cli(tmp_path, env={"TRACE_KEY": os.environ["TRACE_KEY"]})
    assert r.returncode == 1 and "verified 1/2" in r.stdout


def test_cli_exit_0_all_good(tmp_path, data):
    agent.reconcile(data, OK, tmp_path / "a.jsonl")
    r = run_cli(tmp_path, env={"TRACE_KEY": os.environ["TRACE_KEY"]})
    assert r.returncode == 0, r.stdout


# ---- 7: README claims ----------------------------------------------------------

README = (ROOT / "README.md").read_text()
WORDS = {"six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
         "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17}


def test_readme_documents_key_and_hmac():
    assert "TRACE_KEY" in README and "HMAC" in README
    lim = README.split("## Limitations")[1].split("## Files")[0]
    assert "key" in lim.lower() and "TRACE_KEY" in lim
    assert re.search(r"not (the )?truth", lim)


def test_readme_tamper_class_count_matches_suite():
    claims = re.findall(r"\b(" + "|".join(WORDS) + r") tamper classes", README)
    assert claims, "README names no tamper class count"
    assert all(WORDS[c] == len(evaluate.TAMPERS) for c in claims), (claims, len(evaluate.TAMPERS))


def test_readme_quickstart_runs_as_written(tmp_path):
    block = re.search(r"## Quickstart\n\n```bash\n(.*?)```", README, re.S).group(1)
    env = {k: v for k, v in os.environ.items() if k != "TRACE_KEY"}
    ran = 0
    for line in block.splitlines():
        cmd = line.split("#")[0].strip()
        if not cmd:
            continue
        m = re.match(r"export (\w+)=(\S+)$", cmd)
        if m:
            env[m.group(1)] = m.group(2).strip("'\"")
            continue
        argv = cmd.replace("python3", sys.executable, 1).split()
        argv = [str(tmp_path / "traces") if a == "traces" else a for a in argv]
        r = subprocess.run(argv, capture_output=True, text=True, env=env, cwd=ROOT, timeout=120)
        assert r.returncode == 0, (cmd, r.stdout[-300:], r.stderr[-300:])
        ran += 1
    assert ran == 3 and "TRACE_KEY" in env, "Quickstart must export TRACE_KEY"


def test_readme_dataset_numbers_match_data(data):
    assert f"{len(data.invoices)} invoices" in README
    assert f"{len(data.pos)} purchase orders" in README or f"{len(data.pos)},\n> purchase orders" in README or \
        re.search(rf"{len(data.pos)}\s+purchase orders", README)
    assert len(agent.TOOLS) == 5 and "five tools" in README
    reasons = [e["reason"] for e in data.expected.values() if e["outcome"] == "flagged"]
    clean = sum(e["outcome"] == "approved" for e in data.expected.values())
    assert (reasons.count("price"), reasons.count("quantity"), reasons.count("duplicate"),
            reasons.count("missing_po"), len(reasons), clean) == (3, 3, 2, 3, 11, 8)
    assert "3 price, 3 quantity, 2 duplicate invoices, 3 missing\npurchase orders (11 total), plus 8 clean" in README


def test_readme_run_report_numbers_match_verify_output(tmp_path, data):
    block = re.search(r"prints a run report like:\n\n```\n(.*?)```", README, re.S).group(1)
    for iid in data.invoices:
        agent.reconcile(data, iid, tmp_path / f"run-{iid}.jsonl")
    r = run_cli(tmp_path, env={"TRACE_KEY": os.environ["TRACE_KEY"]})
    mask = lambda s: re.sub(r"\d+\.\d+ ms", "T ms", s).strip()
    assert mask(block) == mask("\n".join(r.stdout.splitlines()[:-1]))


def test_readme_sample_variance_claim_is_true(tmp_path, data):
    """README says which fields vary by run; measure it instead of trusting it."""
    def run_once(n):
        p = tmp_path / f"v{n}.jsonl"
        agent.reconcile(data, DUP, p)
        return [json.loads(x) for x in p.read_text().splitlines()]
    a, b = run_once(1), run_once(2)
    varying = {k for x, y in zip(a, b) for k in x if x[k] != y[k]}
    sentence = re.search(r"timestamps[^.]*vary by run", README)
    assert sentence, "README variance sentence missing"
    for field in varying:
        assert field.replace("_ms", "") in sentence.group(0) or field in sentence.group(0) or \
            (field.endswith("_ms") and "timestamps" in sentence.group(0)), (field, sentence.group(0))
