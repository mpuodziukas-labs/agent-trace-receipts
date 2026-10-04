"""evaluate.py - run the agent over every synthetic invoice, then attack the
traces with a tamper suite and print what the verifier caught.

Usage:
    python3 evaluate.py

Prints a markdown table (deterministic: no timings). Exit 0 if every check is
N/N, 1 otherwise, 2 on usage error.

Each run uses a fresh random TRACE_KEY, so no key is needed to run it.

Tamper classes (applied to clean traces):
    edit_line, delete_step, reorder_steps   raw edits, chain left as is
    rechain_unkeyed                         an outsider edits a step and
                                            recomputes the whole chain and head
                                            without the key (plain SHA-256)
    truncate_unkeyed                        an outsider drops the last step and
                                            rewrites the head from the dropped
                                            line's prev_hash, without the key
    approve_after_failure, approve_open_flag, missing_end_time,
    noncanonical_with_key, bad_sequence_with_key, forge_output_with_key,
    truncate_with_key, drop_flag_with_key, approve_without_compare,
    forge_compare_input, splice_runs, reversed_times
                                            forged by an insider who holds the
                                            key and re-chains validly, so only
                                            the semantic checks can catch them

A tamper row counts as refused only when the full verifier refuses the trace AND
the check that owns the class (OWNER below) fires on it. A check that is switched
off therefore lowers its own rows below N/N instead of hiding behind the others.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import agent
import verify
import hashlib

from trace import GENESIS, canonical, chain_hash, get_key, head_mac, head_path, sha256_json

HERE = Path(__file__).resolve().parent


def _read(src: Path) -> tuple[list[str], list[dict]]:
    raw = src.read_text().splitlines()
    return raw, [json.loads(x) for x in raw]


def _link(key: Optional[bytes], line: str) -> str:
    if key is None:  # an attacker with no key can only use plain SHA-256
        return hashlib.sha256(line.encode("utf-8")).hexdigest()
    return chain_hash(key, line)


def _head_mac(key: Optional[bytes], run_id: str, steps: int, last_line: str) -> str:
    if key is None:  # an attacker with no key can only use plain SHA-256
        return hashlib.sha256(f"head\0{run_id}\0{steps}\0{last_line}".encode("utf-8")).hexdigest()
    return head_mac(key, run_id, steps, last_line)


def write_lines(dst: Path, lines: list[str], key: Optional[bytes], run_id: str) -> None:
    """Write raw lines that already carry their prev_hash, then a head for them."""
    dst.write_text("\n".join(lines) + "\n")
    head_path(dst).write_text(canonical({
        "run_id": run_id, "steps": len(lines), "last_hash": _link(key, lines[-1]),
        "mac": _head_mac(key, run_id, len(lines), lines[-1])}) + "\n")


def write_rechained(dst: Path, recs: list[dict], key: Optional[bytes] = ...,  # type: ignore[assignment]
                    renumber: bool = True) -> None:
    """Write records with fresh step numbers, chain and head (an attacker's re-chain).

    key=None models an attacker without the key; default is the TRACE_KEY holder."""
    if key is ...:
        key = get_key()
    prev, lines = GENESIS, []
    for i, rec in enumerate(recs):
        rec["prev_hash"] = prev
        if renumber:
            rec["step"] = i
        line = canonical(rec)
        lines.append(line)
        prev = _link(key, line)
    write_lines(dst, lines, key, recs[0]["run_id"])


def _write_raw(src: Path, dst: Path, lines: list[str]) -> None:
    dst.write_text("\n".join(lines) + "\n")
    head_path(dst).write_text(head_path(src).read_text())


def edit_line(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    raw, recs = _read(src)
    if len(raw) < 2:
        return False
    recs[0]["end_ms"] += 1
    raw[0] = canonical(recs[0])
    _write_raw(src, dst, raw)
    return True


def delete_step(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    raw, _ = _read(src)
    if len(raw) < 3:  # a 2-step trace loses its last step: that is truncation, owned by the head
        return False
    del raw[len(raw) // 2]
    _write_raw(src, dst, raw)
    return True


def reorder_steps(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    raw, _ = _read(src)
    if len(raw) < 2:
        return False
    raw[0], raw[1] = raw[1], raw[0]
    _write_raw(src, dst, raw)
    return True


def _approve_record(recs: list[dict], iid: str) -> dict:
    inp = {"invoice_id": iid}
    out = agent.approve(None, inp)  # type: ignore[arg-type]
    t = recs[-1]["end_ms"] + 1
    return {"run_id": recs[0]["run_id"], "parent": len(recs) - 1, "tool": "approve",
            "input": inp, "input_sha256": sha256_json(inp), "output": out,
            "output_sha256": sha256_json(out), "rc": 0, "start_ms": t, "end_ms": t + 1}


def approve_after_failure(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    _, recs = _read(src)
    if not any(r["rc"] != 0 for r in recs):
        return False
    recs = [r for r in recs if r["tool"] != "flag_mismatch"]
    recs.append(_approve_record(recs, verify.invoice_of(recs) or ""))
    write_rechained(dst, recs, key or get_key())
    return True


def approve_open_flag(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    _, recs = _read(src)
    if any(r["rc"] != 0 for r in recs) or not any(r["tool"] == "flag_mismatch" for r in recs):
        return False
    recs.append(_approve_record(recs, verify.invoice_of(recs) or ""))
    write_rechained(dst, recs, key or get_key())
    return True


def missing_end_time(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    _, recs = _read(src)
    recs[0]["end_ms"] = None
    write_rechained(dst, recs, key or get_key())
    return True


def rechain_unkeyed(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    _, recs = _read(src)
    recs[0]["end_ms"] += 5
    write_rechained(dst, recs, None)
    return True


def truncate_with_key(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    _, recs = _read(src)
    if len(recs) < 2:
        return False
    write_rechained(dst, recs[:-1], key or get_key())
    return True


def truncate_unkeyed(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    """Outsider: drop the last step, then rewrite the head with the dropped line's prev_hash."""
    raw, recs = _read(src)
    if len(raw) < 2:
        return False
    kept = raw[:-1]
    dst.write_text("\n".join(kept) + "\n")
    head_path(dst).write_text(canonical({
        "run_id": recs[0]["run_id"], "steps": len(kept), "last_hash": recs[-1]["prev_hash"],
        "mac": _head_mac(None, recs[0]["run_id"], len(kept), kept[-1])}) + "\n")
    return True


def noncanonical_with_key(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    """Insider re-serializes line 0 with different spacing and re-chains: same data, wrong form."""
    _, recs = _read(src)
    key = key or get_key()
    prev, lines = GENESIS, []
    for i, rec in enumerate(recs):
        rec["step"], rec["prev_hash"] = i, prev
        line = json.dumps(rec, sort_keys=True) if i == 0 else canonical(rec)
        lines.append(line)
        prev = _link(key, line)
    write_lines(dst, lines, key, recs[0]["run_id"])
    return True


def bad_sequence_with_key(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    _, recs = _read(src)
    recs[-1]["step"] = len(recs) + 6
    write_rechained(dst, recs, key or get_key(), renumber=False)
    return True


def forge_output_with_key(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    """Insider edits a recorded tool output (and its hash) and re-chains: only replay disagrees."""
    _, recs = _read(src)
    recs[0]["output"]["lines"][0]["qty"] += 1
    recs[0]["output_sha256"] = sha256_json(recs[0]["output"])
    write_rechained(dst, recs, key or get_key())
    return True


def drop_flag_with_key(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    _, recs = _read(src)
    if not any(r["tool"] == "flag_mismatch" for r in recs):
        return False
    write_rechained(dst, [r for r in recs if r["tool"] != "flag_mismatch"], key or get_key())
    return True


def approve_without_compare(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    _, recs = _read(src)
    if any(r["tool"] == "compare_lines" or r["rc"] != 0 for r in recs):
        return False
    recs = [r for r in recs if r["tool"] != "flag_mismatch"]
    recs.append(_approve_record(recs, verify.invoice_of(recs) or ""))
    write_rechained(dst, recs, key or get_key())
    return True


def forge_compare_input(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    """Hide a mismatch by editing the PO embedded in compare_lines' input, then approve."""
    _, recs = _read(src)
    cmp = next((r for r in recs if r["tool"] == "compare_lines" and r["output"]["mismatches"]), None)
    if cmp is None:
        return False
    for po_ln in cmp["input"]["po"]["lines"]:
        for ln in cmp["input"]["invoice"]["lines"]:
            if ln["sku"] == po_ln["sku"]:
                po_ln["unit_price_cents"], po_ln["qty"] = ln["unit_price_cents"], ln["qty"]
    cmp["input_sha256"] = sha256_json(cmp["input"])
    cmp["output"] = agent.compare_lines(data, cmp["input"])
    cmp["output_sha256"] = sha256_json(cmp["output"])
    recs = [r for r in recs if r["tool"] != "flag_mismatch"]
    recs.append(_approve_record(recs, verify.invoice_of(recs) or ""))
    write_rechained(dst, recs, key or get_key())
    return True


def splice_runs(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    """First step of this run, then the rest of a different run relabelled to this run_id."""
    others = [p for p in sorted(src.parent.glob("run-*.jsonl")) if p != src]
    if not others:
        return False
    _, recs = _read(src)
    _, other = _read(others[0])
    spliced = recs[:1] + [dict(r, run_id=recs[0]["run_id"]) for r in other[1:]]
    write_rechained(dst, spliced, key or get_key())
    return True


def reversed_times(src: Path, dst: Path, data: agent.Data, key: Optional[bytes] = None) -> bool:
    _, recs = _read(src)
    recs[0]["end_ms"] = recs[0]["start_ms"] - 1
    write_rechained(dst, recs, key or get_key())
    return True


TAMPERS: dict[str, Callable[..., bool]] = {
    "edit_line": edit_line,
    "delete_step": delete_step,
    "reorder_steps": reorder_steps,
    "approve_after_failure": approve_after_failure,
    "approve_open_flag": approve_open_flag,
    "missing_end_time": missing_end_time,
    "rechain_unkeyed": rechain_unkeyed,
    "truncate_unkeyed": truncate_unkeyed,
    "noncanonical_with_key": noncanonical_with_key,
    "bad_sequence_with_key": bad_sequence_with_key,
    "forge_output_with_key": forge_output_with_key,
    "truncate_with_key": truncate_with_key,
    "drop_flag_with_key": drop_flag_with_key,
    "approve_without_compare": approve_without_compare,
    "forge_compare_input": forge_compare_input,
    "splice_runs": splice_runs,
    "reversed_times": reversed_times,
}


# The check that must fire for each class (the six formerly masked checks each own a class).
OWNER: dict[str, str] = {
    "edit_line": "chain", "delete_step": "chain", "reorder_steps": "chain",
    "rechain_unkeyed": "chain", "truncate_unkeyed": "head",
    "noncanonical_with_key": "shape", "bad_sequence_with_key": "sequence",
    "forge_output_with_key": "replay", "missing_end_time": "times", "reversed_times": "times",
    "approve_after_failure": "approve_after_failure", "approve_open_flag": "approve_open_flag",
    "truncate_with_key": "expected_run", "drop_flag_with_key": "expected_run",
    "approve_without_compare": "expected_run", "forge_compare_input": "expected_run",
    "splice_runs": "expected_run",
}


def attributed(path: Path, data: agent.Data, key: bytes, cls: str) -> bool:
    """Refused by the full verifier and the owning check fires on its own."""
    if verify.verify_trace(path, data, key).ok:
        return False
    try:
        return OWNER[cls] in verify.firing_checks(path, data, key)
    except Exception:
        return False


@dataclass
class Results:
    caught: tuple[int, int]
    clean_accepted: tuple[int, int]
    tamper: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        pairs = [self.caught, self.clean_accepted, *self.tamper.values()]
        return all(a == b and b > 0 for a, b in pairs)


def run(data_dir: Optional[Path] = None, key: Optional[bytes] = None) -> Results:
    key = key or secrets.token_bytes(32)  # fresh per run; the attacker never sees it
    data = agent.Data.load(data_dir or HERE / "data")
    with tempfile.TemporaryDirectory() as td:
        clean = Path(td) / "clean"
        clean.mkdir()
        for iid in sorted(data.invoices):
            agent.reconcile(data, iid, clean / f"run-{iid}.jsonl", key)
        paths = sorted(clean.glob("*.jsonl"))
        results = [verify.verify_trace(p, data, key) for p in paths]
        res = Results(
            caught=verify.mismatches_caught(results, data),
            clean_accepted=(sum(r.ok for r in results), len(paths)),
        )
        bad = Path(td) / "bad.jsonl"
        for name, fn in TAMPERS.items():
            refused = total = 0
            for p in paths:
                if fn(p, bad, data, key):
                    total += 1
                    refused += attributed(bad, data, key, name)
            res.tamper[name] = (refused, total)
    return res


def render(res: Results) -> str:
    rows = [("Planted mismatches caught", res.caught), ("Clean traces accepted", res.clean_accepted)]
    rows += [(f"Tampered traces refused: {k}", v) for k, v in res.tamper.items()]
    out = ["| Check | Result |", "|---|---|"]
    out += [f"| {label} | {a}/{b} |" for label, (a, b) in rows]
    return "\n".join(out)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Run the agent and the tamper suite, print N/N results.")
    ap.parse_args(argv)
    res = run()
    print(render(res))
    return 0 if res.ok else 1


if __name__ == "__main__":
    sys.exit(main())
