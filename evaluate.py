"""evaluate.py - run the agent over every synthetic invoice, then attack the
traces with a tamper suite and print what the verifier caught.

Usage:
    python3 evaluate.py

Prints a markdown table (deterministic: no timings). Exit 0 if every check is
N/N, 1 otherwise, 2 on usage error.

Tamper classes (applied to clean traces):
    edit_line, delete_step, reorder_steps   raw edits, chain left as is
    approve_after_failure, approve_open_flag, missing_end_time
                                            forged by an attacker who re-chains
                                            the hashes correctly, so only the
                                            semantic checks can catch them
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import agent
import verify
from trace import GENESIS, canonical, head_path, sha256_json, sha256_text

HERE = Path(__file__).resolve().parent


def _read(src: Path) -> tuple[list[str], list[dict]]:
    raw = src.read_text().splitlines()
    return raw, [json.loads(x) for x in raw]


def write_rechained(dst: Path, recs: list[dict]) -> None:
    """Write records with fresh step numbers, chain and head (an attacker's re-chain)."""
    prev, lines = GENESIS, []
    for i, rec in enumerate(recs):
        rec["step"], rec["prev_hash"] = i, prev
        line = canonical(rec)
        lines.append(line)
        prev = sha256_text(line)
    dst.write_text("\n".join(lines) + "\n")
    head_path(dst).write_text(
        canonical({"run_id": recs[0]["run_id"], "steps": len(recs), "last_hash": prev}) + "\n")


def _write_raw(src: Path, dst: Path, lines: list[str]) -> None:
    dst.write_text("\n".join(lines) + "\n")
    head_path(dst).write_text(head_path(src).read_text())


def edit_line(src: Path, dst: Path, data: agent.Data) -> bool:
    raw, recs = _read(src)
    if len(raw) < 2:
        return False
    recs[0]["end_ms"] += 1
    raw[0] = canonical(recs[0])
    _write_raw(src, dst, raw)
    return True


def delete_step(src: Path, dst: Path, data: agent.Data) -> bool:
    raw, _ = _read(src)
    if len(raw) < 2:
        return False
    del raw[len(raw) // 2]
    _write_raw(src, dst, raw)
    return True


def reorder_steps(src: Path, dst: Path, data: agent.Data) -> bool:
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


def approve_after_failure(src: Path, dst: Path, data: agent.Data) -> bool:
    _, recs = _read(src)
    if not any(r["rc"] != 0 for r in recs):
        return False
    recs = [r for r in recs if r["tool"] != "flag_mismatch"]
    recs.append(_approve_record(recs, verify.invoice_of(recs) or ""))
    write_rechained(dst, recs)
    return True


def approve_open_flag(src: Path, dst: Path, data: agent.Data) -> bool:
    _, recs = _read(src)
    if any(r["rc"] != 0 for r in recs) or not any(r["tool"] == "flag_mismatch" for r in recs):
        return False
    recs.append(_approve_record(recs, verify.invoice_of(recs) or ""))
    write_rechained(dst, recs)
    return True


def missing_end_time(src: Path, dst: Path, data: agent.Data) -> bool:
    _, recs = _read(src)
    recs[0]["end_ms"] = None
    write_rechained(dst, recs)
    return True


TAMPERS: dict[str, Callable[[Path, Path, agent.Data], bool]] = {
    "edit_line": edit_line,
    "delete_step": delete_step,
    "reorder_steps": reorder_steps,
    "approve_after_failure": approve_after_failure,
    "approve_open_flag": approve_open_flag,
    "missing_end_time": missing_end_time,
}


@dataclass
class Results:
    caught: tuple[int, int]
    clean_accepted: tuple[int, int]
    tamper: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        pairs = [self.caught, self.clean_accepted, *self.tamper.values()]
        return all(a == b and b > 0 for a, b in pairs)


def run(data_dir: Optional[Path] = None) -> Results:
    data = agent.Data.load(data_dir or HERE / "data")
    with tempfile.TemporaryDirectory() as td:
        clean = Path(td) / "clean"
        clean.mkdir()
        for iid in sorted(data.invoices):
            agent.reconcile(data, iid, clean / f"run-{iid}.jsonl")
        paths = sorted(clean.glob("*.jsonl"))
        results = [verify.verify_trace(p, data) for p in paths]
        res = Results(
            caught=verify.mismatches_caught(results, data),
            clean_accepted=(sum(r.ok for r in results), len(paths)),
        )
        bad = Path(td) / "bad.jsonl"
        for name, fn in TAMPERS.items():
            refused = total = 0
            for p in paths:
                if fn(p, bad, data):
                    total += 1
                    refused += not verify.verify_trace(bad, data).ok
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
