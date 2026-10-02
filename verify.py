"""verify.py - verify agent traces and REFUSE bad ones.

Refuses: edited line, deleted step, reordered steps, failed step followed by
approve, approve with an open mismatch flag, missing end time, missing head
anchor, and any step whose recorded hashes do not match a replay of the tool
against the data.

Usage:
    python3 verify.py traces/ --data data
    python3 verify.py traces/run-INV-1009.jsonl

Exit codes: 0 all traces verified, 1 at least one trace refused, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import agent
from trace import GENESIS, error_output, head_path, sha256_json, sha256_text

HERE = Path(__file__).resolve().parent


@dataclass
class Result:
    path: Path
    ok: bool
    errors: list[str] = field(default_factory=list)
    steps: list[dict] = field(default_factory=list)


def check_chain(raw: list[str], steps: list[dict]) -> list[str]:
    prev = GENESIS
    errs = []
    for i, (line, rec) in enumerate(zip(raw, steps)):
        if rec.get("prev_hash") != prev:
            errs.append(f"line {i}: hash chain broken")
        prev = sha256_text(line)
    return errs


def check_head(raw: list[str], path: Path) -> list[str]:
    hp = head_path(path)
    if not hp.exists():
        return ["head anchor missing"]
    try:
        head = json.loads(hp.read_text())
    except ValueError:
        return ["head anchor unreadable"]
    errs = []
    if head.get("steps") != len(raw):
        errs.append(f"head anchor step count {head.get('steps')} != {len(raw)} lines")
    if head.get("last_hash") != sha256_text(raw[-1]):
        errs.append("head anchor last hash mismatch")
    return errs


def check_sequence(steps: list[dict]) -> list[str]:
    errs = []
    for i, rec in enumerate(steps):
        if rec.get("step") != i:
            errs.append(f"line {i}: step number {rec.get('step')} out of sequence")
        parent = rec.get("parent")
        if parent is not None and not (isinstance(parent, int) and 0 <= parent < i):
            errs.append(f"line {i}: bad parent {parent!r}")
        if rec.get("run_id") != steps[0].get("run_id"):
            errs.append(f"line {i}: run_id differs")
    return errs


def _num(x: object) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def check_times(steps: list[dict]) -> list[str]:
    errs = []
    for i, rec in enumerate(steps):
        s, e = rec.get("start_ms"), rec.get("end_ms")
        if not _num(e):
            errs.append(f"step {i}: missing end time")
        elif not _num(s) or e < s:
            errs.append(f"step {i}: end time before start time")
    return errs


def check_replay(steps: list[dict], data: agent.Data) -> list[str]:
    errs = []
    for i, rec in enumerate(steps):
        fn = agent.TOOLS.get(rec.get("tool"))
        if fn is None:
            errs.append(f"step {i}: unknown tool {rec.get('tool')!r}")
            continue
        inp = rec.get("input")
        try:
            rc, out = 0, fn(data, inp)
        except Exception as exc:  # replay must reproduce failures too
            rc, out = 1, error_output(exc)
        if sha256_json(inp) != rec.get("input_sha256"):
            errs.append(f"step {i}: replay input hash mismatch")
        if sha256_json(rec.get("output")) != rec.get("output_sha256"):
            errs.append(f"step {i}: replay output hash does not match recorded output")
        elif sha256_json(out) != rec.get("output_sha256") or rc != rec.get("rc"):
            errs.append(f"step {i}: replay against data differs from recorded output")
    return errs


def check_approve_after_failure(steps: list[dict]) -> list[str]:
    failed = False
    for i, rec in enumerate(steps):
        failed = failed or rec.get("rc") != 0
        if rec.get("tool") == "approve" and failed:
            return [f"step {i}: approve after failed step"]
    return []


def check_approve_open_flag(steps: list[dict]) -> list[str]:
    open_flag = False
    for i, rec in enumerate(steps):
        if rec.get("tool") == "flag_mismatch":
            open_flag = True
        if rec.get("tool") == "compare_lines" and (rec.get("output") or {}).get("mismatches"):
            open_flag = True
        if rec.get("tool") == "approve" and open_flag:
            return [f"step {i}: approve with open mismatch flag"]
    return []


def verify_trace(path: str | Path, data: agent.Data) -> Result:
    path = Path(path)
    raw = path.read_text(encoding="utf-8").splitlines()
    if not raw:
        return Result(path, False, ["empty trace"])
    try:
        steps = [json.loads(x) for x in raw]
        if not all(isinstance(s, dict) for s in steps):
            raise ValueError("line is not an object")
    except ValueError as exc:
        return Result(path, False, [f"unparseable trace: {exc}"])
    errors: list[str] = []
    errors += check_chain(raw, steps)
    errors += check_head(raw, path)
    errors += check_sequence(steps)
    errors += check_times(steps)
    errors += check_replay(steps, data)
    errors += check_approve_after_failure(steps)
    errors += check_approve_open_flag(steps)
    return Result(path, not errors, errors, steps)


def flags_of(steps: list[dict]) -> list[str]:
    return [s["output"]["reason"] for s in steps if s.get("tool") == "flag_mismatch" and s.get("rc") == 0]


def invoice_of(steps: list[dict]) -> Optional[str]:
    return steps[0]["input"].get("invoice_id") if steps and steps[0].get("tool") == "load_invoice" else None


def mismatches_caught(results: list[Result], data: agent.Data) -> tuple[int, int]:
    caught = total = 0
    for r in results:
        iid = invoice_of(r.steps)
        exp = data.expected.get(iid or "")
        if exp and exp["outcome"] == "flagged":
            total += 1
            if r.ok and flags_of(r.steps) == [exp["reason"]] and not any(s["tool"] == "approve" for s in r.steps):
                caught += 1
    return caught, total


def report(results: list[Result], data: agent.Data) -> str:
    steps = [s for r in results for s in r.steps]
    lat: dict[str, list[float]] = {}
    for s in steps:
        if _num(s.get("start_ms")) and _num(s.get("end_ms")):
            lat.setdefault(s["tool"], []).append(round(s["end_ms"] - s["start_ms"], 3))
    lines = [f"traces: {len(results)}  steps: {len(steps)}"]
    for tool in sorted(lat):
        v = lat[tool]
        lines.append(f"  {tool:<14} n={len(v):<3} p50={statistics.median(v):.3f} ms  max={max(v):.3f} ms")
    lines.append(f"failures (rc!=0 steps): {sum(1 for s in steps if s.get('rc') != 0)}")
    c, t = mismatches_caught(results, data)
    lines.append(f"mismatches caught: {c}/{t}" if t else "mismatches caught: n/a (no planted mismatches in these traces)")
    return "\n".join(lines)


def collect(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for p in map(Path, paths):
        out += sorted(p.glob("*.jsonl")) if p.is_dir() else [p]
    return out


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Verify agent traces; refuse tampered or unsafe ones.")
    ap.add_argument("traces", nargs="+", help="trace .jsonl files or directories")
    ap.add_argument("--data", default=str(HERE / "data"), help="data directory used for replay")
    args = ap.parse_args(argv)
    paths = collect(args.traces)
    if not paths or not all(p.exists() for p in paths):
        ap.error("no traces found")
    try:
        data = agent.Data.load(args.data)
    except (OSError, KeyError, ValueError) as exc:
        ap.error(f"cannot load data: {exc}")
    results = [verify_trace(p, data) for p in paths]
    for r in results:
        if not r.ok:
            print(f"REFUSED {r.path.name}: " + "; ".join(r.errors))
    good = [r for r in results if r.ok]
    print(report(good, data))
    print(f"verified {len(good)}/{len(results)} traces")
    return 0 if len(good) == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
