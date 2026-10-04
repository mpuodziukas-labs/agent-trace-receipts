"""verify.py - verify agent traces and REFUSE bad ones.

Refuses: edited line, deleted step, reordered steps, failed step followed by
approve, approve with an open mismatch flag, missing end time, missing head
anchor, and any step whose recorded hashes do not match a replay of the tool
against the data.

Needs the same TRACE_KEY the recorder used (HMAC chain); a missing, short or
wrong key refuses. Also refuses: a trace that differs from a re-run of the
deterministic agent for its invoice, non-canonical or malformed lines.

Usage:
    export TRACE_KEY=<secret, at least 16 characters>
    python3 verify.py traces/ --data data --expect
    python3 verify.py traces/run-INV-1009.jsonl

Also refuses: a head anchor whose own MAC does not verify, a file whose name differs
from its run_id, a duplicate run_id, and (with --expect) any run missing from or not
listed in data/expected.json. A head one line behind is labelled as a recorder crash.

Exit codes: 0 all traces verified, 1 at least one trace refused, 2 usage error
(no traces, bad data directory, TRACE_KEY missing or too short).
"""

from __future__ import annotations

import argparse
import hmac
import json
import math
import statistics
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import agent
from trace import (GENESIS, KeyConfigError, canonical, chain_hash, error_output, get_key, head_mac,
                   head_path, sha256_json)

HERE = Path(__file__).resolve().parent


@dataclass
class Result:
    path: Path
    ok: bool
    errors: list[str] = field(default_factory=list)
    steps: list[dict] = field(default_factory=list)


FIELDS = {"run_id", "step", "parent", "tool", "input", "input_sha256", "output",
          "output_sha256", "rc", "start_ms", "end_ms", "prev_hash"}
MAX_LINE = 1_000_000
MAX_FILE = 16_000_000


def _int(x: object) -> bool:
    return type(x) is int  # excludes bool and float


def check_shape(raw: list[str], steps: list[dict]) -> list[str]:
    errs = []
    for i, (line, rec) in enumerate(zip(raw, steps)):
        if len(line) > MAX_LINE:
            errs.append(f"line {i}: longer than {MAX_LINE} characters")
        elif canonical(rec) != line:
            errs.append(f"line {i}: not in canonical form")
        if set(rec) != FIELDS:
            errs.append(f"line {i}: fields differ from the trace format")
            continue
        ok = (isinstance(rec["run_id"], str) and isinstance(rec["tool"], str)
              and _int(rec["step"]) and (rec["parent"] is None or _int(rec["parent"]))
              and _int(rec["rc"]) and isinstance(rec["input_sha256"], str)
              and isinstance(rec["output_sha256"], str) and isinstance(rec["prev_hash"], str))
        if not ok:
            errs.append(f"line {i}: field has the wrong type")
    return errs


def check_chain(raw: list[str], steps: list[dict], key: bytes) -> list[str]:
    prev = GENESIS
    errs = []
    for i, (line, rec) in enumerate(zip(raw, steps)):
        got = rec.get("prev_hash")
        if not isinstance(got, str) or not hmac.compare_digest(got, prev):
            errs.append(f"line {i}: hash chain broken (edited, reordered, or wrong TRACE_KEY)")
        prev = chain_hash(key, line)
    return errs


def check_head(raw: list[str], steps: list[dict], path: Path, key: bytes) -> list[str]:
    """The head carries its own domain-separated MAC over run_id, step count and last line,
    so it cannot be forged from a chain value (the dropped line's prev_hash)."""
    hp = head_path(path)
    if not hp.is_file():
        return ["head anchor missing"]
    try:
        head = json.loads(hp.read_bytes().decode("utf-8"))
    except (ValueError, RecursionError):
        return ["head anchor unreadable"]
    if not isinstance(head, dict) or set(head) != {"run_id", "steps", "last_hash", "mac"}:
        return ["head anchor unreadable"]
    run_id = steps[0].get("run_id")
    n, mac = head["steps"], head["mac"]
    if not isinstance(mac, str) or not isinstance(run_id, str) or not _int(n):
        return ["head anchor unreadable"]
    if n == len(raw) - 1 and hmac.compare_digest(
            mac, head_mac(key, run_id, n, raw[n - 1] if n else "")):
        return [f"head anchor is one line behind ({n} of {len(raw)} lines): the recorder stopped "
                "between the line write and the head write; incomplete run, not proof of tampering"]
    errs = []
    if n != len(raw):
        errs.append(f"head anchor step count {n!r} != {len(raw)} lines")
    last = head["last_hash"]
    if not isinstance(last, str) or not hmac.compare_digest(last, chain_hash(key, raw[-1])):
        errs.append("head anchor last hash mismatch")
    if head["run_id"] != run_id:
        errs.append("head anchor run_id differs from the trace")
    if not hmac.compare_digest(mac, head_mac(key, run_id, len(raw), raw[-1])):
        errs.append("head anchor signature mismatch")
    return errs


def check_sequence(steps: list[dict]) -> list[str]:
    errs = []
    for i, rec in enumerate(steps):
        if not (_int(rec.get("step")) and rec["step"] == i):
            errs.append(f"line {i}: step number {rec.get('step')!r} out of sequence")
        parent = rec.get("parent")
        if parent is not None and not (_int(parent) and 0 <= parent < i):
            errs.append(f"line {i}: bad parent {parent!r}")
        if rec.get("run_id") != steps[0].get("run_id"):
            errs.append(f"line {i}: run_id differs")
    return errs


def _num(x: object) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def check_times(steps: list[dict]) -> list[str]:
    errs = []
    prev_start = 0.0
    for i, rec in enumerate(steps):
        s, e = rec.get("start_ms"), rec.get("end_ms")
        if not _num(e):
            errs.append(f"step {i}: missing end time")
        elif not _num(s) or s < 0 or e < s:
            errs.append(f"step {i}: end time before start time, or negative time")
        elif s < prev_start:
            errs.append(f"step {i}: starts before the previous step")
        else:
            prev_start = s
    return errs


def check_replay(steps: list[dict], data: agent.Data) -> list[str]:
    errs = []
    for i, rec in enumerate(steps):
        tool = rec.get("tool")
        fn = agent.TOOLS.get(tool) if isinstance(tool, str) else None
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


def check_expected_run(steps: list[dict], data: agent.Data, key: bytes) -> list[str]:
    """The agent is deterministic: re-run it for this invoice and compare every step
    (tool, parent, input, output, rc). Catches dropped, added, spliced or doctored steps,
    forged data flow between steps, and runs that never reached approve or flag."""
    iid = invoice_of(steps)
    if not isinstance(iid, str) or iid not in data.invoices:
        return [f"step 0: invoice {iid!r} is not in the data"]
    if steps[0].get("run_id") != f"run-{iid}":
        return [f"run_id {steps[0].get('run_id')!r} does not belong to invoice {iid}"]
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "expected.jsonl"
        agent.reconcile(data, iid, p, key)
        exp = [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()]
    if len(steps) != len(exp):
        return [f"run has {len(steps)} steps, the agent run for {iid} has {len(exp)}"]
    pick = lambda r: canonical([r.get(k) for k in ("tool", "parent", "input", "output", "rc")])
    return [f"step {i}: differs from the agent run for {iid}"
            for i, (a, b) in enumerate(zip(steps, exp)) if pick(a) != pick(b)]


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


def verify_trace(path: str | Path, data: agent.Data, key: Optional[bytes] = None) -> Result:
    """Fail closed: any problem, including an unexpected exception, refuses the trace."""
    key = key if key is not None else get_key()
    path = Path(path)
    try:
        return _verify(path, data, key)
    except Exception as exc:  # never crash, never accept
        return Result(path, False, [f"could not verify ({type(exc).__name__})"])


def _verify(path: Path, data: agent.Data, key: bytes) -> Result:
    if not path.is_file():
        return Result(path, False, ["not a regular file"])
    if path.stat().st_size > MAX_FILE:
        return Result(path, False, [f"trace larger than {MAX_FILE} bytes"])
    try:
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        return Result(path, False, ["trace is not valid UTF-8"])
    if not text:
        return Result(path, False, ["empty trace"])
    if not text.endswith("\n"):
        return Result(path, False, ["trace does not end with a newline (truncated line)"])
    raw = text[:-1].split("\n")
    try:
        steps = [json.loads(x) for x in raw]
        if not all(isinstance(s, dict) for s in steps):
            raise ValueError("line is not an object")
    except (ValueError, RecursionError) as exc:
        return Result(path, False, [f"unparseable trace: {type(exc).__name__}"])
    errors = check_shape(raw, steps)
    if errors:  # later checks assume the record shape
        return Result(path, False, errors, steps)
    errors = [e for _, errs in run_checks(raw, steps, path, data, key) for e in errs]
    return Result(path, not errors, errors, steps)


CHECK_NAMES = ["chain", "head", "sequence", "times", "replay", "expected_run",
               "approve_after_failure", "approve_open_flag"]


def run_checks(raw: list[str], steps: list[dict], path: Path, data: agent.Data,
               key: bytes) -> list[tuple[str, list[str]]]:
    """Every check after shape, in order, each reporting on its own (no short circuit).
    Looked up by name at call time so a stubbed check shows up in the attribution."""
    me = sys.modules[__name__]
    args = {"chain": (raw, steps, key), "head": (raw, steps, path, key), "sequence": (steps,),
            "times": (steps,), "replay": (steps, data), "expected_run": (steps, data, key),
            "approve_after_failure": (steps,), "approve_open_flag": (steps,)}
    return [(n, getattr(me, "check_" + n)(*args[n])) for n in CHECK_NAMES]


def firing_checks(path: str | Path, data: agent.Data, key: bytes) -> list[str]:
    """Names of the checks that fire on this trace ("shape" alone if the shape is bad)."""
    path = Path(path)
    raw = path.read_text(encoding="utf-8")[:-1].split("\n")
    steps = [json.loads(x) for x in raw]
    if check_shape(raw, steps):
        return ["shape"]
    return [n for n, errs in run_checks(raw, steps, path, data, key) if errs]


def flags_of(steps: list[dict]) -> list[str]:
    return [s["output"]["reason"] for s in steps if s.get("tool") == "flag_mismatch" and s.get("rc") == 0]


def invoice_of(steps: list[dict]) -> Optional[str]:
    if steps and steps[0].get("tool") == "load_invoice" and isinstance(steps[0].get("input"), dict):
        return steps[0]["input"].get("invoice_id")
    return None


def mismatches_caught(results: list[Result], data: agent.Data, full: bool = False) -> tuple[int, int]:
    """full=True takes the denominator from expected.json, not from the files handed in."""
    caught = total = 0
    if full:
        total = sum(1 for e in data.expected.values() if e["outcome"] == "flagged")
    for r in results:
        iid = invoice_of(r.steps)
        exp = data.expected.get(iid or "")
        if exp and exp["outcome"] == "flagged":
            total += 0 if full else 1
            if r.ok and flags_of(r.steps) == [exp["reason"]] and not any(s["tool"] == "approve" for s in r.steps):
                caught += 1
    return caught, total


def report(results: list[Result], data: agent.Data, full: bool = False) -> str:
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
    c, t = mismatches_caught(results, data, full)
    lines.append(f"mismatches caught: {c}/{t}" if t else "mismatches caught: n/a (no planted mismatches in these traces)")
    return "\n".join(lines)


def collect(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for p in map(Path, paths):
        out += sorted(p.glob("*.jsonl")) if p.is_dir() else [p]
    return out


def bind_names(results: list[Result]) -> None:
    """The file name must be its run_id (for run-* files) and no run_id may appear twice."""
    seen: dict[str, list[Result]] = {}
    for r in results:
        if not r.steps:
            continue
        rid = r.steps[0].get("run_id")
        seen.setdefault(rid, []).append(r)
        if r.path.name.startswith("run-") and r.path.name != f"{rid}.jsonl":
            r.ok = False
            r.errors.append(f"file name does not match its run_id {rid!r}")
    for rid, group in seen.items():
        if len(group) > 1:
            for r in group:
                r.ok = False
                r.errors.append(f"duplicate run_id {rid!r} in {len(group)} files")


def expected_set(paths: list[str], results: list[Result], data: agent.Data) -> tuple[list[str], int]:
    """Compare what was handed in with the run list in expected.json (missing, extra, renamed)."""
    want = {f"run-{iid}.jsonl" for iid in data.expected}
    have = {r.path.name for r in results}
    notes = [f"MISSING {n}: expected.json lists it, no such trace" for n in sorted(want - have)]
    notes += [f"EXTRA {n}: not in expected.json" for n in sorted(have - want)]
    for d in map(Path, paths):  # stray files in a trace directory (e.g. a renamed .bak)
        if d.is_dir():
            notes += [f"EXTRA {f.name}: not in expected.json" for f in sorted(d.iterdir())
                      if f.name not in want and not f.name.endswith(".head") and f.name not in have]
    return notes, len(want)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Verify agent traces; refuse tampered or unsafe ones.")
    ap.add_argument("traces", nargs="+", help="trace .jsonl files or directories")
    ap.add_argument("--data", default=str(HERE / "data"), help="data directory used for replay")
    ap.add_argument("--expect", action="store_true",
                    help="require exactly the runs listed in <data>/expected.json: missing, extra "
                         "or renamed traces are refused and mismatch counts use that list")
    args = ap.parse_args(argv)
    paths = collect(args.traces)
    if not paths or not all(p.exists() for p in paths):
        ap.error("no traces found")
    try:
        key = get_key()
    except KeyConfigError as exc:
        ap.error(str(exc))
    try:
        data = agent.Data.load(args.data)
    except (OSError, KeyError, ValueError) as exc:
        ap.error(f"cannot load data: {exc}")
    results = [verify_trace(p, data, key) for p in paths]
    bind_names(results)
    notes, total = [], len(results)
    if args.expect:
        if not data.expected:
            ap.error("--expect needs expected.json in the data directory")
        notes, total = expected_set(args.traces, results, data)
        for r in results:
            if r.path.name != f"{(r.steps[0].get('run_id') if r.steps else None)}.jsonl":
                r.ok = False
                r.errors.append("file name does not match its run_id")
    for r in results:
        if not r.ok:
            print(f"REFUSED {r.path.name}: " + "; ".join(dict.fromkeys(r.errors)))
    for n in notes:
        print(f"REFUSED {n}")
    good = [r for r in results if r.ok]
    print(report(good, data, args.expect))
    print(f"verified {len(good)}/{max(total, len(results))} traces")
    return 0 if len(good) == len(results) and not notes else 1


if __name__ == "__main__":
    sys.exit(main())
