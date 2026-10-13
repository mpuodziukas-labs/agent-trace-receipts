"""multiagent.py - two scripted agents, handoff records, escalation to a human queue, and a verifier.

Synthetic and scripted: no model call, no network. Both agents write to ONE existing HMAC-chained
trace (record shape unchanged). The new record types are carried in the existing `tool`, `input`
and `output` fields:

  act             {agent, case, action}            an agent does something
  handoff         {from, to, reason, context_hash, handoff_id}
  receive         {agent, handoff_id, context_hash}
  escalate        {agent, case, reason, confidence, amount, queue: "human"}   instead of acting
  human_approval  {escalation_step, approver, decision}

Escalation rule: confidence below THRESHOLD, or a policy hit (refund over LIMIT), routes the case
to the human queue. No act, handoff or receive may follow until a human_approval for that
escalation is on the chain.

Usage:
    python3 multiagent.py     # run the scenario, verify it, run the planted tampers, print N/N
Exit codes: 0 all checks passed and every tamper refused with the expected reason, 1 otherwise.
"""

from __future__ import annotations

import json
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Callable, Optional

import trace as tr
import verify as vf

THRESHOLD = 0.80
LIMIT = 500
RUN_ID = "multiagent-demo"

CASES = [  # (case, amount, intake confidence)
    ("CASE-1", 40, 0.97),
    ("CASE-2", 75, 0.62),
    ("CASE-3", 900, 0.91),
]


def should_escalate(confidence: float, amount: int) -> Optional[str]:
    if confidence < THRESHOLD:
        return "low_confidence"
    if amount > LIMIT:
        return "policy:refund_over_limit"
    return None


def _act(rec: tr.Recorder, agent: str, case: str, action: str, out: dict) -> None:
    with rec.step("act", {"agent": agent, "case": case, "action": action}) as s:
        s.output = out


def _handoff(rec: tr.Recorder, case: str, amount: int, hid: str, reason: str) -> None:
    ctx = {"case": case, "amount": amount}
    h = tr.sha256_json(ctx)
    with rec.step("handoff", {"from": "intake", "to": "resolver", "reason": reason,
                              "context_hash": h, "handoff_id": hid}) as s:
        s.output = {"sent": True}
    with rec.step("receive", {"agent": "resolver", "handoff_id": hid, "context_hash": h}) as s:
        s.output = {"accepted": True}


def _escalate(rec: tr.Recorder, agent: str, case: str, why: str, conf: float, amount: int) -> int:
    with rec.step("escalate", {"agent": agent, "case": case, "reason": why, "confidence": conf,
                               "amount": amount, "queue": "human"}) as s:
        s.output = {"queued": True}
    return rec._n - 1


def run_scenario(path: str | Path, key: bytes, force: bool = False) -> None:
    rec = tr.Recorder(path, RUN_ID, key=key, force=force)
    for n, (case, amount, conf) in enumerate(CASES):
        _act(rec, "intake", case, "classify", {"category": "refund", "confidence": conf})
        why = should_escalate(conf, 0)  # intake judges on confidence only
        if why:
            at = _escalate(rec, "intake", case, why, conf, amount)
            with rec.step("human_approval", {"escalation_step": at, "approver": "human:ops-queue",
                                             "decision": "approved"}) as s:
                s.output = {"recorded": True}
        _handoff(rec, case, amount, f"H-{n + 1}", "classified:refund")
        _act(rec, "resolver", case, "evaluate_refund", {"amount": amount})
        why = should_escalate(1.0, amount)  # resolver judges on policy
        if why:
            _escalate(rec, "resolver", case, why, 1.0, amount)  # left pending in the human queue
        else:
            _act(rec, "resolver", case, "issue_refund", {"amount": amount, "issued": True})


# ---- verifier -------------------------------------------------------------------------------

def check_handoff_receive(steps: list[dict]) -> list[str]:
    errs, pending, done = [], {}, set()
    all_ids = {r["input"].get("handoff_id") for r in steps
               if r["tool"] == "handoff" and isinstance(r["input"], dict)}
    for i, r in enumerate(steps):
        inp = r["input"] if isinstance(r["input"], dict) else {}
        hid = inp.get("handoff_id")
        if r["tool"] == "handoff":
            if hid in pending or hid in done:
                errs.append(f"step {i}: duplicate handoff id {hid!r}")
            pending[hid] = inp
        elif r["tool"] == "receive":
            if hid in done:
                errs.append(f"step {i}: duplicate receive for handoff {hid!r}")
            elif hid in pending:
                h = pending.pop(hid)
                done.add(hid)
                if h.get("to") != inp.get("agent"):
                    errs.append(f"step {i}: receive by {inp.get('agent')!r}, handoff was to {h.get('to')!r}")
                if h.get("context_hash") != inp.get("context_hash"):
                    errs.append(f"step {i}: context hash differs between handoff and receive")
            elif hid in all_ids:
                errs.append(f"step {i}: receive before handoff {hid!r}")
            else:
                errs.append(f"step {i}: receive without handoff {hid!r}")
    for hid in pending:
        errs.append(f"handoff without receive {hid!r}")
    return errs


def check_escalation_gate(steps: list[dict]) -> list[str]:
    errs, open_at = [], None
    for i, r in enumerate(steps):
        inp = r["input"] if isinstance(r["input"], dict) else {}
        t = r["tool"]
        if t in ("act", "handoff", "receive") and open_at is not None:
            errs.append(f"step {i}: action after escalation without human approval "
                        f"(escalated at step {open_at})")
        elif t == "escalate":
            if inp.get("queue") != "human":
                errs.append(f"step {i}: escalation not routed to the human queue")
            if open_at is None:
                open_at = i
        elif t == "human_approval":
            if open_at is None or inp.get("escalation_step") != open_at or inp.get("decision") != "approved":
                errs.append(f"step {i}: human approval does not match an open escalation")
            else:
                open_at = None
    return errs


CHECKS: list[tuple[str, Callable]] = [
    ("chain", lambda raw, steps, p, k: vf.check_chain(raw, steps, k)),
    ("head", lambda raw, steps, p, k: vf.check_head(raw, steps, p, k)),
    ("sequence", lambda raw, steps, p, k: vf.check_sequence(steps)),
    ("times", lambda raw, steps, p, k: vf.check_times(steps)),
    ("handoff_receive", lambda raw, steps, p, k: check_handoff_receive(steps)),
    ("escalation_gate", lambda raw, steps, p, k: check_escalation_gate(steps)),
]


def run_checks(path: Path, key: bytes) -> tuple[list[tuple[str, list[str]]], list[dict]]:
    text = path.read_bytes().decode("utf-8")
    raw = text[:-1].split("\n")
    steps = [json.loads(x) for x in raw]
    if vf.check_shape(raw, steps):
        return [("shape", vf.check_shape(raw, steps))], steps
    return [(n, f(raw, steps, path, key)) for n, f in CHECKS], steps


def verify_multiagent(path: str | Path, key: bytes) -> vf.Result:
    """Fail closed: any problem, including an unexpected exception, refuses the trace."""
    path = Path(path)
    try:
        res, steps = run_checks(path, key)
    except Exception as exc:
        return vf.Result(path, False, [f"could not verify ({type(exc).__name__})"])
    errs = [e for _, es in res for e in es]
    return vf.Result(path, not errs, errs, steps)


# ---- planted tampers (the attacker holds the key and re-signs, so only the new checks can catch it)

def _drop_handoff(recs: list[dict]) -> None:
    del recs[next(i for i, r in enumerate(recs) if r["tool"] == "handoff")]


def _drop_approval(recs: list[dict]) -> None:
    del recs[next(i for i, r in enumerate(recs) if r["tool"] == "human_approval")]


def _reorder(recs: list[dict]) -> None:
    i = next(i for i, r in enumerate(recs) if r["tool"] == "handoff")
    recs[i], recs[i + 1] = recs[i + 1], recs[i]


TAMPERS: dict[str, tuple[Callable, str]] = {
    "dropped_handoff": (_drop_handoff, "receive without handoff"),
    "action_after_escalation": (_drop_approval, "action after escalation without human approval"),
    "reordered_records": (_reorder, "receive before handoff"),
}


def plant(name: str, src: Path, dst: Path, key: bytes) -> None:
    """Copy src to dst with one planted change, then renumber and re-sign the chain and head."""
    recs = [json.loads(x) for x in Path(src).read_text().splitlines()]
    TAMPERS[name][0](recs)
    prev, lines = tr.GENESIS, []
    for i, r in enumerate(recs):
        r["step"], r["prev_hash"] = i, prev
        line = tr.canonical(r)
        lines.append(line)
        prev = tr.chain_hash(key, line)
    Path(dst).write_text("\n".join(lines) + "\n", encoding="utf-8")
    tr.write_head(Path(dst), key, RUN_ID, len(lines), prev, lines[-1])


# ---- command ---------------------------------------------------------------------------------

def _detail(r: dict) -> str:
    i = r["input"]
    if r["tool"] == "act":
        return f"{i['agent']:8} {i['action']} {i['case']}"
    if r["tool"] == "handoff":
        return f"{i['from']} -> {i['to']} {i['handoff_id']} ({i['reason']}) ctx={i['context_hash'][:8]}"
    if r["tool"] == "receive":
        return f"{i['agent']} got {i['handoff_id']} ctx={i['context_hash'][:8]}"
    if r["tool"] == "escalate":
        return f"{i['agent']} {i['case']} -> human queue ({i['reason']})"
    return f"{i['approver']} {i['decision']} escalation at step {i['escalation_step']}"


def main() -> int:
    key = secrets.token_hex(16).encode()
    ok = True
    with tempfile.TemporaryDirectory() as d:
        good = Path(d) / "run.jsonl"
        run_scenario(good, key)
        res, steps = run_checks(good, key)
        print("scenario: intake and resolver, 3 cases, one chained trace")
        for i, r in enumerate(steps):
            print(f"  {i:2} {r['tool']:15} {_detail(r)}")
        open_esc = sum(1 for r in steps if r["tool"] == "escalate") - sum(
            1 for r in steps if r["tool"] == "human_approval")
        print(f"human queue: {open_esc} escalation pending approval")
        passed = sum(1 for _, e in res if not e)
        ok = ok and passed == len(res)
        print(f"verification: {passed}/{len(res)} checks passed ({', '.join(n for n, _ in res)})")
        refused = 0
        for name, (_, reason) in TAMPERS.items():
            bad = Path(d) / f"{name}.jsonl"
            plant(name, good, bad, key)
            r = verify_multiagent(bad, key)
            hit = (not r.ok) and any(reason in e for e in r.errors)
            refused += hit
            print(f"  planted {name}: {'refused' if hit else 'NOT refused'} ({reason})")
        ok = ok and refused == len(TAMPERS)
        print(f"tamper suite: {refused}/{len(TAMPERS)} refused with the expected reason")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
