"""agent.py - deterministic scripted agent (no LLM) that reconciles synthetic
invoices against synthetic purchase orders and records every step.

Usage:
    export TRACE_KEY=<secret, at least 16 characters>
    python3 agent.py                      # all invoices -> ./traces/
    python3 agent.py --invoice INV-1009   # one invoice
    python3 agent.py --data data --out traces

Existing traces are never overwritten unless --force is given.

Exit codes: 0 ok, 2 usage error (including a missing or weak TRACE_KEY, or an existing trace).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Optional

from trace import KeyConfigError, Recorder, get_key

HERE = Path(__file__).resolve().parent


class Data:
    def __init__(self, invoices: dict[str, dict], pos: dict[str, dict], expected: dict[str, dict]) -> None:
        self.invoices = invoices
        self.pos = pos
        self.expected = expected

    @classmethod
    def load(cls, directory: str | Path) -> "Data":
        d = Path(directory)
        invs = json.loads((d / "invoices.json").read_text())["invoices"]
        pos = json.loads((d / "purchase_orders.json").read_text())["purchase_orders"]
        exp_path = d / "expected.json"
        expected = json.loads(exp_path.read_text())["expected"] if exp_path.exists() else {}
        return cls({i["invoice_id"]: i for i in invs}, {p["po_id"]: p for p in pos}, expected)

    def duplicate_of(self, inv: dict) -> Optional[str]:
        for other_id in sorted(self.invoices):
            other = self.invoices[other_id]
            if other_id >= inv["invoice_id"]:
                break
            if (other["vendor"], other["invoice_number"]) == (inv["vendor"], inv["invoice_number"]):
                return other_id
        return None


def load_invoice(data: Data, inp: dict) -> dict:
    inv = data.invoices.get(inp["invoice_id"])
    if inv is None:
        raise LookupError(f"invoice {inp['invoice_id']} not found")
    return {**inv, "duplicate_of": data.duplicate_of(inv)}


def load_po(data: Data, inp: dict) -> dict:
    po = data.pos.get(inp["po_id"])
    if po is None:
        raise LookupError(f"purchase order {inp['po_id']} not found")
    return po


def compare_lines(data: Data, inp: dict) -> dict:
    ordered = {ln["sku"]: ln for ln in inp["po"]["lines"]}
    found = []
    for ln in inp["invoice"]["lines"]:
        po_ln = ordered.get(ln["sku"])
        if po_ln is None:
            found.append({"sku": ln["sku"], "kind": "sku"})
            continue
        if ln["unit_price_cents"] != po_ln["unit_price_cents"]:
            found.append({"sku": ln["sku"], "kind": "price"})
        if ln["qty"] != po_ln["qty"]:
            found.append({"sku": ln["sku"], "kind": "quantity"})
    return {"mismatches": found}


def flag_mismatch(data: Data, inp: dict) -> dict:
    return {"invoice_id": inp["invoice_id"], "reason": inp["reason"], "open": True}


def approve(data: Data, inp: dict) -> dict:
    return {"invoice_id": inp["invoice_id"], "status": "approved"}


TOOLS: dict[str, Callable[[Data, dict], Any]] = {
    "load_invoice": load_invoice,
    "load_po": load_po,
    "compare_lines": compare_lines,
    "flag_mismatch": flag_mismatch,
    "approve": approve,
}


def reconcile(data: Data, invoice_id: str, trace_path: str | Path, key: Optional[bytes] = None,
              force: bool = False) -> dict:
    rec = Recorder(trace_path, f"run-{invoice_id}", key, force=force)
    last: Optional[int] = None

    def call(tool: str, inp: dict) -> Any:
        nonlocal last
        try:
            with rec.step(tool, inp, parent=last) as s:
                s.output = TOOLS[tool](data, inp)
        finally:
            last = s.step
        return s.output

    def flagged(reason: str) -> dict:
        call("flag_mismatch", {"invoice_id": invoice_id, "reason": reason})
        return {"invoice_id": invoice_id, "outcome": "flagged", "reason": reason}

    inv = call("load_invoice", {"invoice_id": invoice_id})
    if inv["duplicate_of"]:
        return flagged("duplicate")
    try:
        po = call("load_po", {"po_id": inv["po_id"]})
    except LookupError:
        return flagged("missing_po")
    cmp = call("compare_lines", {"invoice": inv, "po": po})
    if cmp["mismatches"]:
        return flagged("+".join(sorted({m["kind"] for m in cmp["mismatches"]})))
    call("approve", {"invoice_id": invoice_id})
    return {"invoice_id": invoice_id, "outcome": "approved"}


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Reconcile synthetic invoices and record traces.")
    ap.add_argument("--data", default=str(HERE / "data"), help="data directory")
    ap.add_argument("--out", default="traces", help="trace output directory")
    ap.add_argument("--invoice", help="reconcile only this invoice id")
    ap.add_argument("--force", action="store_true", help="overwrite existing traces")
    args = ap.parse_args(argv)
    try:
        data = Data.load(args.data)
    except (OSError, KeyError, ValueError) as exc:
        ap.error(f"cannot load data: {exc}")
    if args.invoice and args.invoice not in data.invoices:
        ap.error(f"unknown invoice {args.invoice}")
    ids = [args.invoice] if args.invoice else sorted(data.invoices)
    try:
        key = get_key()
    except KeyConfigError as exc:
        ap.error(str(exc))
    for iid in ids:
        try:
            out = reconcile(data, iid, Path(args.out) / f"run-{iid}.jsonl", key, force=args.force)
        except FileExistsError as exc:
            ap.error(f"{exc.filename} exists; pass --force to overwrite the earlier trace")
        print(f"{iid} {out['outcome']}" + (f" ({out['reason']})" if "reason" in out else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
