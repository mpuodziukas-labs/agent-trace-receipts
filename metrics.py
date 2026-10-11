"""metrics.py - token, latency and cost metrics over a synthetic traffic file.

Each record: route, tool, model, token_in, token_out, latency_ms. cost_usd is
computed from data/pricing.json (illustrative prices, not a vendor quote).
No model call, no network. Traffic is synthetic and seeded.

Usage:
    python3 metrics.py                      # report over data/traffic.jsonl
    python3 metrics.py --traffic FILE --pricing FILE
    python3 metrics.py --generate           # rewrite data/traffic.jsonl (seed 7, 200 records)

Percentiles use the nearest-rank method: the value at rank ceil(p/100 * n) of the sorted list.
Exit codes: 0 ok, 1 invalid record, 2 usage error (unreadable file, empty traffic).
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import defaultdict
from decimal import Decimal
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent
FIELDS = ("route", "tool", "model", "token_in", "token_out", "latency_ms")
ROUTES = {"invoice_reconcile": ("load_invoice", "compare_lines", "approve"),
          "po_lookup": ("load_po",),
          "mismatch_triage": ("flag_mismatch", "compare_lines")}
MODELS = ("model-small", "model-large")


class RecordError(ValueError):
    """A traffic record failed validation."""


def load_pricing(path: str | Path) -> dict[str, dict[str, Decimal]]:
    raw = json.loads(Path(path).read_text())
    return {m: {"in": Decimal(p["in"]), "out": Decimal(p["out"])} for m, p in raw["models"].items()}


def _count(rec: dict, key: str) -> int:
    v = rec[key]
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise RecordError(f"{key} must be a non-negative integer, got {v!r}")
    return v


def validate(rec: object, pricing: dict) -> dict:
    """Return rec with cost_usd (Decimal) added, or raise RecordError."""
    if not isinstance(rec, dict):
        raise RecordError("record is not an object")
    missing = [k for k in FIELDS if k not in rec or rec[k] is None]
    if missing:
        raise RecordError(f"missing field(s): {', '.join(missing)}")
    for k in ("route", "tool", "model"):
        if not isinstance(rec[k], str) or not rec[k]:
            raise RecordError(f"{k} must be a non-empty string")
    if rec["model"] not in pricing:
        raise RecordError(f"model {rec['model']!r} not in pricing table")
    tin, tout = _count(rec, "token_in"), _count(rec, "token_out")
    lat = rec["latency_ms"]
    if isinstance(lat, bool) or not isinstance(lat, (int, float)) or not math.isfinite(lat) or lat < 0:
        raise RecordError(f"latency_ms must be a finite non-negative number, got {lat!r}")
    p = pricing[rec["model"]]
    cost = (tin * p["in"] + tout * p["out"]) / Decimal(1_000_000)
    return {**rec, "cost_usd": cost}


def load_records(path: str | Path, pricing: dict) -> list[dict]:
    out = []
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            out.append(validate(json.loads(line), pricing))
        except (RecordError, ValueError) as exc:
            raise RecordError(f"line {n}: {exc}") from exc
    return out


def percentile(values: list[float], p: float) -> float:
    """Nearest-rank percentile: sorted value at rank ceil(p/100 * n)."""
    if not values:
        raise ValueError("percentile of empty list")
    s = sorted(values)
    return s[max(1, math.ceil(p / 100 * len(s))) - 1]


def summarize(recs: list[dict]) -> dict[tuple[str, str], dict]:
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in recs:
        groups[(r["route"], r["tool"])].append(r)
    res = {}
    for key, rs in groups.items():
        lat = [r["latency_ms"] for r in rs]
        cost = sum((r["cost_usd"] for r in rs), Decimal(0))
        res[key] = {"n": len(rs), "p50": percentile(lat, 50), "p95": percentile(lat, 95),
                    "p99": percentile(lat, 99), "tokens_in": sum(r["token_in"] for r in rs),
                    "tokens_out": sum(r["token_out"] for r in rs), "cost": cost,
                    "cost_per_req": cost / len(rs)}
    return res


def _usd(d: Decimal) -> str:
    return f"{d:.6f}"


def report(recs: list[dict]) -> str:
    rows = summarize(recs)
    head = ("route/tool", "n", "p50_ms", "p95_ms", "p99_ms", "tok_in", "tok_out", "cost_usd", "usd/req")
    table = [head]
    for (route, tool), s in sorted(rows.items()):
        table.append((f"{route}/{tool}", str(s["n"]), f"{s['p50']:g}", f"{s['p95']:g}", f"{s['p99']:g}",
                      str(s["tokens_in"]), str(s["tokens_out"]), _usd(s["cost"]), _usd(s["cost_per_req"])))
    total = sum((r["cost_usd"] for r in recs), Decimal(0))
    lat = [r["latency_ms"] for r in recs]
    table.append(("ALL", str(len(recs)), f"{percentile(lat, 50):g}", f"{percentile(lat, 95):g}",
                  f"{percentile(lat, 99):g}", str(sum(r["token_in"] for r in recs)),
                  str(sum(r["token_out"] for r in recs)), _usd(total), _usd(total / len(recs))))
    w = [max(len(r[i]) for r in table) for i in range(len(head))]
    lines = [f"{r[0]:<{w[0]}}  " + "  ".join(f"{c:>{w[i]}}" for i, c in enumerate(r) if i) for r in table]
    return "\n".join(lines)


def generate(seed: int = 7, n: int = 200) -> list[dict]:
    rng = random.Random(seed)
    recs = []
    for _ in range(n):
        route = rng.choice(sorted(ROUTES))
        tool = rng.choice(ROUTES[route])
        model = MODELS[rng.random() < 0.25]
        big = model == "model-large"
        recs.append({"route": route, "tool": tool, "model": model,
                     "token_in": 200 + int(rng.random() * (1800 if big else 600)),
                     "token_out": 20 + int(rng.random() * (500 if big else 150)),
                     "latency_ms": (300 if big else 80) + int(rng.random() ** 3 * (4000 if big else 900))})
    return recs


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Token, latency and cost metrics over synthetic traffic.")
    ap.add_argument("--traffic", default=str(HERE / "data" / "traffic.jsonl"))
    ap.add_argument("--pricing", default=str(HERE / "data" / "pricing.json"))
    ap.add_argument("--generate", action="store_true", help="rewrite the traffic file (seed 7)")
    args = ap.parse_args(argv)
    if args.generate:
        Path(args.traffic).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in generate()))
        return 0
    try:
        pricing = load_pricing(args.pricing)
        recs = load_records(args.traffic, pricing)
    except RecordError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, ArithmeticError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not recs:
        print("error: no records in traffic file", file=sys.stderr)
        return 2
    print(report(recs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
