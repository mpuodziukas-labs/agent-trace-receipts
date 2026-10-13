"""Metrics tests: percentile math against hand-computed fixtures, rejection of bad records, README parity."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import pytest

import metrics

ROOT = Path(__file__).resolve().parent.parent
PRICING = metrics.load_pricing(ROOT / "data" / "pricing.json")


def rec(**kw):
    base = {"route": "r", "tool": "t", "model": "model-small", "token_in": 1000, "token_out": 2000,
            "latency_ms": 10}
    return {**base, **kw}


def run_cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "metrics.py"), *args], capture_output=True,
                          text=True, cwd=ROOT, timeout=60)


def write(tmp_path, records):
    p = tmp_path / "t.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in records))
    return p


def test_percentile_hand_computed_ten_values():
    # nearest rank: n=10, p50 -> rank 5, p95 -> rank ceil(9.5)=10, p99 -> rank ceil(9.9)=10
    v = [100, 10, 90, 20, 80, 30, 70, 40, 60, 50]
    assert (metrics.percentile(v, 50), metrics.percentile(v, 95), metrics.percentile(v, 99)) == (50, 100, 100)


def test_percentile_hand_computed_five_values():
    # n=5: p50 -> rank ceil(2.5)=3, p95 -> rank ceil(4.75)=5, p20 -> rank 1
    v = [5, 1, 4, 2, 3]
    assert (metrics.percentile(v, 50), metrics.percentile(v, 95), metrics.percentile(v, 20)) == (3, 5, 1)


def test_percentile_single_and_empty():
    assert metrics.percentile([7], 99) == 7
    with pytest.raises(ValueError):
        metrics.percentile([], 50)


def test_cost_hand_computed():
    # 1000 in * 0.50/1M = 0.0005 ; 2000 out * 1.50/1M = 0.0030 ; total 0.0035
    assert metrics.validate(rec(), PRICING)["cost_usd"] == Decimal("0.0035")
    # model-large: 1000*3.00/1M = 0.003 ; 2000*15.00/1M = 0.03 ; total 0.033
    assert metrics.validate(rec(model="model-large"), PRICING)["cost_usd"] == Decimal("0.033")


def test_summary_hand_computed_fixture(tmp_path):
    recs = [rec(latency_ms=x) for x in (10, 20, 30, 40, 50, 60, 70, 80, 90, 100)]
    recs.append(rec(tool="u", latency_ms=5, token_in=0, token_out=0))
    p = write(tmp_path, recs)
    r = run_cli("--traffic", str(p))
    assert r.returncode == 0, r.stderr
    lines = {ln.split()[0]: ln.split() for ln in r.stdout.splitlines()}
    # group r/t: n=10 p50=50 p95=100 p99=100 tok_in=10000 tok_out=20000 cost=10*0.0035=0.035 per req 0.0035
    assert lines["r/t"][1:] == ["10", "50", "100", "100", "10000", "20000", "0.035000", "0.003500"]
    assert lines["r/u"][1:] == ["1", "5", "5", "5", "0", "0", "0.000000", "0.000000"]
    # ALL: n=11, sorted latencies 5,10..100 ; p50 rank ceil(5.5)=6 -> 50 ; p95 rank ceil(10.45)=11 -> 100
    assert lines["ALL"][1:] == ["11", "50", "100", "100", "10000", "20000", "0.035000", "0.003182"]


@pytest.mark.parametrize("bad", [
    rec(token_in=-1), rec(token_out=-5), rec(token_in=1.5), rec(token_in=True),
    rec(latency_ms=-1), rec(latency_ms=float("inf")), rec(latency_ms="fast"), rec(latency_ms=None),
    rec(model="model-unknown"), rec(route=""),
])
def test_bad_record_rejected_rc1(tmp_path, bad):
    p = write(tmp_path, [rec(), bad])
    r = run_cli("--traffic", str(p))
    assert r.returncode == 1 and "line 2" in r.stderr and r.stdout == ""


def test_missing_latency_field_rejected(tmp_path):
    bad = rec()
    del bad["latency_ms"]
    r = run_cli("--traffic", str(write(tmp_path, [bad])))
    assert r.returncode == 1 and "latency_ms" in r.stderr


def test_malformed_json_line_rejected(tmp_path):
    p = tmp_path / "t.jsonl"
    p.write_text("{not json}\n")
    assert run_cli("--traffic", str(p)).returncode == 1


def test_empty_traffic_is_error_not_success(tmp_path):
    p = tmp_path / "t.jsonl"
    p.write_text("")
    assert run_cli("--traffic", str(p)).returncode == 2


def test_missing_file_rc2(tmp_path):
    assert run_cli("--traffic", str(tmp_path / "nope.jsonl")).returncode == 2


def test_bundled_traffic_is_valid_and_seeded():
    recs = metrics.load_records(ROOT / "data" / "traffic.jsonl", PRICING)
    assert len(recs) == 200
    gen = [json.dumps(r, sort_keys=True) for r in metrics.generate()]
    assert gen == [json.dumps({k: v for k, v in r.items() if k != "cost_usd"}, sort_keys=True) for r in recs]


def test_pricing_table_is_labelled_illustrative():
    raw = json.loads((ROOT / "data" / "pricing.json").read_text())
    assert raw["label"] == "illustrative prices, not a vendor quote"


def test_readme_metrics_block_equals_command_output():
    readme = (ROOT / "README.md").read_text()
    m = re.search(r"<!-- metrics:start -->\n```\n(.*?)```\n<!-- metrics:end -->", readme, re.S)
    assert m, "README metrics block markers missing"
    r = run_cli()
    assert r.returncode == 0
    assert m.group(1) == r.stdout
    assert "python3 metrics.py" in readme
    lim = readme.split("## Limitations")[1].split("## Hostile review")[0]
    assert "illustrative prices" in lim and "synthetic traffic" in lim.lower()
