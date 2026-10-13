"""Multi-agent handoff and escalation tests: genuine run verifies, each planted tamper is refused by name."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

import multiagent as ma
import trace as tr

ROOT = Path(__file__).resolve().parent.parent
KEY = b"unit-test-key-0123456789"


def run(tmp_path):
    p = tmp_path / "ma.jsonl"
    ma.run_scenario(p, KEY)
    return p


def test_genuine_run_verifies(tmp_path):
    r = ma.verify_multiagent(run(tmp_path), KEY)
    assert r.ok, r.errors


def test_scenario_has_handoffs_escalations_and_approval(tmp_path):
    tools = [json.loads(x)["tool"] for x in run(tmp_path).read_text().splitlines()]
    assert tools.count("handoff") == tools.count("receive") >= 2
    assert tools.count("escalate") >= 2 and tools.count("human_approval") >= 1


def test_existing_record_shape_unchanged(tmp_path):
    for line in run(tmp_path).read_text().splitlines():
        assert set(json.loads(line)) == {"run_id", "step", "parent", "tool", "input", "input_sha256",
                                         "output", "output_sha256", "rc", "start_ms", "end_ms", "prev_hash"}


def test_escalation_rule():
    assert ma.should_escalate(0.79, 10) == "low_confidence"
    assert ma.should_escalate(0.95, 501) == "policy:refund_over_limit"
    assert ma.should_escalate(0.95, 10) is None


@pytest.mark.parametrize("name,reason", [(n, r) for n, (_, r) in ma.TAMPERS.items()])
def test_each_tamper_refused_with_named_reason(tmp_path, name, reason):
    p = run(tmp_path)
    out = tmp_path / "bad.jsonl"
    ma.plant(name, p, out, KEY)
    r = ma.verify_multiagent(out, KEY)
    assert not r.ok
    assert any(reason in e for e in r.errors), r.errors


def test_unsigned_drop_breaks_chain(tmp_path):
    p = run(tmp_path)
    lines = p.read_text().splitlines()
    i = next(k for k, x in enumerate(lines) if json.loads(x)["tool"] == "handoff")
    del lines[i]
    p.write_text("\n".join(lines) + "\n")
    r = ma.verify_multiagent(p, KEY)
    assert not r.ok and any("hash chain broken" in e for e in r.errors)


def test_wrong_key_refused(tmp_path):
    r = ma.verify_multiagent(run(tmp_path), b"another-key-0123456789")
    assert not r.ok


def test_cli_prints_scenario_and_counts():
    p = subprocess.run([sys.executable, str(ROOT / "multiagent.py")], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stdout + p.stderr
    assert re.search(r"verification: \d+/\d+ checks passed", p.stdout)
    assert re.search(r"tamper suite: 3/3 refused with the expected reason", p.stdout)


def test_readme_block_matches_command_output():
    p = subprocess.run([sys.executable, str(ROOT / "multiagent.py")], capture_output=True, text=True, timeout=60)
    m = re.search(r"<!-- multiagent:start -->\n```\n(.*?)```\n<!-- multiagent:end -->",
                  (ROOT / "README.md").read_text(), re.S)
    assert m, "README multiagent block markers missing"
    assert m.group(1) == p.stdout
