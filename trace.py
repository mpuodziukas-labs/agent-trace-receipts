"""trace.py - tiny recorder that writes a tamper-evident JSONL trace of an agent run.

Each line is one step: run_id, step, parent, tool, input, input_sha256, output,
output_sha256, rc, start_ms, end_ms, prev_hash. prev_hash is the SHA-256 of the
previous raw line (the first line chains to GENESIS). A sidecar "<trace>.head"
file anchors the last line hash and step count so tail truncation is detectable.

Usage:
    rec = Recorder("run.jsonl", "run-1")
    with rec.step("load_po", {"po_id": "PO-1"}) as s:
        s.output = {"found": True}
"""

from __future__ import annotations

import hashlib
import json
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

GENESIS = "0" * 64


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_json(obj: Any) -> str:
    return sha256_text(canonical(obj))


def error_output(exc: BaseException) -> dict[str, str]:
    return {"error": f"{type(exc).__name__}: {exc}"}


def now_ms() -> float:
    return round(time.time() * 1000, 3)


def head_path(trace: Path) -> Path:
    trace = Path(trace)
    return trace.with_name(trace.name + ".head")


class Step:
    def __init__(self, tool: str, input: Any, parent: Optional[int]) -> None:
        self.tool = tool
        self.input = input
        self.parent = parent
        self.output: Any = None
        self.rc = 0
        self.step = -1  # assigned when the line is written


class Recorder:
    def __init__(self, path: str | Path, run_id: str) -> None:
        self.path = Path(path)
        self.run_id = run_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")
        self._n = 0
        self._prev = GENESIS

    @contextmanager
    def step(self, tool: str, input: Any, parent: Optional[int] = None) -> Iterator[Step]:
        s = Step(tool, input, parent)
        start = now_ms()
        try:
            yield s
        except Exception as exc:
            s.rc = 1
            s.output = error_output(exc)
            raise
        finally:
            self._write(s, start, now_ms())

    def _write(self, s: Step, start: float, end: float) -> None:
        s.step = self._n
        rec = {
            "run_id": self.run_id,
            "step": s.step,
            "parent": s.parent,
            "tool": s.tool,
            "input": s.input,
            "input_sha256": sha256_json(s.input),
            "output": s.output,
            "output_sha256": sha256_json(s.output),
            "rc": s.rc,
            "start_ms": start,
            "end_ms": end,
            "prev_hash": self._prev,
        }
        line = canonical(rec)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        self._prev = sha256_text(line)
        self._n += 1
        head_path(self.path).write_text(
            canonical({"run_id": self.run_id, "steps": self._n, "last_hash": self._prev}) + "\n",
            encoding="utf-8",
        )
