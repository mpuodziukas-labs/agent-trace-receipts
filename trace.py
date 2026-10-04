"""trace.py - tiny recorder that writes a tamper-evident JSONL trace of an agent run.

Each line is one step: run_id, step, parent, tool, input, input_sha256, output,
output_sha256, rc, start_ms, end_ms, prev_hash. prev_hash is HMAC-SHA256 of the
previous raw line, keyed with the TRACE_KEY environment variable (the first line
chains to GENESIS). Without the key nobody can recompute a valid chain. A
sidecar "<trace>.head" file anchors the step count and last line MAC, signed
with its own domain-separated HMAC ("head" tag), so tail truncation is
detectable and an outsider cannot forge a head from a chain value. The head is
written atomically (temp file, fsync, rename) after the line is fsynced.

Usage:
    export TRACE_KEY=<at least 16 characters, kept secret>
    rec = Recorder("run.jsonl", "run-1")
    with rec.step("load_po", {"po_id": "PO-1"}) as s:
        s.output = {"found": True}
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

GENESIS = "0" * 64
MIN_KEY_LEN = 16
MIN_DISTINCT_BYTES = 8


class KeyConfigError(Exception):
    """TRACE_KEY is missing or too short."""


def get_key(env: Optional[dict] = None) -> bytes:
    raw = (os.environ if env is None else env).get("TRACE_KEY", "")
    if not raw:
        raise KeyConfigError("TRACE_KEY is not set; export TRACE_KEY with a secret of at least "
                             f"{MIN_KEY_LEN} characters")
    if len(raw.encode("utf-8")) < MIN_KEY_LEN:
        raise KeyConfigError(f"TRACE_KEY is too short; use at least {MIN_KEY_LEN} characters")
    if not raw.strip() or len(set(raw.encode("utf-8"))) < MIN_DISTINCT_BYTES:
        raise KeyConfigError("TRACE_KEY is too weak; use at least "
                             f"{MIN_DISTINCT_BYTES} distinct bytes and not only whitespace")
    return raw.encode("utf-8")


def chain_hash(key: bytes, line: str) -> str:
    """HMAC-SHA256(key, raw line), hex. This is the prev_hash of the next line."""
    return hmac.new(key, line.encode("utf-8"), hashlib.sha256).hexdigest()


def head_mac(key: bytes, run_id: str, steps: int, last_line: str) -> str:
    """Domain-separated MAC of the head anchor. Never equal to any line's prev_hash."""
    msg = "head\0" + run_id + "\0" + str(steps) + "\0" + last_line
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()


def write_head(path: Path, key: bytes, run_id: str, steps: int, last_hash: str, last_line: str) -> None:
    """Atomic head write: temp file, fsync, rename. A crash leaves the old head intact."""
    hp = head_path(path)
    tmp = hp.with_name(hp.name + ".tmp")
    body = canonical({"run_id": run_id, "steps": steps, "last_hash": last_hash,
                      "mac": head_mac(key, run_id, steps, last_line)}) + "\n"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(body)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, hp)


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
    def __init__(self, path: str | Path, run_id: str, key: Optional[bytes] = None,
                 force: bool = False) -> None:
        self.key = key if key is not None else get_key()
        self.path = Path(path)
        self.run_id = run_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # exclusive create: never destroy an earlier trace unless the caller says --force
        with self.path.open("w" if force else "x", encoding="utf-8"):
            pass
        self._n = 0
        self._prev = GENESIS
        self._last_line = ""
        write_head(self.path, self.key, self.run_id, 0, GENESIS, "")

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
            f.flush()
            os.fsync(f.fileno())  # the line is durable before the head moves
        self._prev = chain_hash(self.key, line)
        self._n += 1
        self._last_line = line
        write_head(self.path, self.key, self.run_id, self._n, self._prev, line)
