"""Shared fixtures: every test runs with a trace key in the environment."""

from __future__ import annotations

import pytest

TEST_KEY = "unit-test-key-0123456789"


@pytest.fixture(autouse=True)
def trace_key_env(monkeypatch):
    monkeypatch.setenv("TRACE_KEY", TEST_KEY)
    return TEST_KEY.encode()
