"""Shared test setup.

Run settings must not leak into the tests: the preflight runs `pytest tests` inside a run's environment, and on
2026-10-16 `OLLAMA_THINK_STAGES` (set for the qwen3.6 run) made a test that assumes it unset fail. Every test starts
with it unset; the thinking tests set it themselves.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_run_settings(monkeypatch):
    monkeypatch.delenv("OLLAMA_THINK_STAGES", raising=False)
