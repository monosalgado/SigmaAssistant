"""The harness side of running an older version of the pipeline (`run_eval.py --code <checkout>`).

`OldCodeAgent` looks to `run_eval.run_case` like today's agent: `.client` and
`.orchestrator.run_sync(description)`. Each case is sent to the old code in a worker process
(`eval/old_code_worker.py`, which says what in it is today's and why) together with the case's
saved pages, taken from the shims `run_case` has installed. The worker's LLM calls are recorded
here as if made here, so the row, the scorer, resuming and stopping at a failed call are the
harness's own. A worker that dies counts as a failed call: the case is not written and the run
stops, to be resumed like any other infrastructure failure.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from backend.telemetry import TELEMETRY, stage_scope

HARNESS = Path(__file__).resolve().parent.parent
_USAGE = ("prompt_tokens", "completion_tokens", "thinking_tokens", "total_tokens")


class OldCodeError(Exception):
    """The old pipeline raised; the message is its exception."""


def replay_calls(calls: list) -> None:
    """Record the worker's LLM calls in this process, each under its stage."""
    for c in calls:
        with stage_scope(c.get("stage")):
            TELEMETRY.record(backend=c["backend"], tier=c["tier"], model=c["model"],
                             operation=c["operation"], latency_s=c["latency_s"],
                             prompt_chars=c["prompt_chars"], response_chars=c.get("response_chars", 0),
                             usage={k: c.get(k) for k in _USAGE}, ok=c.get("ok", True),
                             error=c.get("error"), output_limited=c.get("output_limited", False))


class WorkerTransport:
    """The worker process: one JSON line out per case, one back. `ask` returns None if the
    worker has died."""

    def __init__(self, code_path: str, no_web_enrich: bool):
        cmd = [sys.executable, str(HARNESS / "eval" / "old_code_worker.py"), "--code", str(code_path)]
        if no_web_enrich:
            cmd.append("--no-web-enrich")
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        self._proc = subprocess.Popen(cmd, cwd=HARNESS, env=env, stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, text=True)
        self.hello = self._read()
        if not self.hello or not self.hello.get("ready"):
            raise RuntimeError("the old-code worker did not start (see its output above)")

    def _read(self):
        line = self._proc.stdout.readline()
        return json.loads(line) if line.strip() else None

    def ask(self, request: dict):
        try:
            self._proc.stdin.write(json.dumps(request) + "\n")
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError):
            return None
        return self._read()


class _Client:
    """What `run_case` touches on the client; the real one lives in the worker."""

    def __init__(self, backend: str, model_name: str):
        self.backend, self.model_name = backend, model_name
        self.fast_model_name, self.economy_model_name = model_name, ""

    def web_search(self, query):
        return {"text": "", "sources": []}


class _Orchestrator:
    def __init__(self, transport, model_name: str):
        self._transport, self._model = transport, model_name

    def run_sync(self, description: str, history=None, media_file=None) -> dict:
        import backend.pipeline.stage_poc_analysis as poc_module
        import backend.pipeline.stage_preprocess as preprocess_module

        pages, pocs = preprocess_module.requests, poc_module.requests   # run_case's shims
        reply = self._transport.ask({"description": description,
                                     "url_to_path": getattr(pages, "_map", {}),
                                     "poc_url_map": getattr(pocs, "_map", {})})
        if reply is None:
            with stage_scope("old_code_worker"):
                TELEMETRY.record(backend="old_code_worker", tier="-", model=self._model,
                                 operation="generate", latency_s=0.0, prompt_chars=0, ok=False,
                                 error="the old-code worker exited without answering")
            raise OldCodeError("the old-code worker exited")
        replay_calls(reply.get("calls") or [])
        for shim, served, missed in ((pages, "served", "missed"), (pocs, "poc_served", "poc_missed")):
            if hasattr(shim, "served"):
                shim.served += reply.get(served, 0)
                shim.missed += reply.get(missed, 0)
        if not reply.get("ok"):
            raise OldCodeError(reply.get("error"))
        return reply["result"]


class OldCodeAgent:
    def __init__(self, code_path: str = None, no_web_enrich: bool = True, transport=None,
                 model_name: str = None):
        self.transport = transport or WorkerTransport(code_path, no_web_enrich)
        hello = getattr(self.transport, "hello", None) or {}
        model = model_name or hello.get("model", "")
        self.code_revision = hello.get("code", "")
        self.client = _Client(hello.get("backend", "OldCode"), model)
        self.orchestrator = _Orchestrator(self.transport, model)
