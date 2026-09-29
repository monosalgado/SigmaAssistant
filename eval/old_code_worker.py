#!/usr/bin/env python3
"""Runs an older version of the pipeline (e.g. the May code, 2ec05f6) for today's harness.

Started by `eval/old_code.py`, never by hand. The old code's `backend` package cannot be
imported next to today's, so it runs here, in its own process, with the old checkout first on
`sys.path` and today's repository not on it at all. The harness sends one case per line on
stdin; the worker answers one JSON line per case on the original stdout (the old code's own
prints go to stderr, into the run log).

What is today's here, and why (the rest is the old code, unchanged):
- **The LLM client and the call recording** (`backend/llm_client.py`, `backend/telemetry.py`),
  loaded under the names the old code imports. Same model and server as today's runs, with
  Change 24's output limit, so a runaway answer ends as a scored failure instead of hanging the
  run, and every call is recorded so a failed call stops the run as in any other run.
- **The saved pages** — the same shims as `eval/run_eval.py`, so no live network.
- **Web search off**, as in every run since September (`--no-web-enrich`).
- **Routing:** the harness's input is bare URLs, which today's code sends straight to rule
  generation (Change 8). The old code asked the chat classifier first and sent about half of
  such inputs to chat (defect 8, measured); here they go to rule generation, as today.
Each call is attributed to the old stage that made it (the old code had no stage labels).

Usage (by eval/old_code.py): old_code_worker.py --code <checkout> [--no-web-enrich]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import traceback
from pathlib import Path
from urllib.parse import urldefrag

HARNESS = Path(__file__).resolve().parent.parent


# --- the saved pages (same behaviour as run_eval's shims; tested against them) -------------

class _Response:
    def __init__(self, content: bytes, status_code: int):
        self.content = content
        self.status_code = status_code

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.text)


class SnapshotRequests:
    """Stands in for `requests` in the old PreprocessStage: a saved page, or a 404."""

    def __init__(self, url_to_path: dict):
        self._map = url_to_path
        self.served = self.missed = 0

    def get(self, url, **kwargs):
        path = self._map.get(urldefrag(url)[0])
        if path is None:
            self.missed += 1
            return _Response(b"", 404)
        self.served += 1
        return _Response(Path(path).read_bytes(), 200)


class PocSnapshotRequests:
    """Stands in for `requests` in the old PoCAnalysisStage: replayed as snapshotted."""

    def __init__(self, url_map: dict):
        self._map = url_map
        self.served = self.missed = 0

    def get(self, url, **kwargs):
        entry = self._map.get(url)
        if entry is None:
            self.missed += 1
            return _Response(b"", 404)
        self.served += 1
        return _Response(Path(entry["path"]).read_bytes() if entry.get("path") else b"", entry["status"])


# --- one case -----------------------------------------------------------------------------

def handle(request: dict, orchestrator, preprocess_module, poc_module) -> dict:
    """Run one case on the saved pages; return the result and every LLM call it made."""
    from backend.telemetry import TELEMETRY

    TELEMETRY.reset()
    pages, pocs = SnapshotRequests(request["url_to_path"]), PocSnapshotRequests(request["poc_url_map"])
    original = preprocess_module.requests, poc_module.requests
    preprocess_module.requests, poc_module.requests = pages, pocs
    try:
        result = orchestrator.run_sync(description=request["description"])
        reply = {"ok": True, "result": {"rule": result.get("rule", ""),
                                        "pipeline_metadata": result.get("pipeline_metadata")}}
    except Exception as exc:
        reply = {"ok": False, "result": None, "error": f"{type(exc).__name__}: {exc}",
                 "traceback": traceback.format_exc()[-1500:]}
    finally:
        preprocess_module.requests, poc_module.requests = original
    reply.update(calls=TELEMETRY.as_dicts(), served=pages.served, missed=pages.missed,
                 poc_served=pocs.served, poc_missed=pocs.missed)
    return reply


def serve(requests_in, replies_out, handler) -> None:
    for line in requests_in:
        if line.strip():
            replies_out.write(json.dumps(handler(json.loads(line)), default=str) + "\n")
            replies_out.flush()


# --- start-up -----------------------------------------------------------------------------

def _load_as(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _start(code: Path, no_web_enrich: bool):
    """Import the old pipeline with today's client and call recording; return what `handle`
    needs and what the harness records about the run."""
    if str(HARNESS) in [str(Path(p).resolve()) for p in sys.path if p]:
        raise SystemExit("today's repository is on sys.path; the old code would mix with it")
    sys.path.insert(0, str(code))
    import backend  # the old checkout's package

    backend.telemetry = _load_as("backend.telemetry", HARNESS / "backend" / "telemetry.py")
    backend.llm_client = _load_as("backend.llm_client", HARNESS / "backend" / "llm_client.py")
    from backend.agent import SigmaAgent
    import backend.pipeline.orchestrator as orchestrator_module
    import backend.pipeline.stage_poc_analysis as poc_module
    import backend.pipeline.stage_preprocess as preprocess_module
    from backend.pipeline.base_stage import PipelineStage
    from backend.telemetry import stage_scope

    if not Path(orchestrator_module.__file__).resolve().is_relative_to(code.resolve()):
        raise SystemExit(f"the pipeline was imported from {orchestrator_module.__file__}, not {code}")
    agent = SigmaAgent()
    if no_web_enrich:
        agent.client.web_search = lambda query: {"text": "", "sources": []}
    orchestrator = agent.orchestrator
    orchestrator.classify_intent = lambda description, history=None: {
        "intent": "generate_rule", "reasoning": "bare URL input: rule generation, as today (Change 8)"}
    for stage in vars(orchestrator).values():
        if isinstance(stage, PipelineStage):
            call = stage.llm_call

            def labelled(*args, _call=call, _name=stage.name, **kwargs):
                with stage_scope(_name):
                    return _call(*args, **kwargs)
            stage.llm_call = labelled
    revision = subprocess.run(["git", "-C", str(code), "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True).stdout.strip()
    hello = {"ready": True, "code": revision, "backend": type(agent.client).__name__,
             "model": getattr(agent.client, "model_name", "")}
    return orchestrator, preprocess_module, poc_module, hello


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--code", required=True, type=Path)
    parser.add_argument("--no-web-enrich", action="store_true")
    args = parser.parse_args()
    replies = os.fdopen(os.dup(1), "w", buffering=1)
    sys.stdout = sys.stderr  # the old code's prints stay out of the replies
    orchestrator, preprocess_module, poc_module, hello = _start(args.code, args.no_web_enrich)
    replies.write(json.dumps(hello) + "\n")
    replies.flush()
    serve(sys.stdin, replies, lambda request: handle(request, orchestrator, preprocess_module, poc_module))


if __name__ == "__main__":
    main()
