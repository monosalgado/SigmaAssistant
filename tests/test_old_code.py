"""Tests for running an older version of the pipeline (the May code, 2ec05f6) through today's
harness (user, 2026-09-28: "rerun the may code on the same saved pages, several times each").

The old code cannot be imported next to today's `backend` package, so it runs in a worker
process (`eval/old_code_worker.py`) and the harness talks to it one case at a time
(`eval/old_code.py`). Everything the harness does around the pipeline stays today's code: the
saved pages, the row, the scorer, resuming, and stopping at a failed call.

Offline: a stand-in transport replaces the worker process; no LLM, no network.
"""

from __future__ import annotations

import io
import json

from backend.telemetry import TELEMETRY, stage_scope
from eval import old_code_worker
from eval.old_code import OldCodeAgent, replay_calls
from eval.run_eval import _PocSnapshotRequests, _SnapshotRequests, run_case

RULE = """title: Sudo negative user id
id: 11111111-2222-3333-4444-555555555555
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: '-u#-1'
    condition: selection
"""

GOLD = {"title": "Gold", "logsource": {"category": "process_creation", "product": "linux"},
        "detection": {"selection": {"CommandLine|contains": "-u#-1"}, "condition": "selection"}}


def _call(stage="generation", ok=True):
    return {"backend": "ollama", "tier": "economy", "model": "qwen3-coder:30b", "operation": "generate",
            "latency_s": 2.0, "prompt_chars": 100, "response_chars": 50, "prompt_tokens": 30,
            "completion_tokens": 20, "thinking_tokens": None, "total_tokens": 50, "ok": ok,
            "error": None if ok else "APITimeoutError: Request timed out", "stage": stage,
            "output_limited": False}


class _Transport:
    """Stands in for the worker process: records requests, returns canned replies."""

    def __init__(self, replies):
        self.replies, self.requests = list(replies), []

    def ask(self, request):
        self.requests.append(request)
        return self.replies.pop(0)


def _reply(**over):
    reply = {"ok": True, "result": {"rule": "```yaml\n" + RULE + "```", "pipeline_metadata": {
        "attack_vector": {"primary_telemetry": "process_creation"}}},
        "calls": [_call("attack_vector"), _call("generation")],
        "served": 1, "missed": 0, "poc_served": 0, "poc_missed": 0}
    reply.update(over)
    return reply


def _case():
    return {"rule_id": "r-1", "rule_path": "x.yml", "title": "t", "category": "process_creation",
            "product": "linux", "urls": ["https://example.com/a"],
            "url_to_path": {"https://example.com/a": "/snap/a.html"}, "text_chars": 5000, "gold": GOLD}


# --- the harness side -------------------------------------------------------------------

def test_the_workers_calls_are_recorded_with_their_stage():
    TELEMETRY.reset()
    replay_calls([_call("analysis"), _call("generation", ok=False)])
    calls = TELEMETRY.as_dicts()
    assert [c["stage"] for c in calls] == ["analysis", "generation"]
    assert calls[1]["ok"] is False and calls[1]["total_tokens"] == 50


def test_a_case_runs_through_todays_harness_and_is_scored_by_todays_scorer():
    transport = _Transport([_reply()])
    agent = OldCodeAgent(transport=transport, model_name="qwen3-coder:30b")
    row = run_case(agent, _case(), {"arm": "may"}, no_web_enrich=True,
                   poc_url_map={"https://raw.example/x.py": {"path": None, "status": 404}})
    request = transport.requests[0]
    assert request["description"] == "https://example.com/a"
    assert request["url_to_path"] == {"https://example.com/a": "/snap/a.html"}      # the saved pages
    assert request["poc_url_map"] == {"https://raw.example/x.py": {"path": None, "status": 404}}
    assert row["error"] is None and row["n_rules"] == 1
    assert row["scores"]["logsource"]["exact_match"] is True
    assert row["pipeline"]["attack_vector"]["primary_telemetry"] == "process_creation"
    assert row["snapshots_served"] == 1 and row["snapshots_missed"] == 0
    assert [c["stage"] for c in row["llm_calls"]] == ["attack_vector", "generation"]


def test_a_failed_call_in_the_old_code_stops_the_run_like_any_other():
    from eval.run_eval import unmeasured_reason
    agent = OldCodeAgent(transport=_Transport([_reply(calls=[_call("analysis", ok=False)])]),
                         model_name="m")
    row = run_case(agent, _case(), {"arm": "may"}, no_web_enrich=True)
    assert "1 of 1 LLM calls failed" in unmeasured_reason(row)


def test_a_crash_in_the_old_code_is_an_error_row_with_its_traceback():
    agent = OldCodeAgent(transport=_Transport([_reply(ok=False, result=None, error="KeyError: 'rules'",
                                                      traceback="Traceback ... KeyError")]), model_name="m")
    row = run_case(agent, _case(), {"arm": "may"}, no_web_enrich=True)
    assert row["error"] == "OldCodeError: KeyError: 'rules'"
    assert "KeyError" in row["traceback"]
    assert row["scores"] is None


def test_a_worker_that_died_counts_as_a_failed_call_so_the_case_is_not_written():
    from eval.run_eval import unmeasured_reason
    agent = OldCodeAgent(transport=_Transport([None]), model_name="m")
    row = run_case(agent, _case(), {"arm": "may"}, no_web_enrich=True)
    assert "worker" in unmeasured_reason(row)


# --- the worker side --------------------------------------------------------------------

def test_the_workers_page_snapshots_behave_like_the_harness_own():
    pages = {"https://example.com/a": __file__}
    ours, theirs = old_code_worker.SnapshotRequests(pages), _SnapshotRequests(pages)
    for url in ("https://example.com/a#frag", "https://example.com/missing"):
        a, b = ours.get(url, timeout=10), theirs.get(url, timeout=10)
        assert (a.status_code, a.content) == (b.status_code, b.content)
    assert (ours.served, ours.missed) == (theirs.served, theirs.missed) == (1, 1)
    poc = {"https://raw.example/x.py": {"path": __file__, "status": 200},
           "https://raw.example/gone.py": {"path": None, "status": 404}}
    ours, theirs = old_code_worker.PocSnapshotRequests(poc), _PocSnapshotRequests(poc)
    for url in poc.keys() | {"https://raw.example/other.py"}:
        a, b = ours.get(url), theirs.get(url)
        assert (a.status_code, a.text) == (b.status_code, b.text)
    assert (ours.served, ours.missed) == (theirs.served, theirs.missed) == (2, 1)


class _Module:
    requests = "the real requests module"


class _OldOrchestrator:
    """Stands in for the May orchestrator: its stage modules fetch through `requests`."""

    def __init__(self, preprocess, poc, fail=None):
        self.preprocess, self.poc, self.fail = preprocess, poc, fail

    def run_sync(self, description):
        page = self.preprocess.requests.get("https://example.com/a")
        self.poc.requests.get("https://raw.example/x.py")
        with stage_scope("generation"):
            TELEMETRY.record(backend="ollama", tier="economy", model="m", operation="generate",
                             latency_s=1.0, prompt_chars=len(page.content))
        if self.fail:
            raise self.fail
        return {"rule": "rules for " + description, "pipeline_metadata": {"x": 1},
                "context": {"sigma": ["large"]}}


def test_the_worker_serves_the_saved_pages_and_returns_the_result_and_its_calls():
    pre, poc = _Module(), _Module()
    request = {"description": "https://example.com/a", "url_to_path": {"https://example.com/a": __file__},
               "poc_url_map": {}}
    reply = old_code_worker.handle(request, _OldOrchestrator(pre, poc), pre, poc)
    assert reply["ok"] is True
    assert reply["result"] == {"rule": "rules for https://example.com/a", "pipeline_metadata": {"x": 1}}
    assert (reply["served"], reply["missed"], reply["poc_served"], reply["poc_missed"]) == (1, 0, 0, 1)
    assert [c["stage"] for c in reply["calls"]] == ["generation"]
    assert pre.requests == poc.requests == "the real requests module"      # restored afterwards


def test_the_worker_reports_a_crash_with_the_calls_made_before_it():
    pre, poc = _Module(), _Module()
    reply = old_code_worker.handle({"description": "d", "url_to_path": {}, "poc_url_map": {}},
                                   _OldOrchestrator(pre, poc, fail=KeyError("rules")), pre, poc)
    assert reply["ok"] is False and reply["error"] == "KeyError: 'rules'"
    assert "KeyError" in reply["traceback"] and len(reply["calls"]) == 1


def test_the_worker_answers_one_json_line_per_request():
    requests = io.StringIO(json.dumps({"n": 1}) + "\n" + json.dumps({"n": 2}) + "\n")
    replies = io.StringIO()
    old_code_worker.serve(requests, replies, lambda request: {"echo": request["n"]})
    assert [json.loads(l) for l in replies.getvalue().splitlines()] == [{"echo": 1}, {"echo": 2}]


# --- the harness option -----------------------------------------------------------------

def test_every_row_records_which_code_ran():
    from argparse import Namespace
    from eval.run_eval import run_config
    args = Namespace(arm="may_heldout_r1", no_web_enrich=True, min_chars=2000, code="../SigmaAssistant-may")
    agent = OldCodeAgent(transport=_Transport([]), model_name="qwen3-coder:30b")
    agent.code_revision = "2ec05f6"
    config = run_config(agent, args)
    assert config["code"] == "2ec05f6" and config["code_path"] == "../SigmaAssistant-may"
    assert config["arm"] == "may_heldout_r1" and config["web_enrich"] is False
    assert config["primary_model"] == "qwen3-coder:30b"


def test_todays_code_records_its_own_commit():
    from argparse import Namespace
    from eval.run_eval import run_config
    args = Namespace(arm="main_heldout_r1", no_web_enrich=True, min_chars=2000, code=None)
    agent = type("A", (), {"client": type("C", (), {"model_name": "qwen3-coder:30b"})()})()
    config = run_config(agent, args, head_revision=lambda: "abc1234")
    assert config["code"] == "abc1234" and config["code_path"] is None
