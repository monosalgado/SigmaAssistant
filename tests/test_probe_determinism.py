"""Tests for the determinism probe (plan P-B, user 2026-09-29): is the model's answer at
temperature 0 the same for the same prompt, and what changes that - a fixed seed, or other
requests on the server at the same time?

Offline: stand-ins replace the model server and the pipeline; no LLM, no network.
The probe captures the exact prompt the attack-vector stage sends for a case, then sends that
same prompt again and again, one request at a time or several at once, with or without a seed.
"""

from __future__ import annotations

import json
import threading

import pytest

from backend.llm_client import OllamaLLMClient
from eval.probe_determinism import capture_prompt, request_kwargs, run_batch, summarise


class _FakeCompletions:
    def __init__(self):
        self.kwargs = None

    def create(self, **kwargs):
        self.kwargs = kwargs
        message = type("M", (), {"content": '{"primary_telemetry": "file_event"}'})()
        choice = type("C", (), {"message": message, "finish_reason": "stop"})()
        return type("R", (), {"choices": [choice], "usage": None})()


def test_the_probe_sends_exactly_what_the_pipeline_sends():
    client = OllamaLLMClient("http://localhost:11434", "qwen3-coder:30b")
    fake = _FakeCompletions()
    client._openai = type("O", (), {"chat": type("Ch", (), {"completions": fake})()})()
    client.generate("PROMPT", temperature=0.0, json_mode=True, economy=True)
    assert request_kwargs("PROMPT", "qwen3-coder:30b") == fake.kwargs


def test_a_seed_is_added_only_when_asked_for():
    assert "seed" not in request_kwargs("P", "m")
    assert request_kwargs("P", "m", seed=42)["seed"] == 42


class _Stage:
    name = "attack_vector"

    def __init__(self):
        self.calls = 0

    def llm_call(self, prompt, **kwargs):
        self.calls += 1
        raise AssertionError("the model must not be called while capturing")

    def run(self, context):
        prompt = "ATTACK VECTOR PROMPT for " + context["preprocessed"]["combined_text"]
        return self.llm_call(prompt, temperature=0.0, json_mode=True, economy=True)


def test_the_stages_prompt_is_captured_without_calling_the_model():
    stage = _Stage()
    prompt, kwargs = capture_prompt(stage, {"preprocessed": {"combined_text": "page text"}})
    assert prompt == "ATTACK VECTOR PROMPT for page text"
    assert kwargs == {"temperature": 0.0, "json_mode": True, "economy": True}
    assert stage.llm_call.__func__ is _Stage.llm_call      # restored afterwards


def test_a_batch_sends_its_requests_at_the_same_time():
    barrier = threading.Barrier(4, timeout=5)

    def send(i):
        barrier.wait()        # only passes if all four are in flight together
        return {"i": i}

    assert sorted(r["i"] for r in run_batch(send, 4)) == [0, 1, 2, 3]


def test_the_summary_counts_different_answers_per_case_and_condition():
    rows = [
        {"rule_id": "a", "condition": "one at a time", "output": "X", "primary_telemetry": "file_event"},
        {"rule_id": "a", "condition": "one at a time", "output": "X", "primary_telemetry": "file_event"},
        {"rule_id": "a", "condition": "four at once", "output": "X", "primary_telemetry": "file_event"},
        {"rule_id": "a", "condition": "four at once", "output": "Y", "primary_telemetry": "registry_event"},
        {"rule_id": "a", "condition": "four at once", "output": None, "error": "timeout"},
    ]
    out = summarise(rows)
    assert out[("a", "one at a time")] == {"answers": 2, "different_answers": 1, "different_telemetry": 1,
                                           "errors": 0}
    assert out[("a", "four at once")] == {"answers": 2, "different_answers": 2, "different_telemetry": 2,
                                          "errors": 1}


# --- in time order (added after the first probe: its conditions ran in a fixed order) -------

def _answer(rid, condition, i, output, seconds=6.0, at="2026-09-29T19:00:00"):
    return {"kind": "answer", "rule_id": rid, "condition": condition, "request": i, "output": output,
            "seconds": seconds, "at": at}


def test_whether_only_the_first_request_of_a_prompt_answered_differently():
    from eval.probe_determinism import order_effects
    rows = [_answer("a", "one at a time", 0, "COLD", at="t0"),
            _answer("a", "one at a time", 1, "WARM", at="t1"),
            _answer("a", "one at a time, seed", 0, "WARM", at="t2"),
            _answer("b", "one at a time", 0, "X", at="t0"), _answer("b", "one at a time", 1, "Y", at="t1"),
            _answer("b", "one at a time", 2, "X", at="t2")]
    out = order_effects(rows)
    # first_differs: the first request's answer was never given again
    assert out["a"] == {"requests": 3, "first_differs": True, "later_identical": True}
    assert out["b"] == {"requests": 3, "first_differs": False, "later_identical": False}


def test_requests_sent_at_once_that_were_served_one_after_another():
    from eval.probe_determinism import served_in_turn
    queued = [_answer("a", "at once", i, "W", seconds=s) for i, s in enumerate([12.1, 6.0, 24.0, 18.2])]
    together = [_answer("b", "at once", i, "W", seconds=s) for i, s in enumerate([7.0, 7.2, 6.9, 7.4])]
    assert served_in_turn(queued + together) == {("a", "at once"): True, ("b", "at once"): False}


# --- the follow-up (user 2026-09-29): is a first-time answer repeatable, and does what came
# --- before change it? Every request is sent one at a time, in a fixed, recorded order.

def test_the_follow_up_order():
    from eval.probe_determinism import follow_up_schedule
    labels = [s["prompt"] for s in follow_up_schedule(["a", "b", "c"], forward_rounds=2, reverse_rounds=1,
                                                      unrelated_rounds=1)]
    assert labels[:6] == ["a", "b", "c", "a", "b", "c"]                          # rotation
    assert labels[6:9] == ["c", "b", "a"]                                         # reversed
    assert labels[9:15] == ["unrelated", "a", "unrelated", "b", "unrelated", "c"]
    # asked twice in a row, after the question before it in the rotation, in the reversed
    # rotation, and after the unrelated question
    assert labels[15:24] == ["c", "a", "a", "b", "a", "a", "unrelated", "a", "a"]
    assert labels[24:33] == ["a", "b", "b", "c", "b", "b", "unrelated", "b", "b"]
    assert labels[33:] == ["b", "c", "c", "a", "c", "c", "unrelated", "c", "c"]


def test_each_answer_records_what_came_just_before_it():
    from eval.probe_determinism import annotate_order
    rows = [{"prompt": p, "output": "x"} for p in ["a", "b", "b", "unrelated", "a"]]
    annotate_order(rows, before_first="(start)")
    assert [(r["after"], r["fresh"]) for r in rows] == [
        ("(start)", True), ("a", True), ("b", False), ("b", True), ("unrelated", True)]


def test_the_follow_up_answers_per_question():
    from eval.probe_determinism import follow_up_analysis
    rows = [
        # fresh after c: the same twice; fresh after b: another answer -> depends on what came before
        {"prompt": "a", "after": "c", "fresh": True, "output": "A1", "primary_telemetry": "file_event"},
        {"prompt": "a", "after": "c", "fresh": True, "output": "A1", "primary_telemetry": "file_event"},
        {"prompt": "a", "after": "b", "fresh": True, "output": "A2", "primary_telemetry": "file_event"},
        # asked again right away, after different things before: the same answer each time
        {"prompt": "a", "after": "a", "fresh": False, "output": "W", "primary_telemetry": "file_event"},
        {"prompt": "a", "after": "a", "fresh": False, "output": "W", "primary_telemetry": "file_event"},
        {"prompt": "unrelated", "after": "a", "fresh": True, "output": "OK"},
    ]
    out = follow_up_analysis(rows)
    assert list(out) == ["a"]
    assert out["a"] == {"fresh": 3, "fresh_different": 2, "most_different_after_one_question": 1,
                        "second_asks": 2, "second_different": 1, "telemetry_labels": 1}


def test_the_second_asks_compared_with_the_first_probes_repeats_for_the_same_prompt():
    from eval.probe_determinism import same_as_first_probe
    earlier = [{"kind": "prompt", "rule_id": "a", "sha256": "S"}, {"kind": "prompt", "rule_id": "b", "sha256": "T"},
               _answer("a", "one at a time", 0, "COLD", at="t0"), _answer("a", "one at a time", 1, "Y", at="t1"),
               _answer("a", "one at a time", 2, "Y", at="t2"),
               _answer("b", "one at a time", 0, "Q", at="t0"), _answer("b", "one at a time", 1, "R", at="t1")]
    follow = [{"kind": "prompt", "rule_id": "a", "sha256": "S"}, {"kind": "prompt", "rule_id": "b", "sha256": "U"},
              {"kind": "follow_up", "prompt": "a", "fresh": False, "output": "Y"},
              {"kind": "follow_up", "prompt": "b", "fresh": False, "output": "R"}]
    # b's prompt changed (its PoC answer differed at capture), so it cannot be compared
    assert same_as_first_probe(follow, earlier) == {"a": True, "b": None}
