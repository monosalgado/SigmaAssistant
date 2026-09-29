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
