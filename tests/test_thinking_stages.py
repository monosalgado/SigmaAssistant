"""Tests for thinking per step (qwen3.6 probe, part 2; user 2026-10-16: thinking on for the attack vector, the
analysis and rule writing).

`OLLAMA_THINK_STAGES` unset: nothing is sent, so qwen3-coder runs stay byte-identical. Set: a listed stage's request
goes as is (the model thinks by default), any other carries `reasoning_effort: "none"` (part 1: the field that turns
thinking off on this endpoint). Each call records whether thinking was allowed and the thinking's size; each run
records the stages. Offline: a stand-in OpenAI client.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from backend import llm_client
from backend.llm_client import OllamaLLMClient
from backend.telemetry import TELEMETRY, stage_scope


class _Completions:
    def __init__(self, reasoning=None):
        self.kwargs, self.reasoning = [], reasoning

    def create(self, **kwargs):
        self.kwargs.append(kwargs)
        message = SimpleNamespace(content='{"ok": true}', reasoning=self.reasoning)
        return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="stop")], usage=None)


def _client(reasoning=None):
    client = OllamaLLMClient.__new__(OllamaLLMClient)
    client.model_name = "fake"
    client._completions = _Completions(reasoning)
    client._openai = SimpleNamespace(chat=SimpleNamespace(completions=client._completions))
    return client


def _sent(client, stage):
    with stage_scope(stage):
        client.generate("p")
    return client._completions.kwargs[-1]


def test_unset_nothing_is_sent(monkeypatch):
    monkeypatch.delenv("OLLAMA_THINK_STAGES", raising=False)
    kwargs = _sent(_client(), "analysis")
    assert "extra_body" not in kwargs and "reasoning_effort" not in kwargs


def test_listed_steps_think_and_the_others_do_not(monkeypatch):
    monkeypatch.setenv("OLLAMA_THINK_STAGES", "attack_vector, analysis,generation")
    client = _client()
    for stage in ("attack_vector", "analysis", "generation"):
        assert "extra_body" not in _sent(client, stage)
    for stage in ("poc_analysis", "web_enrichment", "review"):
        assert _sent(client, stage)["extra_body"] == {"reasoning_effort": "none"}


def test_set_but_empty_turns_thinking_off_everywhere(monkeypatch):
    monkeypatch.setenv("OLLAMA_THINK_STAGES", "")
    assert _sent(_client(), "analysis")["extra_body"] == {"reasoning_effort": "none"}


def test_a_call_records_whether_it_could_think_and_how_much_it_did(monkeypatch):
    monkeypatch.setenv("OLLAMA_THINK_STAGES", "analysis")
    monkeypatch.setattr(llm_client, "count_tokens", lambda text: len(text.split()))
    TELEMETRY.reset()
    _sent(_client(reasoning="first check the evidence then decide"), "analysis")
    _sent(_client(), "review")
    first, second = TELEMETRY.as_dicts()
    assert first["thinking_allowed"] is True and first["thinking_tokens"] == 6
    assert second["thinking_allowed"] is False and not second["thinking_tokens"]


def test_without_the_setting_calls_record_nothing_about_thinking(monkeypatch):
    monkeypatch.delenv("OLLAMA_THINK_STAGES", raising=False)
    TELEMETRY.reset()
    _sent(_client(), "analysis")
    assert TELEMETRY.as_dicts()[0]["thinking_allowed"] is None


def test_the_run_records_the_thinking_steps(monkeypatch):
    from eval.run_eval import run_config
    agent = SimpleNamespace(client=SimpleNamespace(model_name="qwen3.6:latest"), code_revision=None)
    args = SimpleNamespace(arm="x", no_web_enrich=True, web_snapshots=None, min_chars=2000, code=None)
    monkeypatch.setenv("OLLAMA_THINK_STAGES", "analysis,attack_vector")
    assert run_config(agent, args, head_revision=lambda: "abc")["thinking_stages"] == ["analysis", "attack_vector"]
    monkeypatch.delenv("OLLAMA_THINK_STAGES")
    assert run_config(agent, args, head_revision=lambda: "abc")["thinking_stages"] is None
