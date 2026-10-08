"""Tests for Change 49, part 2: a ceiling on every request to the Spark (user 2026-10-08).

All three Spark halts came during a web-digest call with a long prompt (28,099 and 31,324 tokens, and a larger one).
Before anything is sent, the request (system message + prompt + a 64-token allowance for the chat template) is
counted; over 30,000 tokens it is not sent - `PromptTooLarge`, recorded as a refused call, never retried. 30,000 sits
above every call the other stages have made (largest 29,347), so it changes nothing that has run. A refusal is a
finding about the pipeline, not an outage: the harness's stop rule does not count it. Offline: a stand-in OpenAI
client and a stand-in counter (one token per character).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from backend import llm_client
from backend.llm_client import PROMPT_TOKEN_CEILING, OllamaLLMClient, PromptTooLarge
from backend.pipeline.base_stage import PipelineStage
from backend.telemetry import TELEMETRY
from eval.run_eval import unmeasured_reason

JSON_SYSTEM = ("You must respond with valid JSON only. Do not include any text, explanation, or markdown outside the "
               "JSON object.")


class _Completions:
    def __init__(self):
        self.sent = 0

    def create(self, **kwargs):
        self.sent += 1
        choice = SimpleNamespace(message=SimpleNamespace(content="{}"), finish_reason="stop")
        return SimpleNamespace(choices=[choice], usage=None)


def _client():
    client = OllamaLLMClient.__new__(OllamaLLMClient)
    client.model_name = "fake"
    client._completions = _Completions()
    client._openai = SimpleNamespace(chat=SimpleNamespace(completions=client._completions))
    return client


@pytest.fixture
def one_token_per_char(monkeypatch):
    monkeypatch.setattr(llm_client, "count_tokens", len)


def test_the_ceiling_is_above_every_call_made_so_far_and_below_the_halted_digests():
    assert PROMPT_TOKEN_CEILING == 30_000
    assert 29_347 < PROMPT_TOKEN_CEILING < 31_324


def test_a_request_over_the_ceiling_is_not_sent_and_is_recorded_as_refused(one_token_per_char):
    TELEMETRY.reset()
    client = _client()
    room = PROMPT_TOKEN_CEILING - len(JSON_SYSTEM) - llm_client.TEMPLATE_ALLOWANCE_TOKENS
    with pytest.raises(PromptTooLarge):
        client.generate("x" * (room + 1))
    assert client._completions.sent == 0
    (call,) = TELEMETRY.as_dicts()
    assert call["refused"] is True and call["ok"] is False and "not sent" in call["error"]


def test_a_request_at_the_ceiling_is_sent(one_token_per_char):
    TELEMETRY.reset()
    client = _client()
    room = PROMPT_TOKEN_CEILING - len(JSON_SYSTEM) - llm_client.TEMPLATE_ALLOWANCE_TOKENS
    assert client.generate("x" * room) == "{}"
    assert client._completions.sent == 1 and TELEMETRY.as_dicts()[0]["refused"] is False


def test_without_json_mode_only_the_prompt_and_the_allowance_count(one_token_per_char):
    client = _client()
    room = PROMPT_TOKEN_CEILING - llm_client.TEMPLATE_ALLOWANCE_TOKENS
    client.generate("x" * room, json_mode=False)
    with pytest.raises(PromptTooLarge):
        client.generate("x" * (room + 1), json_mode=False)
    assert client._completions.sent == 1


def test_a_stage_does_not_retry_a_refused_request():
    class _Refusing:
        calls = 0

        def generate(self, **kwargs):
            _Refusing.calls += 1
            raise PromptTooLarge("prompt of 34291 tokens is over the 30000-token ceiling; not sent")

    class _Stage(PipelineStage):
        name = "analysis"

        def run(self, context):
            return context

    stage = _Stage.__new__(_Stage)
    stage.client = _Refusing()
    with pytest.raises(PromptTooLarge):
        stage.llm_call("p", economy=True)
    assert _Refusing.calls == 1          # "34291" contains "429", which the retry rule reads as a rate limit


def test_the_harness_does_not_stop_on_a_refused_call():
    refused = {"ok": False, "refused": True, "stage": "generation", "error": "not sent"}
    failed = {"ok": False, "stage": "analysis", "error": "APIConnectionError: Connection error."}
    assert unmeasured_reason({"llm_calls": [{"ok": True}, refused]}) is None
    assert "1 of 3 LLM calls failed" in unmeasured_reason({"llm_calls": [{"ok": True}, refused, failed]})
