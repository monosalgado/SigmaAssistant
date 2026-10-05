"""Tests for #7's measurement step (user 2026-10-05: "continue with #7"): an answer cut at the output limit keeps its
last 2,000 characters in its call record (`cut_tail`), so a run shows what the model was writing when it ran out.

Why: 0-2 of 60 cases per run lose their whole analysis (every attempt cut at 16,384 tokens), the same cases again and
again; they are long, often indicator-heavy reports (REvil/Kaseya ~720 domain-like strings, Emotet ~220 hashes), and
the indicators are 56% of a saved analysis - but answers are not saved, so what fills a cut answer is a guess.
Measurement only: no answer, retry or rule changes. Offline: a stand-in OpenAI client.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from backend.llm_client import OUTPUT_TOKEN_LIMIT, OllamaLLMClient, OutputLimitReached
from backend.telemetry import TELEMETRY, LLMTelemetry

TAIL = 2000


def test_a_record_keeps_a_cut_answers_tail_and_nothing_for_a_finished_one():
    t = LLMTelemetry()
    t.record(backend="ollama", tier="economy", model="m", operation="generate", latency_s=1.0, prompt_chars=10,
             output_limited=True, cut_tail="...the end")
    t.record(backend="ollama", tier="economy", model="m", operation="generate", latency_s=1.0, prompt_chars=10)
    first, second = t.as_dicts()
    assert first["cut_tail"] == "...the end" and second["cut_tail"] is None


class _Completions:
    def __init__(self, content, finish_reason):
        self.content, self.finish_reason = content, finish_reason

    def create(self, **kwargs):
        choice = SimpleNamespace(message=SimpleNamespace(content=self.content), finish_reason=self.finish_reason)
        return SimpleNamespace(choices=[choice], usage=None)


def _client(content, finish_reason):
    client = OllamaLLMClient.__new__(OllamaLLMClient)
    client.model_name = "fake"
    client._openai = SimpleNamespace(chat=SimpleNamespace(completions=_Completions(content, finish_reason)))
    return client


def test_the_local_client_records_the_last_2000_characters_of_every_cut_attempt():
    TELEMETRY.reset()
    answer = "".join(f"{{\"value\": \"evil{i}.example\"}}, " for i in range(2000))
    with pytest.raises(OutputLimitReached):
        _client(answer, "length").generate("p")
    calls = TELEMETRY.as_dicts()
    assert len(calls) == 3 and all(c["output_limited"] for c in calls)
    assert all(c["cut_tail"] == answer[-TAIL:] for c in calls)


def test_a_finished_answer_keeps_no_tail():
    TELEMETRY.reset()
    assert _client("{\"ok\": 1}", "stop").generate("p") == "{\"ok\": 1}"
    assert TELEMETRY.as_dicts()[0]["cut_tail"] is None
    assert OUTPUT_TOKEN_LIMIT == 16384
