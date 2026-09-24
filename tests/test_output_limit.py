"""Offline tests for Change 24 (defect 19): every LLM answer has a bounded length.

Case 9a2d8b3e's analysis answer looped — 336 invented ATT&CK sub-techniques in
sequence — and, with no output limit, ran until the client timeout on every
attempt; the stop rule then halted the run at that case each time. Now a call asks
for at most OUTPUT_TOKEN_LIMIT tokens; an answer cut at the limit is retried like a
timeout; if every attempt is cut, the stage gets an error (and uses its empty
default), and the case is written as the pipeline's real result — the model failed,
the infrastructure did not.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.llm_client import OUTPUT_LIMIT_RETRIES, OUTPUT_TOKEN_LIMIT, OutputLimitReached
from backend.telemetry import LLMTelemetry

REPO = Path(__file__).resolve().parent.parent


class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _response(content, finish_reason="stop", completion=10):
    return _Obj(choices=[_Obj(message=_Obj(content=content), finish_reason=finish_reason)],
                usage=_Obj(prompt_tokens=100, completion_tokens=completion,
                           total_tokens=100 + completion))


def _client(monkeypatch, responses):
    """The real OllamaLLMClient; only its network call is replaced."""
    from backend import telemetry as telemetry_module
    from backend.llm_client import OllamaLLMClient

    tel = LLMTelemetry()
    monkeypatch.setattr(telemetry_module, "TELEMETRY", tel)
    monkeypatch.setattr("backend.llm_client.TELEMETRY", tel)
    client = OllamaLLMClient("http://localhost:11434", "qwen3-coder:30b")
    sent = []
    queue = list(responses)

    def create(**kwargs):
        sent.append(kwargs)
        return queue.pop(0)

    monkeypatch.setattr(client, "_openai", _Obj(chat=_Obj(completions=_Obj(create=create))))
    return client, tel, sent


def test_every_call_asks_for_the_output_limit(monkeypatch):
    client, _, sent = _client(monkeypatch, [_response('{"a": 1}')])
    client.generate("p")
    assert sent[0]["max_tokens"] == OUTPUT_TOKEN_LIMIT == 16384


def test_a_finished_answer_is_returned_after_one_call(monkeypatch):
    client, tel, sent = _client(monkeypatch, [_response('{"a": 1}')])
    assert client.generate("p") == '{"a": 1}'
    assert len(sent) == 1
    assert tel.calls()[0].output_limited is False


def test_a_response_without_finish_reason_counts_as_finished(monkeypatch):
    """Older fakes and some servers omit it; that must not trigger retries."""
    response = _Obj(choices=[_Obj(message=_Obj(content="x"))],
                    usage=_Obj(prompt_tokens=1, completion_tokens=1, total_tokens=2))
    client, tel, sent = _client(monkeypatch, [response])
    assert client.generate("p", json_mode=False) == "x"
    assert len(sent) == 1 and tel.calls()[0].output_limited is False


def test_a_cut_answer_is_retried_and_a_finished_retry_is_used(monkeypatch):
    client, tel, sent = _client(monkeypatch, [
        _response('{"loop": [1, 2, 3', "length", OUTPUT_TOKEN_LIMIT),
        _response('{"a": 1}'),
    ])
    assert client.generate("p") == '{"a": 1}'
    assert len(sent) == 2
    first, second = tel.calls()
    assert (first.output_limited, first.ok) == (True, True)
    assert (second.output_limited, second.ok) == (False, True)


def test_an_answer_cut_on_every_attempt_raises(monkeypatch):
    attempts = 1 + OUTPUT_LIMIT_RETRIES
    client, tel, sent = _client(monkeypatch, [
        _response('{"loop": [', "length", OUTPUT_TOKEN_LIMIT) for _ in range(attempts)])
    with pytest.raises(OutputLimitReached):
        client.generate("p")
    assert len(sent) == attempts == 3
    assert all(c.output_limited and c.ok for c in tel.calls())


def test_the_error_is_an_ordinary_exception_so_stages_fall_back_as_today():
    assert issubclass(OutputLimitReached, Exception)


def test_summary_counts_output_limited_calls():
    tel = LLMTelemetry()
    tel.record(backend="ollama", tier="economy", model="m", operation="generate",
               latency_s=1.0, prompt_chars=10, output_limited=True)
    tel.record(backend="ollama", tier="economy", model="m", operation="generate",
               latency_s=1.0, prompt_chars=10)
    s = tel.summary()
    assert s["calls_output_limited"] == 1
    assert s["n_errors"] == 0


def test_a_cut_answer_does_not_stop_the_run():
    """The stop rule is for infrastructure failures (Change 16)."""
    from eval.run_eval import unmeasured_reason
    assert unmeasured_reason({"llm_calls": [{"ok": True, "output_limited": True}]}) is None
    assert unmeasured_reason({"llm_calls": [{"ok": False, "error": "APITimeoutError"}]})


def test_the_summariser_reports_cut_calls_without_failing_the_gates():
    from eval.summarise import check_gates, summarise
    row = {"rule_id": "a", "snapshots_missed": 0, "poc_snapshots_missed": 0, "error": None,
           "pipeline": {}, "elapsed_s": 100.0,
           "telemetry": {"n_errors": 0, "calls_without_token_data": 0, "calls_output_limited": 2}}
    assert check_gates([row])["verdict"] == "CITABLE"
    s = summarise([row])
    assert s["calls_output_limited"] == 2 and s["cases_output_limited"] == 1


def test_the_limit_is_above_every_answer_that_finished_in_the_reference_run():
    """Justifies the value: it binds only on answers that would not have finished."""
    longest = max(c.get("completion_tokens") or 0
                  for line in (REPO / "eval/results/baseline60_v2.jsonl").read_text().splitlines()
                  for c in json.loads(line).get("llm_calls") or [])
    assert longest == 12374
    assert longest < OUTPUT_TOKEN_LIMIT
