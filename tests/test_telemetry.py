"""Tests for LLM telemetry recording.

Constraint: fully offline — no VPN, no network, no LLM calls. The Ollama wiring
test replaces the transport with a fake response object, so nothing leaves the
machine.

The cases that matter most here are the ones where telemetry could be silently
wrong rather than visibly broken: missing token counts being summed as zero, and
failed calls vanishing instead of being recorded. Both would produce cost figures
that look precise and are not.

See thesis/ENGINEERING_LOG.md, Change 5.
"""

from __future__ import annotations

import pytest

from backend.telemetry import (
    LLMTelemetry,
    extract_gemini_usage,
    extract_openai_usage,
    stage_scope,
)


class _Obj:
    """Minimal stand-in for an SDK response object."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


@pytest.fixture
def tel() -> LLMTelemetry:
    return LLMTelemetry()


def _record(tel, **overrides):
    args = dict(
        backend="gemini", tier="primary", model="gemini-2.5-flash",
        operation="generate", latency_s=1.0, prompt_chars=100,
        response_chars=50, usage={"prompt_tokens": 10, "completion_tokens": 5,
                                  "total_tokens": 15},
    )
    args.update(overrides)
    tel.record(**args)


# --------------------------------------------------------------------------
# Usage extraction
# --------------------------------------------------------------------------

def test_gemini_usage_extracted():
    response = _Obj(usage_metadata=_Obj(
        prompt_token_count=1200, candidates_token_count=300,
        thoughts_token_count=800, total_token_count=2300))
    assert extract_gemini_usage(response) == {
        "prompt_tokens": 1200, "completion_tokens": 300,
        "thinking_tokens": 800, "total_tokens": 2300}


def test_thinking_tokens_are_not_dropped_from_the_total():
    """gemini-2.5-flash bills reasoning tokens at the output rate, but excludes
    them from candidates_token_count. Deriving the total as prompt + completion
    would undercount by the entire thinking budget."""
    tel = LLMTelemetry()
    tel.record(
        backend="gemini", tier="primary", model="gemini-2.5-flash",
        operation="generate", latency_s=1.0, prompt_chars=10, response_chars=10,
        usage={"prompt_tokens": 1200, "completion_tokens": 300,
               "thinking_tokens": 800, "total_tokens": 2300},
    )
    summary = tel.summary()
    assert summary["thinking_tokens"] == 800
    assert summary["total_tokens"] == 2300  # not 1500
    assert summary["by_tier"]["primary"]["thinking_tokens"] == 800


def test_total_is_derived_including_thinking_when_provider_omits_it():
    tel = LLMTelemetry()
    tel.record(
        backend="gemini", tier="primary", model="m", operation="generate",
        latency_s=1.0, prompt_chars=10, response_chars=10,
        usage={"prompt_tokens": 100, "completion_tokens": 20, "thinking_tokens": 50},
    )
    assert tel.summary()["total_tokens"] == 170


def test_openai_usage_extracted():
    response = _Obj(usage=_Obj(prompt_tokens=800, completion_tokens=200, total_tokens=1000))
    assert extract_openai_usage(response) == {
        "prompt_tokens": 800, "completion_tokens": 200, "total_tokens": 1000}


def test_missing_usage_metadata_returns_empty_not_zeros():
    """SDK field names change between versions. A response without usage must
    yield no data rather than a confident zero."""
    assert extract_gemini_usage(_Obj()) == {}
    assert extract_openai_usage(_Obj()) == {}


def test_partial_usage_fields_do_not_raise():
    response = _Obj(usage_metadata=_Obj(prompt_token_count=100))
    usage = extract_gemini_usage(response)
    assert usage["prompt_tokens"] == 100
    assert usage["completion_tokens"] is None


# --------------------------------------------------------------------------
# Recording and aggregation
# --------------------------------------------------------------------------

def test_single_call_is_recorded(tel):
    _record(tel)
    summary = tel.summary()
    assert summary["n_calls"] == 1
    assert summary["total_tokens"] == 15
    assert summary["calls_without_token_data"] == 0


def test_reset_clears_calls(tel):
    _record(tel)
    tel.reset()
    assert tel.summary()["n_calls"] == 0


def test_tokens_are_summed_per_tier(tel):
    _record(tel, tier="primary")
    _record(tel, tier="economy", model="qwen3-coder:30b", backend="ollama",
            usage={"prompt_tokens": 40, "completion_tokens": 60, "total_tokens": 100})
    summary = tel.summary()
    assert summary["by_tier"]["primary"]["prompt_tokens"] == 10
    assert summary["by_tier"]["economy"]["completion_tokens"] == 60
    assert summary["total_tokens"] == 115


def test_calls_without_token_data_are_counted_not_zeroed(tel):
    """A call with no token data did not use zero tokens. It must be flagged so a
    partial total is never read as a complete one."""
    _record(tel)
    _record(tel, usage={})
    summary = tel.summary()
    assert summary["calls_with_token_data"] == 1
    assert summary["calls_without_token_data"] == 1
    assert summary["total_tokens"] == 15


def test_all_calls_missing_tokens_gives_none_total(tel):
    """If nothing reported usage, the total is unknown — not zero."""
    _record(tel, usage={})
    summary = tel.summary()
    assert summary["total_tokens"] is None
    assert summary["prompt_tokens"] is None
    assert summary["n_calls"] == 1


def test_failed_calls_are_recorded_with_error(tel):
    _record(tel, ok=False, error="ConnectionError: refused", usage={})
    summary = tel.summary()
    assert summary["n_errors"] == 1
    assert summary["by_tier"]["primary"]["errors"] == 1


def test_latency_accumulates(tel):
    _record(tel, latency_s=1.5)
    _record(tel, latency_s=2.25)
    assert tel.summary()["total_latency_s"] == 3.75


def test_bounded_history_does_not_grow_without_limit():
    """The FastAPI server is long-running; unbounded history would leak memory."""
    small = LLMTelemetry(maxlen=3)
    for _ in range(10):
        _record(small)
    assert small.summary()["n_calls"] == 3


def test_as_dicts_is_serialisable(tel):
    _record(tel)
    row = tel.as_dicts()[0]
    assert row["tier"] == "primary"
    assert row["prompt_tokens"] == 10
    assert row["ok"] is True


# --------------------------------------------------------------------------
# Wiring: the client actually records
# --------------------------------------------------------------------------

def test_ollama_client_records_tokens_and_latency(monkeypatch):
    """Proves the instrumentation is wired in, not merely importable. The unit
    tests above would all pass even if llm_client never called TELEMETRY."""
    from backend import telemetry as telemetry_module
    from backend.llm_client import OllamaLLMClient

    fake_telemetry = LLMTelemetry()
    monkeypatch.setattr(telemetry_module, "TELEMETRY", fake_telemetry)
    monkeypatch.setattr("backend.llm_client.TELEMETRY", fake_telemetry)

    client = OllamaLLMClient("http://localhost:11434", "qwen3-coder:30b")

    response = _Obj(
        choices=[_Obj(message=_Obj(content='{"ok": true}'))],
        usage=_Obj(prompt_tokens=123, completion_tokens=45, total_tokens=168),
    )
    monkeypatch.setattr(
        client, "_openai",
        _Obj(chat=_Obj(completions=_Obj(create=lambda **kw: response))),
    )

    assert client.generate("a prompt", json_mode=False) == '{"ok": true}'

    summary = fake_telemetry.summary()
    assert summary["n_calls"] == 1
    assert summary["by_tier"]["economy"]["prompt_tokens"] == 123
    assert summary["total_tokens"] == 168
    assert fake_telemetry.calls()[0].backend == "ollama"


def test_ollama_failure_is_recorded_and_reraised(monkeypatch):
    """A Spark outage must appear as a failed economy call. Otherwise the hybrid
    fallback shows up only as an unexplained extra Gemini call."""
    from backend import telemetry as telemetry_module
    from backend.llm_client import OllamaLLMClient

    fake_telemetry = LLMTelemetry()
    monkeypatch.setattr(telemetry_module, "TELEMETRY", fake_telemetry)
    monkeypatch.setattr("backend.llm_client.TELEMETRY", fake_telemetry)

    client = OllamaLLMClient("http://localhost:11434", "qwen3-coder:30b")

    def boom(**kwargs):
        raise ConnectionError("connection refused")

    monkeypatch.setattr(
        client, "_openai", _Obj(chat=_Obj(completions=_Obj(create=boom))))

    with pytest.raises(ConnectionError):
        client.generate("a prompt")

    summary = fake_telemetry.summary()
    assert summary["n_calls"] == 1
    assert summary["n_errors"] == 1
    assert fake_telemetry.calls()[0].ok is False


# --------------------------------------------------------------------------
# Stage attribution (plan 1.1a)
# --------------------------------------------------------------------------
# Every recorded call used to read operation="generate", so the stages of a case
# could only be told apart by call order, which shifts whenever the PoC stage or a
# regeneration runs.

def _fake_ollama(monkeypatch, create):
    """The real OllamaLLMClient, with only its network call replaced."""
    from backend import telemetry as telemetry_module
    from backend.llm_client import OllamaLLMClient

    fake_telemetry = LLMTelemetry()
    monkeypatch.setattr(telemetry_module, "TELEMETRY", fake_telemetry)
    monkeypatch.setattr("backend.llm_client.TELEMETRY", fake_telemetry)
    client = OllamaLLMClient("http://localhost:11434", "qwen3-coder:30b")
    monkeypatch.setattr(
        client, "_openai", _Obj(chat=_Obj(completions=_Obj(create=create))))
    return client, fake_telemetry


def _ok_response(**kwargs):
    return _Obj(
        choices=[_Obj(message=_Obj(content='{"intent": "question", "reasoning": "x"}'))],
        usage=_Obj(prompt_tokens=1, completion_tokens=1, total_tokens=2),
    )


def test_call_outside_any_stage_has_no_stage(tel):
    _record(tel)
    assert tel.calls()[0].stage is None


def test_call_inside_a_stage_scope_is_labelled(tel):
    with stage_scope("analysis"):
        _record(tel)
    _record(tel)
    assert [c.stage for c in tel.calls()] == ["analysis", None]


def test_stage_scope_is_restored_after_an_exception(tel):
    with pytest.raises(RuntimeError):
        with stage_scope("review"):
            raise RuntimeError("stage failed")
    _record(tel)
    assert tel.calls()[0].stage is None


def test_stage_label_survives_serialisation(tel):
    """The harness writes as_dicts() into each result row."""
    with stage_scope("generation"):
        _record(tel)
    assert tel.as_dicts()[0]["stage"] == "generation"


def test_pipeline_stage_labels_the_real_client_call(monkeypatch):
    from backend.pipeline.stage_attack_vector import AttackVectorStage

    client, fake_telemetry = _fake_ollama(monkeypatch, _ok_response)
    AttackVectorStage(client, "qwen3-coder:30b").llm_call("a prompt", economy=True)
    assert fake_telemetry.calls()[0].stage == "attack_vector"


def test_failed_call_is_still_attributed_to_its_stage(monkeypatch):
    """A failed call must say which stage lost its answer."""
    from backend.pipeline.stage_review import ReviewStage

    def boom(**kwargs):
        raise ConnectionError("connection refused")

    client, fake_telemetry = _fake_ollama(monkeypatch, boom)
    with pytest.raises(ConnectionError):
        ReviewStage(client, "qwen3-coder:30b").llm_call("a prompt", economy=True)
    call = fake_telemetry.calls()[0]
    assert (call.stage, call.ok) == ("review", False)


def test_orchestrator_intent_call_is_labelled(monkeypatch):
    """Intent classification calls the client directly, not through a stage."""
    from backend.pipeline.orchestrator import PipelineOrchestrator

    client, fake_telemetry = _fake_ollama(monkeypatch, _ok_response)
    PipelineOrchestrator(client, "qwen3-coder:30b", vector_store=None).classify_intent(
        "how do I write a rule for lateral movement?")
    assert fake_telemetry.calls()[0].stage == "intent_classification"
