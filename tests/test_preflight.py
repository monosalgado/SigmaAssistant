"""The pre-run checklist (plan 1.4b). Offline: parsing and control flow only; the
network, SSH and model steps are injected as stand-ins."""

from __future__ import annotations

from eval.preflight import context_from_ollama_ps, has_token_counts, run_preflight

# Captured from the Spark on 2026-09-23 (`ollama ps`).
OLLAMA_PS = """NAME               ID              SIZE     PROCESSOR    CONTEXT    UNTIL              
qwen3-coder:30b    06c1097efce0    45 GB    100% GPU     262144     4 minutes from now    
"""


def test_context_is_read_from_ollama_ps():
    assert context_from_ollama_ps(OLLAMA_PS, "qwen3-coder:30b") == 262144


def test_a_model_that_is_not_loaded_has_no_context():
    assert context_from_ollama_ps(OLLAMA_PS, "qwen3:30b") is None
    assert context_from_ollama_ps("NAME    ID    SIZE    PROCESSOR    CONTEXT    UNTIL\n", "qwen3-coder:30b") is None


def test_token_counts_must_be_present_and_positive():
    assert has_token_counts({"usage": {"prompt_tokens": 12, "completion_tokens": 1}})
    assert not has_token_counts({"usage": {"prompt_tokens": 12, "completion_tokens": None}})
    assert not has_token_counts({})


def _step(name, ok, log):
    def run():
        log.append(name)
        return ok, f"{name} detail"
    return name, run


def test_all_steps_passing_gives_exit_0():
    log = []
    assert run_preflight([_step("a", True, log), _step("b", True, log)]) == 0
    assert log == ["a", "b"]


def test_it_stops_at_the_first_failure():
    """Later steps are not run: a smoke run is pointless without a tunnel."""
    log = []
    code = run_preflight([_step("tunnel", False, log), _step("smoke", True, log)])
    assert code == 1 and log == ["tunnel"]


def test_a_step_that_raises_is_a_failure_not_a_crash():
    def broken():
        raise ConnectionError("refused")
    assert run_preflight([("tunnel", broken)]) == 1
