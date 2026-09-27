"""Tests for analyses saved in the session while the analyst reviews them.

Fully offline: `backend/review_sessions.py` works on the session's message list only.

Design decision 2 (user, 2026-09-26): the analysis waiting for review lives in the
session record persisted to `data/sessions.json`, so reviewing can take a while and a
page reload does not lose it. Each analysis is generated from once.
"""

from __future__ import annotations

import pytest

from backend.review_sessions import (
    AWAITING, GENERATED, GENERATING,
    AnalysisNotAwaiting, AnalysisNotFound,
    abandon_generation, checkpoint_message, finish_generation, public_messages,
    reset_interrupted, start_generation,
)

CHECKPOINT = {
    "state": {"attack_vector": {"initial_access_vector": "x"}, "preprocessed": {"combined_text": "page"}},
    "pipeline_metadata": {"logsource_primary": "process_creation/windows"},
    "context": {"sigma": [], "mitre": ["doc"], "sysmon": []},
}


def _session():
    return [
        {"role": "assistant", "content": "greeting"},
        {"role": "user", "content": "an earlier question"},
        {"role": "assistant", "content": "an earlier answer"},
        {"role": "user", "content": "https://example.org/advisory"},
        checkpoint_message("a1", CHECKPOINT),
    ]


def test_the_checkpoint_message_keeps_the_analysis_and_what_the_panel_shows():
    msg = checkpoint_message("a1", CHECKPOINT)
    assert msg["role"] == "assistant"
    assert msg["analysis_id"] == "a1"
    assert msg["status"] == AWAITING
    assert msg["state"] == CHECKPOINT["state"]
    assert msg["pipeline_metadata"] == CHECKPOINT["pipeline_metadata"]
    assert msg["context"] == CHECKPOINT["context"]
    assert "Analysis panel" in msg["content"]


def test_starting_generation_returns_the_saved_analysis_and_the_conversation_before_it():
    messages = _session()
    state, history = start_generation(messages, "a1")
    assert state == CHECKPOINT["state"]
    assert [m["content"] for m in history] == ["greeting", "an earlier question", "an earlier answer"]
    assert messages[-1]["status"] == GENERATING


def test_an_analysis_is_generated_from_once():
    messages = _session()
    start_generation(messages, "a1")
    with pytest.raises(AnalysisNotAwaiting):
        start_generation(messages, "a1")


def test_an_unknown_analysis_is_not_found():
    with pytest.raises(AnalysisNotFound):
        start_generation(_session(), "nope")


def test_finishing_appends_the_rules_and_records_the_review():
    messages = _session()
    start_generation(messages, "a1")
    result = {"rule": "```yaml\ntitle: X\n```", "context": {"sigma": ["s"], "mitre": [], "sysmon": []},
              "pipeline_metadata": {"analyst_review": {"note": "Linux only"}}}
    finish_generation(messages, "a1", result)
    assert messages[4]["status"] == GENERATED
    assert messages[4]["review"] == {"note": "Linux only"}
    assert messages[-1] == {"role": "assistant", "content": result["rule"], "context": result["context"],
                            "pipeline_metadata": result["pipeline_metadata"], "analysis_id": "a1"}


def test_a_failed_generation_can_be_retried():
    messages = _session()
    start_generation(messages, "a1")
    abandon_generation(messages, "a1")
    assert messages[-1]["status"] == AWAITING
    start_generation(messages, "a1")


def test_a_generation_cut_by_a_restart_can_be_retried():
    sessions = {"s1": _session()}
    start_generation(sessions["s1"], "a1")
    reset_interrupted(sessions)
    assert sessions["s1"][-1]["status"] == AWAITING


def test_the_browser_gets_the_messages_without_the_saved_analysis():
    messages = _session()
    public = public_messages(messages)
    assert "state" not in public[-1]
    assert public[-1]["pipeline_metadata"] == CHECKPOINT["pipeline_metadata"]
    assert "state" in messages[-1]   # the saved session keeps it
