"""Tests for analyses saved in the session while the analyst reviews them.

Fully offline: `backend/review_sessions.py` works on the session's message list only.

Design decision 2 (user, 2026-09-26): the analysis waiting for review lives in the
session record persisted to `data/sessions.json`, so reviewing can take a while and a
page reload does not lose it.

Change 46 (user, 2026-10-07): the rules come first - the analysis is saved at the checkpoint and generation goes on;
the analyst's corrections then regenerate from the saved analysis. Every set of rules is kept as a numbered version
(1 = automatic); an analysis can be generated from again, but not while a generation is running.
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


def test_an_analysis_being_generated_from_cannot_start_again():
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
                            "pipeline_metadata": result["pipeline_metadata"], "analysis_id": "a1", "version": 1,
                            "corrections": "note: Linux only", "carry_review": {"note": "Linux only"}}


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


# --- Change 46: rules first, corrections after; every version kept ----------------------------------------------

from backend.review_sessions import corrections_summary, first_pass_events  # noqa: E402

RESULT = {"rule": "```yaml\ntitle: X\n```", "context": {"sigma": [], "mitre": [], "sysmon": []},
          "pipeline_metadata": {"logsource_primary": "process_creation/windows", "coverage_check": {}}}


def _first_pass(events):
    messages = [{"role": "user", "content": "https://example.org/advisory"}]
    out = list(first_pass_events(messages, iter(events), "a1"))
    return messages, out


def test_the_first_pass_saves_the_analysis_and_the_rules_as_version_1():
    stage = {"event": "stage", "data": {"stage": "analysis", "status": "complete"}}
    messages, out = _first_pass([stage, {"event": "checkpoint", "data": CHECKPOINT}, stage,
                                 {"event": "result", "data": dict(RESULT)}])
    assert [e for e, _ in out] == ["stage", "stage", "result"]         # the checkpoint is kept, not sent
    analysis, rules = messages[1], messages[2]
    assert analysis["analysis_id"] == "a1" and analysis["status"] == GENERATED and analysis["state"] == CHECKPOINT["state"]
    assert analysis["content"] == ""                                    # not a chat bubble of its own
    assert rules["version"] == 1 and rules["analysis_id"] == "a1" and rules["content"] == RESULT["rule"]
    result = out[-1][1]
    assert result["analysis_id"] == "a1" and result["version"] == 1
    assert result["analysis_metadata"] == CHECKPOINT["pipeline_metadata"]    # what the corrections refer to


def test_a_first_pass_that_fails_before_the_analysis_is_saved_is_a_plain_message():
    error = {"rule": "Error during analysis: boom", "context": {}, "pipeline_metadata": None}
    messages, out = _first_pass([{"event": "result", "data": error}])
    assert messages[-1] == {"role": "assistant", "content": error["rule"], "context": {}}
    assert "analysis_id" not in out[-1][1]


def test_a_first_pass_that_fails_after_the_analysis_keeps_it_for_generating_again():
    error = {"rule": "Error during analysis: boom", "context": {}, "pipeline_metadata": None}
    messages, out = _first_pass([{"event": "checkpoint", "data": CHECKPOINT}, {"event": "result", "data": error}])
    assert messages[1]["status"] == AWAITING and messages[-1]["content"] == error["rule"]
    assert out[-1][1]["retry_analysis_id"] == "a1"


def test_corrections_regenerate_from_the_saved_analysis_as_version_2_and_keep_version_1():
    messages, _ = _first_pass([{"event": "checkpoint", "data": CHECKPOINT}, {"event": "result", "data": dict(RESULT)}])
    state, history = start_generation(messages, "a1")                   # allowed: the analysis was generated from
    assert state == CHECKPOINT["state"] and history == []
    assert messages[1]["status"] == GENERATING
    assert finish_generation(messages, "a1", {"rule": "v2 rules", "context": {}, "pipeline_metadata": {}}) == 2
    versions = [m["version"] for m in messages if m.get("analysis_id") == "a1" and "version" in m]
    assert versions == [1, 2] and messages[1]["status"] == GENERATED


def test_a_failed_regeneration_leaves_the_versions_as_they_were():
    messages, _ = _first_pass([{"event": "checkpoint", "data": CHECKPOINT}, {"event": "result", "data": dict(RESULT)}])
    start_generation(messages, "a1")
    abandon_generation(messages, "a1")
    assert messages[1]["status"] == GENERATED
    sessions = {"s": messages}
    start_generation(messages, "a1")
    reset_interrupted(sessions)
    assert messages[1]["status"] == GENERATED


def test_the_corrections_are_summarised_in_plain_words():
    record = {"techniques": {"confirmed": ["T1059"], "rejected": ["T1105", "T1027"]},
              "indicators": {"confirmed": [], "rejected": ["evil.example"], "linked": ["evil.example"]},
              "patterns": {"confirmed": [], "rejected": []}, "excluded": {"restored": ["-enc"]},
              "logsource": {"category": "process_creation", "product": "linux", "service": None, "suggested_rank": 2},
              "note": "Linux hosts only"}
    text = corrections_summary(record)
    assert "log source process_creation / linux" in text
    assert "rejected 2 techniques, 1 indicator" in text and "restored 1 string" in text
    assert "confirmed 1 technique" in text and "note: Linux hosts only" in text
    assert corrections_summary({}) == "no corrections"


def test_each_version_keeps_its_corrections_in_words_for_a_reload():
    messages, _ = _first_pass([{"event": "checkpoint", "data": CHECKPOINT}, {"event": "result", "data": dict(RESULT)}])
    assert messages[-1]["corrections"] is None                          # version 1: automatic
    start_generation(messages, "a1")
    finish_generation(messages, "a1", {"rule": "v2", "context": {}, "pipeline_metadata": {"analyst_review": {
        "logsource": {"category": "process_creation", "product": "linux"}, "note": ""}}})
    assert messages[-1]["corrections"] == "log source process_creation / linux"


def test_the_saved_analysis_panel_data_is_found_by_id():
    from backend.review_sessions import saved_analysis_metadata
    messages, _ = _first_pass([{"event": "checkpoint", "data": CHECKPOINT}, {"event": "result", "data": dict(RESULT)}])
    assert saved_analysis_metadata(messages, "a1") == CHECKPOINT["pipeline_metadata"]


def test_each_version_keeps_its_corrections_by_position_to_carry_into_the_next_round():
    # User 2026-10-07: "carry corrections forward" - the next round starts with these marked (review_from_record).
    state = {"ttp_mapping": {"mappings": [{"technique_id": "T1548.004"}, {"technique_id": "T1068"}]}}
    messages = [{"role": "user", "content": "u"}, analysis_message_for(state)]
    start_generation(messages, "a1")
    finish_generation(messages, "a1", {"rule": "v", "context": {}, "pipeline_metadata": {"analyst_review": {
        "techniques": {"confirmed": [], "rejected": ["T1548.004"]}, "logsource": None, "note": ""}}})
    assert messages[-1]["carry_review"] == {"techniques": {"0": "rejected"}}


def analysis_message_for(state):
    from backend.review_sessions import analysis_message
    msg = analysis_message("a1", {"state": state, "pipeline_metadata": {}, "context": {}})
    msg["status"] = GENERATED
    return msg
