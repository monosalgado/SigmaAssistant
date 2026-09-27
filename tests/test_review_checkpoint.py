"""Tests for the checkpoint between analysis and generation (plan Phase 3/4, user 2026-09-27).

Fully offline: every stage is a fake that records its call; no LLM, no network.

The web app's run stops after the analysis, saves it, and waits for the analyst's review;
generation then starts from the saved analysis - no second analysis, whose output would
differ (LLM output is not deterministic). The one-pass stream keeps its exact event
sequence (the first test pins it), and `run_sync`, which the harness calls, is not touched
(design P5).
"""

from __future__ import annotations

import json

import pytest

from backend.pipeline.analyst_review import ReviewError
from backend.pipeline.orchestrator import PipelineOrchestrator, analysis_state

URL = "https://example.org/advisory"
RULE = """title: Sudo negative user id
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: 'sudo -u#-1'
    condition: selection
"""
# A rule that misses the attack vector: no payload signature, entry point or attacker input.
MISSES_VECTOR = """title: Whoami after a privilege change
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/whoami'
    condition: selection
"""


class FakeStage:
    def __init__(self, name, calls, effect):
        self.name, self.calls, self.effect = name, calls, effect

    def run(self, context):
        self.calls.append(self.name)
        self.effect(context)
        return context


def _orchestrator(first_review_valid=True, rules_cover_from=1):
    """rules_cover_from: the first generation whose rule covers the attack vector."""
    orch = PipelineOrchestrator.__new__(PipelineOrchestrator)
    orch.calls = []
    orch.seen_by_generation = []
    reviews = []

    def analysis(c):
        c["extraction"] = {"indicators": [{"value": "sudo -u#-1 id", "type": "command_line"},
                                          {"value": "/etc/sudoers", "type": "file_path"}],
                           "attack_summary": "sudo bypass", "suggested_log_sources": []}
        c["ttp_mapping"] = {"mappings": [{"technique_id": "T1548.003"}, {"technique_id": "T1068"}],
                            "dropped_ids": []}
        c["logsource_suggestion"] = {"suggestions": [
            {"category": "process_creation", "product": "windows", "service": None, "confidence": 0.95},
            {"category": "process_creation", "product": "linux", "service": None, "confidence": 0.7}],
            "primary_source": "process_creation/windows"}
        c["rag_mitre"] = ["T1548.003 Sudo and Sudo Caching"]

    def generate(c):
        orch.seen_by_generation.append({
            "techniques": [m["technique_id"] for m in c["ttp_mapping"]["mappings"]],
            "logsource": dict(c["logsource_suggestion"]),
            "history": list(c.get("history") or []),
            "retry": bool(c.get("validation_feedback")),
        })
        covers = len(orch.seen_by_generation) >= rules_cover_from
        c["generation"] = {"rules": [{"yaml_content": RULE if covers else MISSES_VECTOR, "explanation": "why"}],
                           "notes": ""}
        c["rag_sigma"], c["rag_sysmon"] = ["sigma doc"], ["sysmon doc"]

    def review(c):
        reviews.append(1)
        valid = first_review_valid or len(reviews) > 1
        c["validation"] = {"is_valid": valid,
                           "issues": [] if valid else [{"severity": "error", "message": "bad field"}]}
        c["optimization"] = {"rules": [{"yaml_content": r["yaml_content"], "changes_made": []}
                                       for r in c["generation"]["rules"]], "all_changes": []}

    stage = lambda name, effect: FakeStage(name, orch.calls, effect)  # noqa: E731
    orch.preprocess = stage("preprocess", lambda c: c.update(preprocessed={
        "original_query": URL, "segments": ["s"], "url_content": [{"url": URL, "content": "page"}],
        "image_transcription": None, "combined_text": "page"}))
    orch.web_enrich = stage("web_enrich", lambda c: c.update(enrichment={"sources": [], "search_queries": []}))
    orch.poc_analysis = stage("poc_analysis", lambda c: c.update(poc_analysis={
        "snippets_found": 0, "behavioral_indicators": [], "attack_flow": ""}))
    orch.attack_vector = stage("attack_vector", lambda c: c.update(attack_vector={
        "initial_access_vector": "local sudo call", "protocol": "local", "vuln_class": "auth_bypass",
        "entry_point": "sudo", "attacker_controlled_input": "user id",
        "payload_signatures": [{"pattern": "sudo -u#-1", "where": "command line", "derived_from": "x"}],
        "incidental_artifacts": [], "confidence": 0.9}))
    orch.analysis = stage("analysis", analysis)
    orch.generate = stage("generate", generate)
    orch.review = stage("review", review)
    return orch


def _steps(events):
    return [(e["event"], e["data"].get("stage"), e["data"].get("status"), e["data"].get("detail"))
            for e in events if e["event"] == "stage"]


ANALYSIS_STEPS = [
    ("stage", "classification", "running", "Classifying intent..."),
    ("stage", "classification", "complete", "Intent: generate_rule"),
    ("stage", "preprocessing", "running", "Parsing input and fetching URLs..."),
    ("stage", "preprocessing", "complete", "1 segments, 1 URLs"),
    ("stage", "web_enrichment", "running", "Searching for additional threat intelligence..."),
    ("stage", "web_enrichment", "complete", "0 sources from 0 queries"),
    ("stage", "poc_analysis", "running", "Scanning for code snippets and PoC artifacts..."),
    ("stage", "poc_analysis", "complete", "No code snippets found"),
    ("stage", "attack_vector", "running", "Identifying the primary attack vector..."),
    ("stage", "attack_vector", "complete",
     "auth_bypass via local · 1 payload signatures · 0 incidental strings blacklisted · confidence 90%"),
    ("stage", "analysis", "running", "Extracting indicators, mapping TTPs, analyzing log sources..."),
    ("stage", "analysis", "complete", "2 indicators, 2 TTPs, logsource: process_creation/windows"),
]
GENERATION_STEPS = [
    ("stage", "generation", "running", "Generating Sigma rules..."),
    ("stage", "generation", "complete", "Generated 1 rule(s)"),
    ("stage", "review", "running", "Validating and optimizing rules..."),
    ("stage", "review", "complete", "Valid: True, 0 optimizations"),
    ("stage", "coverage_check", "complete", "No gaps detected"),
]
FEEDBACK_STEP = [("stage", "feedback", "complete", "No corrections needed")]
ANALYSIS_CALLS = ["preprocess", "web_enrich", "poc_analysis", "attack_vector", "analysis"]


# --- the one-pass stream is unchanged -----------------------------------------------

def test_the_one_pass_stream_keeps_its_event_sequence():
    orch = _orchestrator()
    events = list(orch.run_stream(URL))
    assert _steps(events) == ANALYSIS_STEPS + FEEDBACK_STEP + GENERATION_STEPS
    assert [e["event"] for e in events].count("feedback_request") == 1
    assert events[-1]["event"] == "result"
    assert orch.calls == ANALYSIS_CALLS + ["generate", "review"]


def test_the_one_pass_stream_still_retries_once_on_review_errors():
    orch = _orchestrator(first_review_valid=False)
    events = list(orch.run_stream(URL))
    assert ("stage", "review", "running", "Issues found, regenerating...") in _steps(events)
    assert orch.calls == ANALYSIS_CALLS + ["generate", "review", "generate", "review"]


# --- phase A: analyse, then stop ----------------------------------------------------

def test_the_analysis_stops_at_a_checkpoint():
    orch = _orchestrator()
    events = list(orch.analyse_for_review(URL, history=[{"role": "assistant", "content": "hi"}]))
    assert _steps(events) == ANALYSIS_STEPS
    assert events[-1]["event"] == "checkpoint"
    assert orch.calls == ANALYSIS_CALLS


def test_the_checkpoint_carries_what_the_panel_shows_and_what_generation_needs():
    orch = _orchestrator()
    data = list(orch.analyse_for_review(URL))[-1]["data"]
    meta = data["pipeline_metadata"]
    assert meta["logsource_primary"] == "process_creation/windows"
    assert [m["technique_id"] for m in meta["ttp_mappings"]] == ["T1548.003", "T1068"]
    assert meta["attack_vector"]["payload_signatures"][0]["pattern"] == "sudo -u#-1"
    assert data["context"] == {"sigma": [], "mitre": ["T1548.003 Sudo and Sudo Caching"], "sysmon": []}
    for key in ("preprocessed", "attack_vector", "extraction", "ttp_mapping", "logsource_suggestion"):
        assert key in data["state"]


def test_the_saved_analysis_is_json_and_leaves_out_the_conversation():
    orch = _orchestrator()
    state = list(orch.analyse_for_review(URL, history=[{"role": "user", "content": "x"}]))[-1]["data"]["state"]
    assert "history" not in state and "media_file" not in state
    assert json.loads(json.dumps(state)) == state


def test_analysis_state_refuses_what_json_cannot_store():
    with pytest.raises(TypeError):
        analysis_state({"preprocessed": {"x": object()}})


def test_a_chat_message_gets_the_conversational_answer_not_a_checkpoint():
    orch = _orchestrator()
    orch.classify_intent = lambda message, history=None: {"intent": "chat"}
    orch.handle_conversational = lambda message, history=None: "Hello."
    events = list(orch.analyse_for_review("hello there"))
    assert events[-1] == {"event": "result", "data": {
        "rule": "Hello.", "context": {"sigma": [], "mitre": [], "sysmon": []}, "pipeline_metadata": None}}
    assert orch.calls == []


# --- phase B: generate from the saved analysis --------------------------------------

def _saved(orch):
    return list(orch.analyse_for_review(URL))[-1]["data"]["state"]


def test_generation_from_an_unreviewed_analysis_matches_the_one_pass_stream():
    one_pass = _orchestrator()
    reference = list(one_pass.run_stream(URL))
    orch = _orchestrator()
    state = _saved(orch)
    orch.calls.clear()
    events = list(orch.generate_after_review(state, {}))
    assert _steps(events) == GENERATION_STEPS
    assert orch.calls == ["generate", "review"]
    assert events[-1]["data"]["rule"] == reference[-1]["data"]["rule"]
    assert events[-1]["data"]["context"] == reference[-1]["data"]["context"]


def test_generation_does_not_analyse_again():
    orch = _orchestrator(first_review_valid=False)
    state = _saved(orch)
    orch.calls.clear()
    list(orch.generate_after_review(state, {}))
    assert orch.calls == ["generate", "review", "generate", "review"]


def test_the_analysts_review_reaches_generation():
    orch = _orchestrator()
    state = _saved(orch)
    list(orch.generate_after_review(state, {
        "techniques": {"1": "rejected"},
        "logsource": {"category": "process_creation", "product": "linux"}},
        history=[{"role": "user", "content": URL}]))
    seen = orch.seen_by_generation[0]
    assert seen["techniques"] == ["T1548.003"]
    assert seen["logsource"]["user_confirmed"] is True
    assert seen["logsource"]["confirmed_logsource"]["product"] == "linux"
    assert seen["history"] == [{"role": "user", "content": URL}]


def test_the_result_records_the_review_for_the_panel():
    orch = _orchestrator()
    state = _saved(orch)
    result = list(orch.generate_after_review(state, {"techniques": {"1": "rejected"}}))[-1]["data"]
    assert result["pipeline_metadata"]["analyst_review"]["techniques"]["rejected"] == ["T1068"]


def test_an_invalid_review_is_refused_before_any_event():
    orch = _orchestrator()
    state = _saved(orch)
    orch.calls.clear()
    with pytest.raises(ReviewError):
        orch.generate_after_review(state, {"techniques": {"9": "rejected"}})
    assert orch.calls == []


# --- defect 20: the stream's coverage retry ---------------------------------------
# `_should_regenerate_for_coverage` marks the request as retried when it says yes. The stream
# asked it once to word the progress line, so the real check always found "already retried":
# the web app never regenerated for a coverage gap while saying "regenerating". `run_sync`
# (the harness) asks once and retries, so the evaluated pipeline did retry.

def test_the_stream_regenerates_once_when_the_rules_miss_the_attack_vector():
    orch = _orchestrator(rules_cover_from=2)
    steps = _steps(list(orch.run_stream(URL)))
    assert orch.calls == ANALYSIS_CALLS + ["generate", "review", "generate", "review"]
    assert ("stage", "generation", "running", "Regenerating to close coverage gaps...") in steps
    assert steps[-1] == ("stage", "coverage_check", "complete", "Gaps resolved")


def test_generation_after_review_regenerates_on_a_coverage_gap_too():
    orch = _orchestrator(rules_cover_from=2)
    state = _saved(orch)
    orch.calls.clear()
    list(orch.generate_after_review(state, {}))
    assert orch.calls == ["generate", "review", "generate", "review"]


def test_the_progress_line_says_regenerating_only_when_it_regenerates():
    # A validation retry already used the one regeneration a request gets.
    orch = _orchestrator(first_review_valid=False, rules_cover_from=99)
    steps = _steps(list(orch.run_stream(URL)))
    assert orch.calls == ANALYSIS_CALLS + ["generate", "review", "generate", "review"]
    coverage = [d for (_, stage, _, d) in steps if stage == "coverage_check"]
    assert len(coverage) == 1 and coverage[0].endswith("see notes below")


@pytest.mark.parametrize("first_review_valid, rules_cover_from", [
    (True, 1), (True, 2), (True, 99), (False, 1), (False, 99)])
def test_the_stream_regenerates_exactly_when_the_harness_path_does(first_review_valid, rules_cover_from):
    harness = _orchestrator(first_review_valid, rules_cover_from)
    harness.run_sync(URL)
    web = _orchestrator(first_review_valid, rules_cover_from)
    list(web.run_stream(URL))
    assert web.calls == harness.calls
