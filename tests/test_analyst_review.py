"""Tests for the analyst's review of a saved analysis (plan Phase 3/4, user 2026-09-27).

Fully offline: `apply_review` and `logsource_choices` are pure functions.

The analyst checks what the model understood before any rule is written. Rejected
techniques, indicators and attack patterns do not reach generation; a rejected
pattern joins the excluded strings; a restored excluded string becomes a pattern; a
confirmed log source becomes the analyst's decision (design P4). Code only validates
the decisions against the saved lists and SigmaHQ's log source table; it never
decides for the analyst.
"""

from __future__ import annotations

import copy

import pytest

from backend.pipeline.analyst_review import ReviewError, apply_review, logsource_choices
from backend.pipeline.sigma_logsource import load_logsource_table, on_table

TABLE = {
    "with_category": [
        {"category": "process_creation", "products": ["linux", "macos", "windows"], "fields": []},
        {"category": "webserver", "products": [None], "fields": []},
    ],
    "without_category": [
        {"product": "linux", "service": "auditd", "fields": []},
    ],
}


def _context():
    return {
        "original_query": "https://example.org/sudo",
        "attack_vector": {
            "initial_access_vector": "local sudo invocation",
            "payload_signatures": [
                {"pattern": "sudo -u#-1", "where": "command line", "derived_from": "the advisory"},
                {"pattern": "-u#4294967295", "where": "command line", "derived_from": "the advisory"},
            ],
            "incidental_artifacts": [
                {"value": "researcher_poc.sh", "reason": "the researcher's test script"},
                "patch-2019.diff",
            ],
        },
        "extraction": {"indicators": [
            {"value": "sudo -u#-1 id", "type": "command_line", "context": "c", "confidence": "high"},
            {"value": "/etc/sudoers", "type": "file_path", "context": "c", "confidence": "medium"},
            {"value": "ALL=(ALL, !root)", "type": "other", "context": "c", "confidence": "high"},
        ]},
        "ttp_mapping": {"mappings": [
            {"technique_id": "T1548.003", "technique_name": "Sudo and Sudo Caching"},
            {"technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation"},
        ], "dropped_ids": []},
        "logsource_suggestion": {
            "suggestions": [
                {"category": "process_creation", "product": "windows", "service": None,
                 "confidence": 0.95, "reasoning": "commands run"},
                {"category": "process_creation", "product": "linux", "service": None,
                 "confidence": 0.7, "reasoning": "sudo is a Linux tool"},
            ],
            "primary_source": "process_creation/windows",
        },
    }


# --- nothing decided --------------------------------------------------------------

def test_an_empty_review_changes_nothing_but_records_itself():
    ctx = _context()
    out = apply_review(ctx, {}, TABLE)
    record = out.pop("analyst_review")
    assert out == _context()
    assert record["logsource"] is None
    assert record["techniques"] == {"confirmed": [], "rejected": []}
    assert record["note"] == ""


def test_the_saved_analysis_is_not_modified():
    ctx = _context()
    before = copy.deepcopy(ctx)
    apply_review(ctx, {"techniques": {"1": "rejected"}, "patterns": {"0": "rejected"},
                       "logsource": {"category": "process_creation", "product": "linux"}}, TABLE)
    assert ctx == before


# --- techniques and indicators ----------------------------------------------------

def test_a_rejected_technique_does_not_reach_generation():
    out = apply_review(_context(), {"techniques": {"0": "confirmed", "1": "rejected"}}, TABLE)
    assert [m["technique_id"] for m in out["ttp_mapping"]["mappings"]] == ["T1548.003"]
    assert out["analyst_review"]["techniques"] == {"confirmed": ["T1548.003"], "rejected": ["T1068"]}


def test_a_rejected_indicator_does_not_reach_generation():
    out = apply_review(_context(), {"indicators": {"1": "rejected"}}, TABLE)
    assert [i["value"] for i in out["extraction"]["indicators"]] == ["sudo -u#-1 id", "ALL=(ALL, !root)"]
    assert out["analyst_review"]["indicators"]["rejected"] == ["/etc/sudoers"]


def test_indices_refer_to_the_saved_list_not_to_a_shrinking_one():
    out = apply_review(_context(), {"indicators": {0: "rejected", 2: "rejected"}}, TABLE)
    assert [i["value"] for i in out["extraction"]["indicators"]] == ["/etc/sudoers"]


# --- attack patterns and excluded strings -----------------------------------------

def test_a_rejected_pattern_is_not_given_to_the_rule_writer():
    # Not added to the excluded strings: live on 2026-09-27 the analyst rejected the bare
    # pattern `sudo` as too broad, and as an excluded string it made the coverage check
    # flag every sudo rule as using a "researcher artifact".
    out = apply_review(_context(), {"patterns": {"1": "rejected"}}, TABLE)
    av = out["attack_vector"]
    assert [s["pattern"] for s in av["payload_signatures"]] == ["sudo -u#-1"]
    assert av["incidental_artifacts"] == _context()["attack_vector"]["incidental_artifacts"]
    assert out["analyst_review"]["patterns"]["rejected"] == ["-u#4294967295"]


def test_a_restored_excluded_string_becomes_a_pattern():
    out = apply_review(_context(), {"excluded": {"0": "restored", "1": "restored"}}, TABLE)
    av = out["attack_vector"]
    assert av["incidental_artifacts"] == []
    restored = av["payload_signatures"][-2:]
    assert [s["pattern"] for s in restored] == ["researcher_poc.sh", "patch-2019.diff"]
    assert "restored by the analyst" in restored[0]["derived_from"].lower()
    assert "the researcher's test script" in restored[0]["derived_from"]
    assert out["analyst_review"]["excluded"]["restored"] == ["researcher_poc.sh", "patch-2019.diff"]


# --- log source ------------------------------------------------------------------

def test_confirming_the_models_second_suggestion_puts_it_first():
    out = apply_review(_context(), {"logsource": {"category": "process_creation", "product": "linux"}}, TABLE)
    ls = out["logsource_suggestion"]
    assert ls["user_confirmed"] is True
    assert ls["confirmed_logsource"] == {"category": "process_creation", "product": "linux", "service": None}
    assert ls["primary_source"] == "process_creation/linux"
    assert ls["suggestions"][0]["reasoning"] == "sudo is a Linux tool"
    assert len(ls["suggestions"]) == 2
    assert out["analyst_review"]["logsource"]["suggested_rank"] == 2


def test_a_log_source_the_model_did_not_suggest_is_added_first():
    out = apply_review(_context(), {"logsource": {"product": "linux", "service": "auditd"}}, TABLE)
    ls = out["logsource_suggestion"]
    assert ls["suggestions"][0]["service"] == "auditd"
    assert ls["suggestions"][0]["reasoning"] == "Chosen by the analyst"
    assert len(ls["suggestions"]) == 3
    assert ls["primary_source"] == "linux/auditd"
    assert out["analyst_review"]["logsource"]["suggested_rank"] is None


def test_placeholders_count_as_absent_fields():
    out = apply_review(_context(), {"logsource": {"category": "webserver", "product": "", "service": "null"}}, TABLE)
    assert out["logsource_suggestion"]["confirmed_logsource"] == {
        "category": "webserver", "product": None, "service": None}


@pytest.mark.parametrize("logsource", [
    {"category": "email"},                                            # not a Sigma category
    {"category": "process_creation", "product": "linux", "service": "sysmon"},  # category + service
    {"category": "process_creation"},                                 # SigmaHQ names a product
    {"product": "windows", "service": "made_up"},
    {},
    "process_creation/linux",
])
def test_a_log_source_off_sigmahqs_table_is_refused(logsource):
    with pytest.raises(ReviewError):
        apply_review(_context(), {"logsource": logsource}, TABLE)


# --- the analyst's note -----------------------------------------------------------

def test_the_note_reaches_generation():
    out = apply_review(_context(), {"note": "  The target is Linux only.  "}, TABLE)
    assert out["user_feedback_notes"] == "The target is Linux only."
    assert out["analyst_review"]["note"] == "The target is Linux only."


def test_an_overlong_note_is_refused():
    with pytest.raises(ReviewError):
        apply_review(_context(), {"note": "x" * 2001}, TABLE)


# --- malformed decisions ----------------------------------------------------------

@pytest.mark.parametrize("review", [
    {"techniques": {"2": "rejected"}},        # out of range
    {"techniques": {"-1": "rejected"}},
    {"indicators": {"a": "rejected"}},        # not an index
    {"patterns": {"0": "deleted"}},           # unknown status
    {"excluded": {"0": "rejected"}},          # excluded strings can only be restored
    {"techniques": ["T1068"]},                # not a mapping
    {"rules": {}},                            # unknown kind
    {"note": 5},
])
def test_malformed_decisions_are_refused(review):
    with pytest.raises(ReviewError):
        apply_review(_context(), review, TABLE)


def test_a_missing_list_in_the_saved_analysis_is_an_empty_list():
    ctx = _context()
    del ctx["extraction"]
    out = apply_review(ctx, {"techniques": {"0": "rejected"}}, TABLE)
    assert "extraction" not in out
    with pytest.raises(ReviewError):
        apply_review(ctx, {"indicators": {"0": "rejected"}}, TABLE)


# --- the analyst's choices --------------------------------------------------------

def test_the_choices_are_every_log_source_in_the_table():
    choices = logsource_choices(TABLE)
    assert {"category": "process_creation", "product": "linux", "service": None} in choices
    assert {"category": "webserver", "product": None, "service": None} in choices
    assert {"category": None, "product": "linux", "service": "auditd"} in choices
    assert len(choices) == 5


def test_every_choice_from_the_real_table_is_on_the_table():
    table = load_logsource_table()
    choices = logsource_choices(table)
    assert all(on_table(c, table) for c in choices)
    assert len(choices) == sum(len(r["products"]) for r in table["with_category"]) + len(table["without_category"])
