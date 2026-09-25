"""Offline tests for Change 25 (plan 2.2b): a suggested log source with a category
carries no service; without a category the service stays, and an unknown one is
marked for the analyst to confirm.

Why: of SigmaHQ's 2,880 rules with a category, 12 carry a service; of its 811 rules
without one, 792 do (Windows Security, AWS CloudTrail, Linux auditd…). The analysis
stage suggested a service in every case (`sysmon` 35 of 53 after Change 22), wrong
in 53 of 53 against the human rules.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.pipeline.sigma_logsource import (
    KNOWN_SERVICES_PATH,
    build_known_services,
    describe_suggestion,
    has_category,
    load_known_services,
    normalise_suggestion,
)
from backend.pipeline.stage_analysis import AnalysisStage

REPO = Path(__file__).resolve().parent.parent
KNOWN = {("windows", "security"), ("linux", "auditd"), ("aws", "cloudtrail")}


# --- the rule ------------------------------------------------------------

def test_a_suggestion_with_a_category_loses_its_service_and_records_it():
    out = normalise_suggestion(
        {"category": "process_creation", "product": "windows", "service": "sysmon"}, KNOWN)
    assert out["service"] is None
    assert out["service_dropped"] == "sysmon"
    assert out["category"] == "process_creation" and out["product"] == "windows"


def test_a_suggestion_with_a_category_and_no_service_is_unchanged():
    sug = {"category": "webserver", "product": None, "confidence": 0.9}
    out = normalise_suggestion(sug, KNOWN)
    assert out == {**sug, "service": None}
    assert "service_dropped" not in out


def test_without_a_category_a_known_service_stays_unflagged():
    out = normalise_suggestion({"product": "windows", "service": "security"}, KNOWN)
    assert out["service"] == "security"
    assert "service_to_confirm" not in out


def test_without_a_category_an_unknown_service_stays_but_is_marked_to_confirm():
    out = normalise_suggestion({"category": "-", "product": "fortigate",
                                "service": "FortiGate Firewall Logs"}, KNOWN)
    assert out["service"] == "FortiGate Firewall Logs"
    assert out["service_to_confirm"] is True


def test_known_services_match_ignoring_case_and_space():
    out = normalise_suggestion({"product": " Windows ", "service": "Security"}, KNOWN)
    assert "service_to_confirm" not in out


@pytest.mark.parametrize("value", [None, "", "  ", "-", "none", "None", "N/A", "null"])
def test_placeholders_do_not_count_as_a_category(value):
    assert not has_category(value)


def test_a_real_category_counts_whatever_its_case():
    assert has_category(" Process_Creation ")


def test_the_input_suggestion_is_not_modified():
    sug = {"category": "process_creation", "service": "sysmon"}
    normalise_suggestion(sug, KNOWN)
    assert sug == {"category": "process_creation", "service": "sysmon"}


# --- where it applies ----------------------------------------------------

class _Client:
    model_name = "fake"

    def generate(self, prompt, **kwargs):
        return json.dumps({"indicators": [], "ttp_mappings": [], "logsource_primary": "x",
                           "logsource_suggestions": [
                               {"category": "process_creation", "product": "windows",
                                "service": "sysmon", "confidence": 0.9},
                               {"product": "windows", "service": "security", "confidence": 0.5},
                           ]})


class _NoRag:
    def search(self, *args, **kwargs):
        return {}


def test_the_analysis_stage_applies_the_rule_to_its_suggestions():
    ctx = {"preprocessed": {"combined_text": "text", "segments": [], "url_content": []}}
    out = AnalysisStage(_Client(), "fake", _NoRag()).run(ctx)
    first, second = out["logsource_suggestion"]["suggestions"]
    assert first["service"] is None and first["service_dropped"] == "sysmon"
    assert second["service"] == "security" and "service_to_confirm" not in second


@pytest.mark.parametrize("sug, text", [
    ({"category": "process_creation", "product": "windows", "service": None}, "process_creation/windows"),
    ({"category": "webserver"}, "webserver"),
    ({"product": "windows", "service": "security"}, "windows/security"),
    ({}, "?"),
])
def test_the_generation_prompt_shows_only_the_fields_present(sug, text):
    """Not `process_creation/windows/None`: nothing for the model to copy."""
    assert describe_suggestion(sug) == text


def test_flags_are_not_shown_to_the_generation_stage():
    """service_to_confirm is for the analyst (Phase 3), not the rule writer."""
    sug = {"product": "fortigate", "service": "x", "service_to_confirm": True,
           "service_dropped": "y"}
    assert describe_suggestion(sug) == "fortigate/x"


# --- the reference list --------------------------------------------------

def test_the_committed_list_holds_the_common_services():
    known = load_known_services()
    assert KNOWN <= known
    assert len(known) == 73


def test_the_list_is_built_from_the_rules_the_retrieval_index_uses():
    """data/sigma/rules, never rules-emerging-threats: those are the scored answers."""
    rules = REPO / "data/sigma/rules"
    if not rules.is_dir():
        pytest.skip("data/sigma not present (rebuilt locally, not committed)")
    assert build_known_services(rules) == load_known_services()
    assert ("fortios", "sslvpnd") not in load_known_services()  # emerging-threats only


def test_the_list_file_is_where_the_code_reads_it():
    assert KNOWN_SERVICES_PATH.name == "sigma_known_services.json"
    assert KNOWN_SERVICES_PATH.is_file()
