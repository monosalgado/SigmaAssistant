"""Tests for the deterministic evaluation scorers.

Constraint: fully offline — no VPN, no network, no LLM calls. The scorers are pure
functions over YAML text, so nothing needs mocking.

These matter more than typical unit tests: a scorer that is silently wrong produces
plausible numbers, and those numbers would go into the thesis. The cases below pin
the behaviours that would be easiest to get wrong without noticing — undefined
metrics, sub-technique granularity, modifier stripping, and validator state leaks.

See thesis/ENGINEERING_LOG.md, Change 4.
"""

from __future__ import annotations

import yaml

from eval.scorers import (
    extract_detection_fields,
    extract_techniques,
    score_attack_tags,
    score_case,
    score_detection_fields,
    score_logsource,
    score_validity,
    strip_code_fences,
)


GOLD_RULE_TEXT = """
title: Suspicious Encoded PowerShell Command
id: 5e3d3601-0000-4000-8000-000000000000
status: experimental
description: Detects PowerShell invoked with an encoded command payload.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: ' -enc '
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
"""

GOLD_RULE = yaml.safe_load(GOLD_RULE_TEXT)


# --------------------------------------------------------------------------
# Output-boundary handling
# --------------------------------------------------------------------------

def test_code_fence_is_stripped():
    """Models routinely wrap YAML in ```yaml. Scoring that as a parse failure
    would attribute a formatting habit to rule quality."""
    fenced = "```yaml\ntitle: X\n```"
    assert strip_code_fences(fenced) == "title: X"


def test_unfenced_text_is_unchanged():
    assert strip_code_fences("title: X") == "title: X"


# --------------------------------------------------------------------------
# E1 / E2
# --------------------------------------------------------------------------

def test_valid_rule_parses_with_no_errors():
    result = score_validity(GOLD_RULE_TEXT)
    assert result["parses"] is True
    assert result["parse_error"] is None
    assert result["issues_by_severity"]["error"] == 0


def test_valid_rule_parses_when_fenced():
    assert score_validity("```yaml\n" + GOLD_RULE_TEXT.strip() + "\n```")["parses"] is True


def test_malformed_yaml_does_not_parse():
    result = score_validity("title: [unclosed\n  bad: :")
    assert result["parses"] is False
    assert result["parse_error"]


def test_empty_output_does_not_parse():
    result = score_validity("")
    assert result["parses"] is False
    assert result["parse_error"] == "empty output"


def test_prose_instead_of_a_rule_does_not_parse():
    """A refusal or explanation must score as invalid, not crash the harness."""
    result = score_validity("I cannot create a detection rule for this input.")
    assert result["parses"] is False


def test_validator_state_does_not_leak_between_calls():
    """Several pySigma core validators accumulate state across rules (duplicate
    title, identifier collision). Scoring the same rule twice must not invent
    issues on the second call."""
    first = score_validity(GOLD_RULE_TEXT)
    second = score_validity(GOLD_RULE_TEXT)
    assert first["issue_count"] == second["issue_count"]
    assert second["issues_by_severity"]["error"] == 0


# --------------------------------------------------------------------------
# E3
# --------------------------------------------------------------------------

def test_identical_logsource_matches_exactly():
    result = score_logsource(GOLD_RULE["logsource"], GOLD_RULE["logsource"])
    assert result["exact_match"] is True
    assert result["fields_matched"] == result["fields_scored"] == 2


def test_wrong_product_is_not_an_exact_match():
    result = score_logsource(
        {"category": "process_creation", "product": "linux"}, GOLD_RULE["logsource"]
    )
    assert result["exact_match"] is False
    assert result["fields_matched"] == 1


def test_logsource_comparison_is_case_insensitive():
    result = score_logsource(
        {"category": "Process_Creation", "product": "Windows"}, GOLD_RULE["logsource"]
    )
    assert result["exact_match"] is True


def test_field_absent_from_both_counts_as_agreement():
    """Omitting `service` when the gold rule omits it too is correct, not a miss."""
    result = score_logsource(GOLD_RULE["logsource"], GOLD_RULE["logsource"])
    assert result["per_field"]["service"]["match"] is True
    assert result["per_field"]["service"]["gold_present"] is False


def test_extra_service_breaks_exact_match():
    predicted = dict(GOLD_RULE["logsource"], service="sysmon")
    assert score_logsource(predicted, GOLD_RULE["logsource"])["exact_match"] is False


# --------------------------------------------------------------------------
# E4
# --------------------------------------------------------------------------

def test_only_technique_tags_are_extracted():
    """Tactics and CVE tags are not techniques and must not inflate the score."""
    tags = ["attack.execution", "attack.t1059.001", "cve.2010-5278",
            "detection.emerging-threats"]
    assert extract_techniques(tags) == {"t1059.001"}


def test_identical_tags_score_perfectly():
    result = score_attack_tags(GOLD_RULE["tags"], GOLD_RULE["tags"])
    assert result["exact"]["f1"] == 1.0
    assert result["parent"]["f1"] == 1.0


def test_parent_technique_credited_only_at_parent_granularity():
    """Predicting t1059 when gold says t1059.001 is partially right. Exact
    granularity must score it 0 and parent granularity must score it 1."""
    result = score_attack_tags(["attack.t1059"], ["attack.t1059.001"])
    assert result["exact"]["f1"] == 0.0
    assert result["parent"]["f1"] == 1.0


def test_missing_tags_give_undefined_precision_not_zero():
    """No predicted tags means precision is undefined. Reporting 0.0 would drag
    down an average over cases where the model simply emitted nothing."""
    result = score_attack_tags([], GOLD_RULE["tags"])
    assert result["exact"]["precision"] is None
    assert result["exact"]["recall"] == 0.0


def test_no_gold_techniques_gives_undefined_recall():
    result = score_attack_tags(["attack.t1059"], ["detection.emerging-threats"])
    assert result["exact"]["recall"] is None


# --------------------------------------------------------------------------
# E5
# --------------------------------------------------------------------------

def test_modifiers_are_stripped_from_field_names():
    """`Image|endswith` and `Image` are the same field."""
    assert extract_detection_fields(
        {"selection": {"Image|endswith": "x"}, "condition": "selection"}
    ) == {"image"}


def test_condition_is_not_counted_as_a_field():
    fields = extract_detection_fields(GOLD_RULE["detection"])
    assert "condition" not in fields
    assert fields == {"image", "commandline"}


def test_fields_are_collected_from_lists_of_selections():
    """Sigma allows a selection to be a list of maps; fields inside must count."""
    detection = {
        "selection": [{"Image": "a"}, {"ParentImage": "b"}],
        "condition": "selection",
    }
    assert extract_detection_fields(detection) == {"image", "parentimage"}


def test_identical_detection_scores_perfectly():
    result = score_detection_fields(GOLD_RULE["detection"], GOLD_RULE["detection"])
    assert result["f1"] == 1.0


def test_partial_field_overlap_is_scored_proportionally():
    predicted = {"selection": {"Image|endswith": "\\powershell.exe"}, "condition": "selection"}
    result = score_detection_fields(predicted, GOLD_RULE["detection"])
    assert result["precision"] == 1.0
    assert result["recall"] == 0.5


def test_keyword_only_rule_yields_undefined_not_zero():
    """Real case from the dataset: 8 of 341 emerging-threats rules (log4shell,
    FortiOS) detect via a bare keyword list with no field names. E5 does not
    apply to them, so it must report None and be excluded from aggregates
    rather than scored as a zero the model did not earn."""
    keyword_detection = {
        "keywords": ["/data/etc/wxd.conf", "${jndi:"],
        "condition": "keywords",
    }
    assert extract_detection_fields(keyword_detection) == set()
    result = score_detection_fields(GOLD_RULE["detection"], keyword_detection)
    assert result["recall"] is None
    assert result["f1"] is None


def test_modifier_only_key_is_not_a_field():
    """`'|all':` appears as a bare modifier key in keyword rules and names no field."""
    assert extract_detection_fields({"keywords": {"|all": ["a", "b"]}}) == set()


def test_field_names_match_even_when_values_differ():
    """Documents a real limitation: E5 is structural and ignores values, so an
    inverted detection scores identically to the correct one."""
    predicted = yaml.safe_load(GOLD_RULE_TEXT.replace("powershell.exe", "notepad.exe"))
    result = score_detection_fields(predicted["detection"], GOLD_RULE["detection"])
    assert result["f1"] == 1.0


# --------------------------------------------------------------------------
# Top level
# --------------------------------------------------------------------------

def test_gold_rule_scored_against_itself_is_perfect():
    """Upper-bound sanity check: if this ever fails, the scorers are broken."""
    scores = score_case(GOLD_RULE_TEXT, GOLD_RULE)
    assert scores["validity"]["parses"] is True
    assert scores["logsource"]["exact_match"] is True
    assert scores["attack"]["exact"]["f1"] == 1.0
    assert scores["detection_fields"]["f1"] == 1.0


def test_unparseable_output_yields_null_content_scores():
    """Content metrics must be absent, not zero, when there is no rule to compare."""
    scores = score_case("not a rule at all", GOLD_RULE)
    assert scores["validity"]["parses"] is False
    assert scores["logsource"] is None
    assert scores["attack"] is None
    assert scores["detection_fields"] is None
