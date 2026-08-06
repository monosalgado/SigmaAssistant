"""Tests for ReviewStage's deterministic Sigma validation (pySigma-backed).

Constraint: these tests must run fully offline — no VPN, no network, no LLM calls.
`ReviewStage` is constructed with `client=None` and `vector_store=None`; neither is
touched by the functions under test.

History: these began as characterization tests pinning a hand-rolled validator. That
validator was replaced by pySigma; the expectations below record the resulting
behavioural change. See thesis/ENGINEERING_LOG.md, Change 1.
"""

from __future__ import annotations

import pytest

from backend.pipeline.stage_review import ReviewStage


VALID_RULE = """
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


@pytest.fixture
def stage() -> ReviewStage:
    return ReviewStage(client=None, vector_store=None)


def errors(issues: list) -> list:
    return [i for i in issues if i["severity"] == "error"]


def warnings_(issues: list) -> list:
    return [i for i in issues if i["severity"] == "warning"]


# --- happy path -------------------------------------------------------------

def test_valid_rule_produces_no_issues(stage):
    assert stage._validate_rule(VALID_RULE, 0) == []


# --- parse-level failures ---------------------------------------------------

def test_malformed_yaml_is_a_single_error(stage):
    issues = stage._validate_rule("title: [unclosed", 0)
    assert len(issues) == 1
    assert issues[0]["severity"] == "error"
    assert "Invalid YAML syntax" in issues[0]["message"]


def test_yaml_that_is_not_a_mapping_is_an_error(stage):
    """pySigma leaks a bare AttributeError here rather than a SigmaError,
    so the catch-all branch must handle it."""
    issues = stage._validate_rule("just a bare string", 0)
    assert len(issues) == 1
    assert issues[0]["severity"] == "error"
    assert "Could not parse as a Sigma rule" in issues[0]["message"]


def test_detection_without_condition_is_an_error(stage):
    rule = """
title: No Condition
logsource:
    category: process_creation
detection:
    selection:
        Image: 'x.exe'
level: low
"""
    messages = [i["message"] for i in errors(stage._validate_rule(rule, 0))]
    assert any("at least one condition" in m for m in messages)


def test_detection_with_only_condition_is_an_error(stage):
    rule = """
title: No Selections
logsource:
    category: process_creation
detection:
    condition: selection
level: low
"""
    messages = [i["message"] for i in errors(stage._validate_rule(rule, 0))]
    assert any("No detections defined" in m for m in messages)


# --- cases where pySigma is STRICTER than the previous hand-rolled checks ----

def test_nonstandard_level_is_now_a_fatal_error(stage):
    """Previously only a warning. pySigma rejects the rule at parse time."""
    rule = VALID_RULE.replace("level: high", "level: catastrophic")
    issues = stage._validate_rule(rule, 0)
    assert len(errors(issues)) == 1
    assert "not a valid Sigma rule level" in issues[0]["message"]


def test_empty_logsource_is_now_a_fatal_error(stage):
    """Previously only a warning. pySigma rejects the rule at parse time."""
    rule = """
title: Vague Logsource
logsource:
    definition: something custom
detection:
    selection:
        Image: 'x.exe'
    condition: selection
level: low
"""
    issues = stage._validate_rule(rule, 0)
    assert len(errors(issues)) == 1
    assert "log source can't be empty" in issues[0]["message"]


def test_non_attack_tag_is_now_a_warning(stage):
    """Previously info-only. pySigma grades an invalid tag pattern MEDIUM."""
    rule = VALID_RULE.replace("    - attack.execution", "    - cve.2024.1234")
    issues = stage._validate_rule(rule, 0)
    assert errors(issues) == []
    assert any("InvalidPatternTagIssue" in i["field"] for i in warnings_(issues))


def test_missing_uuid_is_a_warning(stage):
    """New check: the previous validator never looked at `id`."""
    rule = VALID_RULE.replace(
        "id: 5e3d3601-0000-4000-8000-000000000000\n", "")
    issues = stage._validate_rule(rule, 0)
    assert errors(issues) == []
    assert any("IdentifierExistenceIssue" in i["field"] for i in warnings_(issues))


# --- case where pySigma is LOOSER: the old checks were simply wrong ---------

def test_missing_level_is_not_an_error(stage):
    """`level` is optional in the Sigma specification. The previous validator
    listed it in REQUIRED_FIELDS and wrongly rejected valid rules."""
    rule = VALID_RULE.replace("level: high\n", "")
    assert errors(stage._validate_rule(rule, 0)) == []


# --- the check neither validator had ---------------------------------------

def test_condition_referencing_undefined_selection_is_an_error(stage):
    """`nonexistent` is never defined under `detection:`. This passes YAML
    parsing, passes SigmaCollection.from_yaml, and passes all 31 pySigma
    validators. Only forcing condition resolution catches it."""
    rule = VALID_RULE.replace(
        "    condition: selection", "    condition: selection and nonexistent")
    issues = stage._validate_rule(rule, 0)
    messages = [i["message"] for i in errors(issues)]
    assert any("not defined in detections" in m for m in messages)


# --- plumbing ---------------------------------------------------------------

def test_rule_index_appears_in_field_paths(stage):
    issues = stage._validate_rule("title: [unclosed", 3)
    assert issues[0]["field"] == "rule[3]"


def test_mitre_tactic_validation_is_skipped_without_vector_store(stage):
    """Complements pySigma: ATTACKTagValidator only checks that a tag exists
    in a static allow-list, not that tactic and technique are consistent."""
    rules = [{"yaml_content": VALID_RULE}]
    assert stage._validate_mitre_tactics(rules) == []
