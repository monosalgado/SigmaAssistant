"""Characterization tests for ReviewStage's hand-rolled Sigma validation.

These pin the CURRENT behaviour of `_validate_syntax` and `_validate_mitre_tactics`
so that replacing them with pySigma produces a visible, reviewable behavioural diff
rather than a silent change.

Constraint: these tests must run fully offline — no VPN, no network, no LLM calls.
`ReviewStage` is therefore constructed with `client=None` and `vector_store=None`;
neither is touched by the functions under test.
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


def infos(issues: list) -> list:
    return [i for i in issues if i["severity"] == "info"]


# --- happy path -------------------------------------------------------------

def test_valid_rule_produces_no_issues(stage):
    assert stage._validate_syntax(VALID_RULE, 0) == []


# --- YAML-level failures ----------------------------------------------------

def test_malformed_yaml_is_a_single_error(stage):
    issues = stage._validate_syntax("title: [unclosed", 0)
    assert len(issues) == 1
    assert issues[0]["severity"] == "error"
    assert "Invalid YAML syntax" in issues[0]["message"]


def test_yaml_that_is_not_a_mapping_is_an_error(stage):
    issues = stage._validate_syntax("just a bare string", 0)
    assert len(issues) == 1
    assert issues[0]["severity"] == "error"
    assert "did not parse to a dictionary" in issues[0]["message"]


# --- required fields --------------------------------------------------------

def test_missing_required_field_is_an_error(stage):
    rule = """
title: No Level Here
logsource:
    category: process_creation
detection:
    selection:
        Image: 'x.exe'
    condition: selection
"""
    fields = {i["field"] for i in errors(stage._validate_syntax(rule, 0))}
    assert "rule[0].level" in fields


# --- detection block --------------------------------------------------------

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
    messages = [i["message"] for i in errors(stage._validate_syntax(rule, 0))]
    assert any("missing 'condition'" in m for m in messages)


def test_detection_with_only_condition_is_an_error(stage):
    rule = """
title: No Selections
logsource:
    category: process_creation
detection:
    condition: selection
level: low
"""
    messages = [i["message"] for i in errors(stage._validate_syntax(rule, 0))]
    assert any("no selection fields" in m for m in messages)


# --- softer checks ----------------------------------------------------------

def test_nonstandard_level_is_a_warning_not_an_error(stage):
    rule = VALID_RULE.replace("level: high", "level: catastrophic")
    issues = stage._validate_syntax(rule, 0)
    assert errors(issues) == []
    assert any("catastrophic" in i["message"] for i in warnings_(issues))


def test_logsource_without_category_or_product_is_a_warning(stage):
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
    issues = stage._validate_syntax(rule, 0)
    assert errors(issues) == []
    assert len(warnings_(issues)) == 1


def test_non_attack_tag_is_info_only(stage):
    rule = VALID_RULE.replace("    - attack.execution", "    - cve.2024.1234")
    issues = stage._validate_syntax(rule, 0)
    assert errors(issues) == []
    assert any("cve.2024.1234" in i["message"] for i in infos(issues))


# --- rule index is threaded through ----------------------------------------

def test_rule_index_appears_in_field_paths(stage):
    issues = stage._validate_syntax("title: [unclosed", 3)
    assert issues[0]["field"] == "rule[3]"


# --- MITRE tactic validation degrades safely without a vector store ---------

def test_mitre_tactic_validation_is_skipped_without_vector_store(stage):
    rules = [{"yaml_content": VALID_RULE}]
    assert stage._validate_mitre_tactics(rules) == []
