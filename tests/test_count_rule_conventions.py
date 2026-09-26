"""Offline tests for eval/count_rule_conventions.py — Change 33's measures (prompt review
item 1: the rule writer's example), fixed before its run.

The example tagged tactics `attack.credential_access`; SigmaHQ writes
`attack.credential-access` (3,021 of 3,021 in the main set, 389 of 389 gold tags), and
pySigma flags the underscore form. Its placeholder id `12345678-1234-…` is a valid UUID, so
the rule-id check (Change 9) kept copies of it and rules shared an id.
"""

from __future__ import annotations

from eval.count_rule_conventions import EXAMPLE_ID, case_measures, summarise, tactic_tag_styles

R1 = """title: a
id: 12345678-1234-1234-1234-123456789abc
tags:
    - attack.initial_access
    - attack.t1190
    - attack.execution
logsource:
    category: webserver
"""
R2 = """title: b
id: 12345678-1234-1234-1234-123456789abc
tags: [attack.credential-access, attack.defense-evasion, attack.privilege_escalation]
"""
R3 = "title: [broken"


def test_tactic_styles_ignore_techniques_and_one_word_tactics():
    assert tactic_tag_styles(["attack.initial_access", "attack.t1190", "attack.execution",
                              "attack.credential-access", "cve.2024-1234"]) == {"underscore": 1, "hyphen": 1}


def test_case_measures():
    row = {"rules_yaml": [R1, R2, R3], "pipeline": {"validation_issues": [
        {"severity": "warning", "message": "Invalid MITRE ATT&CK tagging (tag=attack.initial_access)"},
        {"severity": "error", "message": "Usage of invalid field name"}, "not a dict"]}}
    m = case_measures(row)
    assert (m["underscore"], m["hyphen"]) == (2, 2)
    assert m["example_id"] == 2
    assert m["duplicate_ids"] == 1
    assert m["tag_warnings"] == 1


def test_an_unreplaced_placeholder_id_is_counted():
    m = case_measures({"rules_yaml": ["title: x\nid: <new UUID>\n"]})
    assert m["placeholder_id"] == 1 and m["example_id"] == 0


def test_summary_adds_up_and_counts_cases():
    ms = [{"underscore": 2, "hyphen": 1, "example_id": 1, "duplicate_ids": 1, "placeholder_id": 0, "tag_warnings": 3},
          {"underscore": 0, "hyphen": 4, "example_id": 0, "duplicate_ids": 0, "placeholder_id": 0, "tag_warnings": 0}]
    s = summarise(ms)
    assert (s["underscore"], s["hyphen"], s["tag_warnings"]) == (2, 5, 3)
    assert (s["example_id_rules"], s["cases_with_duplicate_ids"], s["placeholder_id_rules"]) == (1, 1, 0)


def test_the_example_id_is_the_old_prompts():
    assert EXAMPLE_ID == "12345678-1234-1234-1234-123456789abc"
