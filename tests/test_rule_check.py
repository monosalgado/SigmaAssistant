"""Tests for Change 47: the analyst edits a rule's YAML and it is checked on every edit (user 2026-10-07: "do the YAML
editing with instant validation"; design decision 3: "pySigma validation itself is automatic on every edit").

`check_rule` is the pipeline's own deterministic validation (pySigma parse, condition resolution, the core validators -
`stage_review.validate_rule_text`, shared with `ReviewStage._validate_rule`) plus one warning: a log source no SigmaHQ
rule uses. No model call; nothing in the rule is changed. Offline.
"""

from __future__ import annotations

from backend.pipeline.stage_review import ReviewStage, validate_rule_text
from backend.rule_check import check_rule

RULE = """title: Encoded PowerShell
id: 5e3d3601-0000-4000-8000-000000000000
status: experimental
description: PowerShell with an encoded command.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: ' -enc '
    condition: selection
level: medium
"""


def test_a_valid_rule_passes_with_its_title_and_log_source():
    out = check_rule(RULE)
    assert out["valid"] is True and out["errors"] == 0
    assert out["title"] == "Encoded PowerShell"
    assert out["logsource"] == {"category": "process_creation", "product": "windows"}


def test_broken_yaml_is_an_error():
    out = check_rule(RULE.replace("    selection:\n", "    selection:\n  - [\n"))
    assert out["valid"] is False and any("YAML" in i["message"] for i in out["issues"])


def test_a_condition_naming_an_undefined_selection_is_an_error():
    out = check_rule(RULE.replace("condition: selection", "condition: selection and filter"))
    assert out["valid"] is False
    assert any(i["severity"] == "error" and "condition" in i["message"].lower() for i in out["issues"])


def test_a_log_source_no_sigmahq_rule_uses_is_a_warning_not_an_error():
    out = check_rule(RULE.replace("category: process_creation", "category: process_creaton"))
    warnings = [i for i in out["issues"] if i["severity"] == "warning" and "SigmaHQ" in i["message"]]
    assert out["valid"] is True and len(warnings) == 1 and "process_creaton" in warnings[0]["message"]
    assert not any("SigmaHQ" in i["message"] for i in check_rule(RULE)["issues"])


def test_empty_text_is_an_error():
    out = check_rule("")
    assert out["valid"] is False and out["errors"] >= 1


def test_the_editor_and_the_pipeline_share_one_validation():
    for text in (RULE, RULE.replace("condition: selection", "condition: nope"), "not: [yaml"):
        assert validate_rule_text(text, "rule[0]") == ReviewStage(None, "")._validate_rule(text, 0)
