"""Tests for recording which of the analysis's indicators the rules use (Change 40, user 2026-10-03:
"Prompt + record").

Why: on the tuning set, the report values the rule writer had and did not use were mostly offered as the
analysis's indicators, while the payload signatures are used (log 2026-10-03, detection step 2). Code only
records; it does not change the rules. The same function measures runs of earlier code from their saved rows.

An indicator is used when one of a rule's detection values contains it, or is contained in it and is at least
half as long (as S5v matches values); values are compared lower-cased, `*` at the ends removed, a doubled
backslash read as one; an indicator shorter than 3 characters is not judged. Offline; no LLM.
"""

from __future__ import annotations

from backend.pipeline.indicator_use import indicator_use

RULE = """title: t
logsource: {category: process_creation, product: windows}
detection:
  selection:
    Image|endswith: '\\\\schtasks.exe'
    CommandLine|contains: '\\\\Temp\\\\evil.dll'
  condition: selection
"""


def _ind(value, type_="process"):
    return {"value": value, "type": type_, "context": "c"}


def test_an_indicator_a_rule_matches_on_is_used():
    use = indicator_use([_ind("schtasks.exe"), _ind("C:\\Windows\\Temp\\evil.dll", "file_path")], [RULE])
    assert use["used"] == ["schtasks.exe", "C:\\Windows\\Temp\\evil.dll"] and use["unused"] == []


def test_an_indicator_no_rule_matches_on_is_unused():
    use = indicator_use([_ind("CVE-2024-1234", "cve"), _ind("schtasks.exe")], [RULE])
    assert use == {"given": 2, "used": ["schtasks.exe"], "unused": ["CVE-2024-1234"]}


def test_a_much_shorter_rule_value_does_not_use_a_long_indicator():
    rule = "title: t\ndetection:\n  selection:\n    CommandLine|contains: 'reg'\n  condition: selection\n"
    assert indicator_use([_ind("reg.exe save hklm\\sam %temp%\\~reg_sam.save", "command_line")], [rule])["used"] == []


def test_a_very_short_indicator_is_not_judged_and_a_broken_rule_adds_nothing():
    use = indicator_use([_ind("1", "port"), _ind("schtasks.exe")], ["title: [unclosed", RULE])
    assert use == {"given": 1, "used": ["schtasks.exe"], "unused": []}


def test_no_indicators_or_no_rules():
    assert indicator_use([], [RULE]) == {"given": 0, "used": [], "unused": []}
    assert indicator_use([_ind("schtasks.exe")], []) == {"given": 1, "used": [], "unused": ["schtasks.exe"]}


def test_an_indicator_only_in_an_exclusion_is_not_used():
    rule = ("title: t\ndetection:\n  selection:\n    Image|endswith: '\\\\cmd.exe'\n"
            "  filter_main:\n    ParentImage|endswith: '\\\\explorer.exe'\n  condition: selection and not filter_main\n")
    assert indicator_use([_ind("explorer.exe"), _ind("cmd.exe")], [rule])["used"] == ["cmd.exe"]
