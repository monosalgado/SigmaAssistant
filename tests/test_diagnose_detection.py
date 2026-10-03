"""Tests for the detection diagnosis (user 2026-10-03: "do 1 and 2"): per case, what the first rule's detection
gets right and wrong against the human rule - fields missed and added (S5), values found and missed (S5v),
whether a later rule of the same case does better, and which values occur in the report's own text.

Why: S5 is 0.63-0.69 when the log source is right and 0.04-0.12 when it is wrong (held-out runs,
`s5_by_logsource.py`), so detection is diagnosed where the log source is right. Offline; no LLM.
"""

from __future__ import annotations

from eval.diagnose_detection import case_detection, grounded, summarise

GOLD = {"logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"selection": {"Image|endswith": "\\schtasks.exe",
                                    "CommandLine|contains|all": ["create", "ONSTART"]},
                      "condition": "selection"}}


def _rule(category, detection):
    import yaml
    return yaml.safe_dump({"title": "t", "logsource": {"category": category, "product": "windows"},
                           "detection": detection})


FIRST_WEAK = _rule("process_creation", {"selection": {"CommandLine|contains": "dropper"}, "condition": "selection"})
LATER_GOOD = _rule("process_creation", {"selection": {"Image|endswith": "\\schtasks.exe",
                                                      "CommandLine|contains": "/create"}, "condition": "selection"})


def _row(rules, s3=True):
    return {"rule_id": "a", "rules_yaml": rules,
            "scores": {"logsource": {"exact_match": s3}, "detection_fields": {}}}


def test_the_first_rule_is_diagnosed_against_the_human_rule():
    d = case_detection(_row([FIRST_WEAK, LATER_GOOD]), GOLD)
    assert d["s3_right"] is True and d["parses"] is True
    assert d["fields_missing"] == ["image"] and d["fields_extra"] == []
    assert d["s5"] == 2 / 3                                    # 1 of 1 ours right, 1 of 2 theirs found
    assert d["s5v"] == 0.0 and d["values_missing"] == ["\\schtasks.exe", "create", "onstart"]


def test_a_later_rule_of_the_same_case_can_do_better():
    d = case_detection(_row([FIRST_WEAK, LATER_GOOD]), GOLD)
    assert d["best_s5v_rule"] == 1 and d["best_s5v"] > d["s5v"]
    assert d["best_s5_rule"] == 1 and d["best_s5"] == 1.0


def test_a_rule_that_does_not_parse_is_reported_as_such():
    d = case_detection(_row(["title: [unclosed"]), GOLD)
    assert d["parses"] is False and d["s5"] is None and d["s5v"] is None


def test_a_value_is_grounded_when_the_report_contains_it():
    text = "The actor ran schtasks.exe /create /sc ONSTART to persist."
    assert grounded("\\schtasks.exe", text) is True              # a leading path separator is not required
    assert grounded("$(nslookup", text) is False
    assert grounded(";", text) is None                           # too short to judge


def test_grounding_is_recorded_for_ours_and_for_the_humans_values():
    text = "The actor ran schtasks.exe /create /sc ONSTART."
    d = case_detection(_row([FIRST_WEAK]), GOLD, text=text)
    assert d["ours_ungrounded"] == ["dropper"] and d["ours_grounded"] == 0
    assert d["gold_grounded"] == 3 and d["gold_judged"] == 3


def test_the_summary_splits_by_whether_the_log_source_is_right():
    rows = [case_detection(_row([LATER_GOOD]), GOLD), case_detection(_row([FIRST_WEAK], s3=False), GOLD)]
    s = summarise(rows)
    assert s["cases"] == 2 and s["right"]["cases"] == 1 and s["wrong"]["cases"] == 1
    assert s["right"]["s5v"] == rows[0]["s5v"] and s["wrong"]["s5v"] == 0.0
    assert s["right"]["fields_missing"] == {} and s["wrong"]["fields_missing"] == {"image": 1}


def test_of_the_humans_values_in_the_report_the_ones_we_used_are_counted():
    text = "The actor ran schtasks.exe /create /sc ONSTART."
    assert case_detection(_row([FIRST_WEAK]), GOLD, text=text)["gold_grounded_found"] == 0
    assert case_detection(_row([LATER_GOOD]), GOLD, text=text)["gold_grounded_found"] == 2
    s = summarise([case_detection(_row([LATER_GOOD]), GOLD, text=text)])
    assert s["right"]["gold_grounded_found"] == (2, 3)
