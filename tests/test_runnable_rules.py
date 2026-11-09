"""Offline tests for eval/runnable_rules.py (plan in the log 2026-11-09): how often our rules cannot run, before and
after review. A rule runs when pySigma loads it and every condition parses; S1 only loads it."""

from __future__ import annotations

from eval.runnable_rules import can_run, review_effect, run_summary

GOOD = """title: Good
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\\\\node.exe'
    selection_child:
        Image|endswith: '\\\\cmd.exe'
    condition: all of selection_*
"""
SPACE = GOOD.replace("all of selection_*", "all of selection_ *")
UNDEFINED = GOOD.replace("all of selection_*", "selection")


def test_a_good_rule_runs():
    assert can_run(GOOD) == {"loads": True, "runs": True, "error": None}


def test_a_condition_with_a_stray_space_loads_but_does_not_run():
    result = can_run(SPACE)
    assert result["loads"] is True and result["runs"] is False and "SigmaConditionError" in result["error"]


def test_a_condition_naming_a_selection_that_does_not_exist_does_not_run():
    result = can_run(UNDEFINED)
    assert result["loads"] is True and result["runs"] is False and "not defined" in result["error"]


def test_text_that_is_not_a_rule_neither_loads_nor_runs():
    assert can_run("title: [unclosed") ["loads"] is False and can_run("")["runs"] is False


def test_code_fences_are_stripped_as_s1_does():
    assert can_run("```yaml\n" + GOOD + "```")["runs"] is True


def test_review_breaks_and_fixes_are_counted_by_position_when_the_count_is_kept():
    effect = review_effect([GOOD, GOOD, SPACE], [SPACE, GOOD, GOOD])
    assert effect == {"same_count": True, "broken": [1], "fixed": [3]}


def test_when_review_changes_the_number_of_rules_positions_are_not_compared():
    assert review_effect([GOOD, GOOD], [GOOD]) == {"same_count": False, "broken": None, "fixed": None}


def _row(rules, pre=None, parses=True, s3=False, product="windows"):
    row = {"rule_id": "x", "product": product, "rules_yaml": rules,
           "scores": {"validity": {"parses": parses}, "logsource": {"exact_match": s3}}, "pipeline": {}}
    if pre is not None:
        row["pipeline"]["pre_review_rules"] = pre
    return row


def test_the_summary_counts_first_rules_s1_calls_valid_that_cannot_run():
    rows = [_row([GOOD, SPACE], pre=[GOOD, GOOD], s3=True), _row([SPACE, GOOD], pre=[GOOD, GOOD], s3=True),
            _row([GOOD]), _row(["title: [unclosed"], parses=False)]
    s = run_summary(rows)
    assert s["cases"] == 4 and s["rules"] == 6 and s["rules_cannot_run"] == 3
    assert s["s1"] == 3 / 4 and s["s1_corrected"] == 2 / 4
    assert s["first_valid_but_cannot_run"] == 1 and s["first_cannot_run_but_s3_right"] == 1
    assert s["cases_with_before_review"] == 2 and s["before_rules"] == 4 and s["before_cannot_run"] == 0
    assert s["broken_by_review"] == 2 and s["fixed_by_review"] == 0 and s["review_changed_count"] == 0


def test_a_run_without_rules_before_review_has_no_review_counts():
    s = run_summary([_row([GOOD])])
    assert s["cases_with_before_review"] == 0 and s["broken_by_review"] is None
