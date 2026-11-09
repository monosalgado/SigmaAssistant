"""Offline tests for S1r (Change 55 plan, log 2026-11-09): "the first rule runs" - pySigma loads it and every
condition parses - next to S1, which only loads it. Computed from the saved rules, so it applies to old runs too. Also:
the harness keeps review's reverts in each row."""

from __future__ import annotations

from eval.compare_arms import run_value
from eval.compare_runs import metric_value
from eval.run_eval import DIAGNOSIS_FIELDS
from eval.summarise import summarise

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


def _row(rules):
    return {"rules_yaml": rules, "scores": {"validity": {"parses": True}, "logsource": {"exact_match": True}}}


def test_s1r_is_whether_the_first_rule_runs():
    assert metric_value(_row([GOOD, SPACE]), "S1r") is True
    assert metric_value(_row([SPACE, GOOD]), "S1r") is False
    assert metric_value(_row([]), "S1r") is False
    assert metric_value({"scores": {}}, "S1r") is None


def test_compare_arms_reads_s1r_as_a_number():
    assert float(run_value(_row([GOOD]), "S1r")) == 1.0 and float(run_value(_row([SPACE]), "S1r")) == 0.0


def test_the_summary_reports_s1r_next_to_s1():
    s = summarise([_row([GOOD]), _row([SPACE])])
    assert s["validity_rate"] == 1.0 and s["s1r_rate"] == 0.5


def test_the_harness_keeps_reviews_reverts():
    assert "review_reverted" in DIAGNOSIS_FIELDS
