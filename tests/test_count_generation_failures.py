"""Tests for the measure of Change 36 (defect 5): generation answers that could not be read.

Offline: reads result rows only.

Two counts. (1) Cases left with no rule because generation's answer could not be read: zero
rules and "Generation error" in the kept response - computable for every run, old and new.
(2) Generation calls whose answer could not be read, retried or not: `parse_error` in the
row's generation log - recorded from Change 36 on; older runs have no such field and are
reported as not recorded, never as zero.
"""

from __future__ import annotations

from eval.count_generation_failures import count_failures


def _row(rule_id, n_rules, response=None, generations=None):
    row = {"rule_id": rule_id, "n_rules": n_rules, "error": None,
           "pipeline": {"generations": generations or []}}
    if response is not None:
        row["response_text"] = response
    return row


OLD = [
    _row("a", 0, "Generation error: Invalid \\escape: line 4 column 514",
         [{"rules": 0, "ids_replaced": 0}, {"rules": 0, "ids_replaced": 0}]),
    _row("b", 0, "I was unable to generate a rule.", [{"rules": 0, "ids_replaced": 0}]),
    _row("c", 3, None, [{"rules": 3, "ids_replaced": 1}]),
]
NEW = [
    _row("a", 2, None, [{"rules": 0, "ids_replaced": 0, "parse_error": "no ```yaml block"},
                        {"rules": 2, "ids_replaced": 0, "parse_error": None}]),
    _row("b", 0, "Generation error: no ```yaml block with a rule in the answer",
         [{"rules": 0, "ids_replaced": 0, "parse_error": "no ```yaml block"}]),
    _row("c", 3, None, [{"rules": 3, "ids_replaced": 0, "parse_error": None}]),
]


def test_cases_lost_to_an_unreadable_answer_are_counted_in_any_run():
    assert count_failures(OLD)["cases_without_rules_unreadable"] == ["a"]
    assert count_failures(NEW)["cases_without_rules_unreadable"] == ["b"]


def test_a_case_with_no_rules_for_another_reason_is_not_counted():
    assert "b" not in count_failures(OLD)["cases_without_rules_unreadable"]


def test_unreadable_calls_are_counted_where_recorded():
    out = count_failures(NEW)
    assert out["calls_unreadable"] == 2 and out["calls"] == 4
    assert out["cases_with_an_unreadable_call"] == ["a", "b"]


def test_older_runs_say_not_recorded_rather_than_zero():
    out = count_failures(OLD)
    assert out["calls_unreadable"] is None and out["cases_with_an_unreadable_call"] is None
    assert out["calls"] == 4


def test_crashed_rows_are_left_out():
    rows = OLD + [{"rule_id": "d", "n_rules": 0, "error": "ValueError: boom", "scores": None}]
    assert count_failures(rows)["cases"] == 3
