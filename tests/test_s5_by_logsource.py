"""Tests for S5 split by what happened to the log source (S3), case by case, between two runs.

Offline. Written for the simulated-analyst result (plan 5.3): is the detection-field gain
only the cases whose log source became right? Uses `compare_runs.metric_value`, so the cases
and values are exactly those the paired comparison uses.
"""

from __future__ import annotations

from eval.s5_by_logsource import split_s5


def _row(rid, s3, s5, parses=True):
    return {"rule_id": rid, "scores": {"validity": {"parses": parses},
                                        "logsource": {"exact_match": s3},
                                        "detection_fields": {"f1": s5}}}


A = {r["rule_id"]: r for r in [_row("a", False, 0.0), _row("b", True, 0.5), _row("c", False, 0.2),
                               _row("d", True, 0.6), _row("e", False, 0.1, parses=False)]}
B = {r["rule_id"]: r for r in [_row("a", True, 0.8), _row("b", True, 0.5), _row("c", False, 0.4),
                               _row("d", False, 0.2), _row("e", True, 0.9)]}


def test_cases_are_grouped_by_the_log_source_in_each_run():
    groups = split_s5(A, B)
    assert groups["became right"]["cases"] == ["a"]
    assert groups["right in both"]["cases"] == ["b"]
    assert groups["wrong in both"]["cases"] == ["c"]
    assert groups["became wrong"]["cases"] == ["d"]


def test_each_group_reports_its_mean_s5_in_both_runs():
    groups = split_s5(A, B)
    assert groups["became right"]["mean_a"] == 0.0 and groups["became right"]["mean_b"] == 0.8
    assert round(groups["wrong in both"]["mean_b"] - groups["wrong in both"]["mean_a"], 3) == 0.2


def test_a_case_without_a_parsed_first_rule_in_either_run_is_left_out():
    groups = split_s5(A, B)
    assert all("e" not in g["cases"] for g in groups.values())
