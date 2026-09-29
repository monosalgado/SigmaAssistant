"""Tests for comparing two versions of the pipeline run k times each on the same cases (the May
code vs `main`, user 2026-09-28: "rerun the may code on the same saved pages, several times each").

Offline. Each case's value in an arm is the mean over that arm's k runs; the arms are compared
case by case (paired). Two views of S3/S5, fixed before the runs:
- as the user gets it (primary): a first rule that does not parse is a wrong rule - S3 0, S5 0
  (S5 stays undefined for a case whose gold rule names no fields);
- the harness's convention (secondary, as `compare_runs.py`): defined only when the rule parses.
Consistency: whether an arm's k runs chose the same first-rule log source for a case.
"""

from __future__ import annotations

import pytest

from eval.compare_arms import (
    case_means, compare, consistency, run_value, stage_differences_within,
)


def _row(rid, parses=True, exact=True, f1=0.5, n_gold=2, logsource=None, telemetry=None, suggestion=None):
    rule = ("title: r\nlogsource:\n" + "".join(f"    {k}: {v}\n" for k, v in (logsource or {"category": "c"}).items())
            + "detection:\n    s:\n        a: b\n    condition: s\n")
    scores = {"validity": {"parses": parses}}
    if parses:
        scores["logsource"] = {"exact_match": exact}
        scores["detection_fields"] = {"f1": f1, "n_gold": n_gold}
    return {"rule_id": rid, "rules_yaml": [rule], "scores": scores,
            "pipeline": {"attack_vector": {"primary_telemetry": telemetry},
                         "logsource_suggestions": [suggestion] if suggestion else []}}


# --- one run's value ----------------------------------------------------------------------

def test_as_the_user_gets_it_a_rule_that_does_not_parse_is_wrong():
    assert run_value(_row("x", exact=True), "S3u") == 1.0
    assert run_value(_row("x", exact=False), "S3u") == 0.0
    assert run_value(_row("x", parses=False), "S3u") == 0.0
    assert run_value(_row("x", f1=0.5), "S5u", gold_has_fields=True) == 0.5
    assert run_value(_row("x", parses=False), "S5u", gold_has_fields=True) == 0.0
    # The rule names no field while the gold does: F1 is None in the scorer, 0 for the user.
    assert run_value(_row("x", f1=None, n_gold=2), "S5u", gold_has_fields=True) == 0.0
    assert run_value(_row("x", parses=False), "S5u", gold_has_fields=False) is None


def test_the_harness_convention_leaves_out_a_rule_that_does_not_parse():
    assert run_value(_row("x", parses=False), "S3") is None
    assert run_value(_row("x", exact=True), "S3") is True
    assert run_value(_row("x", parses=False), "S1") is False


# --- a case's value in an arm: the mean over its k runs -----------------------------------

def test_a_cases_value_is_the_mean_over_the_arms_runs():
    runs = [{"a": _row("a", exact=True)}, {"a": _row("a", exact=False)}, {"a": _row("a", parses=False)}]
    assert case_means(runs, "S3u")["a"] == pytest.approx(1 / 3)
    assert case_means(runs, "S3")["a"] == pytest.approx(1 / 2)       # the unparsed run left out


def test_whether_the_gold_names_fields_comes_from_any_run_that_parsed():
    runs = [{"a": _row("a", parses=False)}, {"a": _row("a", f1=1.0, n_gold=3)}]
    assert case_means(runs, "S5u")["a"] == pytest.approx(0.5)
    no_fields = [{"a": _row("a", parses=False)}, {"a": _row("a", f1=None, n_gold=0)}]
    assert "a" not in case_means(no_fields, "S5u")


# --- the paired comparison ----------------------------------------------------------------

def test_arms_are_compared_on_the_cases_every_run_of_both_arms_has():
    a = [{"x": _row("x", exact=False), "y": _row("y", exact=False)}, {"x": _row("x", exact=False)}]
    b = [{"x": _row("x", exact=True), "y": _row("y", exact=True)}, {"x": _row("x", exact=True)}]
    out = compare(a, b, "S3u")
    assert out["n"] == 1 and out["excluded"] == ["y"]          # y is missing from a run
    assert out["mean_a"] == 0.0 and out["mean_b"] == 1.0 and out["diff"] == 1.0
    assert out["ci"] == (1.0, 1.0)


# --- consistency --------------------------------------------------------------------------

def test_consistency_is_the_same_first_rule_log_source_in_every_run():
    lin = {"category": "process_creation", "product": "linux"}
    win = {"category": "process_creation", "product": "windows"}
    runs = [{"x": _row("x", logsource=lin), "y": _row("y", logsource=lin)},
            {"x": _row("x", logsource=lin), "y": _row("y", logsource=win)},
            {"x": _row("x", logsource=lin), "y": _row("y", logsource=lin)}]
    out = consistency(runs)
    assert out["same_in_all"] == {"x": True, "y": False}
    assert out["distinct"] == {"x": 1, "y": 2}


def test_stage_differences_are_averaged_over_every_pair_of_runs():
    runs = [{"x": _row("x", telemetry="file_event")}, {"x": _row("x", telemetry="file_event")},
            {"x": _row("x", telemetry="registry_event")}]
    out = stage_differences_within(runs)
    # pairs (1,2), (1,3), (2,3): the attack vector differs in 2 of 3
    assert out["pairs"] == 3 and out["attack vector"] == pytest.approx(2 / 3)


# --- the contamination-flagged cases, listed apart (pre-registered, descriptive) ---------

def test_the_flagged_cases_are_listed_with_each_arms_values():
    from eval.compare_arms import flagged_rows
    a = [{"x": dict(_row("x", exact=False), contamination={"flagged": True}), "y": _row("y")}]
    b = [{"x": dict(_row("x", exact=True), contamination={"flagged": True}), "y": _row("y")}]
    rows = flagged_rows(a, b)
    assert [r["rule_id"] for r in rows] == ["x"]
    assert rows[0]["S3u"] == (0.0, 1.0)
    assert rows[0]["same_in_all"] == (True, True)


def test_a_p_value_is_printed_with_two_significant_figures():
    from eval.compare_arms import fmt_p
    assert fmt_p(1.0928604751825333e-05) == "1.1e-05"
    assert fmt_p(0.0391) == "0.039"
    assert fmt_p(1.0) == "1"
