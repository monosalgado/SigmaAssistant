"""Offline tests for eval/compare_runs.py — paired comparison of two runs.

The v1 -> v2 numbers in the engineering log came from a scratch script
(scipy/numpy). This committed version uses the standard library only and must
reproduce them from the committed result files.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from eval.compare_runs import (
    bootstrap_ci,
    compare,
    load,
    mcnemar,
    metric_value,
    paired,
    percentile,
)

REPO = Path(__file__).resolve().parent.parent


# --- exact McNemar -------------------------------------------------------

@pytest.mark.parametrize("only_a, only_b, p", [
    (3, 5, 0.7265625),      # S1, v1 -> v2
    (5, 2, 0.453125),       # S3, v1 -> v2
    (8, 1, 0.0390625),      # defect-15 copying, Change 12 (logged p = 0.039)
    (0, 0, 1.0),            # no discordant pairs
    (2, 2, 1.0),            # symmetric: capped at 1
])
def test_exact_mcnemar_matches_the_logged_values(only_a, only_b, p):
    pairs = [(True, False)] * only_a + [(False, True)] * only_b + [(True, True)] * 4
    result = mcnemar(pairs)
    assert result["only_a"] == only_a and result["only_b"] == only_b
    assert result["p"] == pytest.approx(p, abs=1e-12)


# --- bootstrap -----------------------------------------------------------

def test_percentile_interpolates_linearly_like_numpy():
    assert percentile([1, 2, 3, 4], 50) == 2.5
    assert percentile([1, 2, 3, 4], 0) == 1 and percentile([1, 2, 3, 4], 100) == 4
    assert percentile([10, 20, 30, 40, 50], 2.5) == pytest.approx(11.0)


def test_bootstrap_is_reproducible_and_brackets_the_mean():
    diffs = [0.0, 0.5, -0.2, 0.1, 0.0, 0.3, -0.1, 0.0]
    first = bootstrap_ci(diffs, resamples=2000, seed=0)
    assert first == bootstrap_ci(diffs, resamples=2000, seed=0)
    assert first[0] <= sum(diffs) / len(diffs) <= first[1]


def test_bootstrap_of_no_differences_is_zero():
    assert bootstrap_ci([0.0] * 10, resamples=500, seed=0) == (0.0, 0.0)


# --- what gets paired ----------------------------------------------------

def _row(rid, parses, exact=None, f1=None, tokens=100, seconds=10.0, rules=1):
    scores = {"validity": {"parses": parses}}
    if parses:
        scores["logsource"] = {"exact_match": exact}
        scores["attack"] = {"exact": {"f1": f1}}
        scores["detection_fields"] = {"f1": f1}
    return {"rule_id": rid, "scores": scores, "telemetry": {"total_tokens": tokens},
            "elapsed_s": seconds, "n_rules": rules}


def test_content_metrics_only_on_rules_that_parse():
    assert metric_value(_row("a", parses=False), "S3") is None
    assert metric_value(_row("a", parses=False), "S1") is False
    assert metric_value(_row("a", parses=True, exact=True), "S3") is True
    assert metric_value(_row("a", parses=True, f1=None), "S4") is None


def test_only_cases_scored_in_both_runs_are_paired():
    a = {"x": _row("x", True, exact=True), "y": _row("y", False), "z": _row("z", True, exact=False)}
    b = {"x": _row("x", True, exact=False), "y": _row("y", True, exact=True), "w": _row("w", True)}
    assert paired(a, b, "S3") == [(True, False)]          # y unscored in a; z, w not in both
    assert paired(a, b, "S1") == [(True, True), (False, True)]


# --- the logged v1 -> v2 comparison, reproduced ---------------------------

def test_reproduces_the_logged_baseline_v1_to_v2_comparison():
    a = load(REPO / "eval/results/baseline60.jsonl")
    b = load(REPO / "eval/results/baseline60_v2.jsonl")
    r = compare(a, b)
    assert r["matched"] == 60
    s1, s3 = r["S1"], r["S3"]
    assert (s1["n"], s1["a_true"], s1["b_true"], s1["only_a"], s1["only_b"]) == (60, 55, 57, 3, 5)
    assert s1["p"] == pytest.approx(0.727, abs=5e-4)
    assert (s3["n"], s3["a_true"], s3["b_true"], s3["only_a"], s3["only_b"]) == (52, 8, 5, 5, 2)
    assert s3["p"] == pytest.approx(0.453, abs=5e-4)
    s4, s5 = r["S4"], r["S5"]
    assert s4["n"] == 35 and round(s4["mean_a"], 3) == 0.119 and round(s4["mean_b"], 3) == 0.133
    assert (s4["better"], s4["worse"], s4["same"]) == (2, 2, 31)
    assert s5["n"] == 51 and round(s5["mean_a"], 3) == 0.200 and round(s5["mean_b"], 3) == 0.203
    assert (s5["better"], s5["worse"], s5["same"]) == (8, 5, 38)
    assert r["tokens"]["n"] == 60 and round(r["tokens"]["diff"]) == 16676
    assert round(r["seconds"]["diff"], 1) == 66.7
    assert round(r["rules"]["diff"], 2) == 0.88
    # the intervals: same method, different random generator than the scratch script,
    # so they agree with the logged ones only approximately
    assert r["S4"]["ci"][0] < 0 < r["S4"]["ci"][1]
    assert r["tokens"]["ci"][0] > 0
