"""Offline tests for the one-sample test of S3 against chance (plan: before Phase 2's exit).

Pre-registered use (2026-09-26): exact binomial, ONE-sided ("is S3 above the chance
level 0.173?"), alpha 0.05, applied once, to the final Phase 2 run; values on earlier
runs are descriptive. Standard library only. Anchors were computed once with scipy
(`binomtest(..., alternative="greater")`, Wilson interval) and are hard-coded here.
"""

from __future__ import annotations

import pytest

from eval.summarise import binom_p_above, min_k_above, summarise, wilson_ci


@pytest.mark.parametrize("k, n, p0, expected", [
    (8, 10, 0.5, 56 / 1024),      # exact, checkable by hand
    (14, 57, 0.173, 0.104493),    # S3 after Change 26
    (8, 55, 0.173, 0.757595),     # baseline v1
    (20, 57, 0.173, 0.000960),
])
def test_one_sided_exact_binomial_matches_scipy(k, n, p0, expected):
    assert binom_p_above(k, n, p0) == pytest.approx(expected, abs=1e-6)  # anchors rounded to 6 dp


def test_edges():
    assert binom_p_above(0, 10, 0.2) == pytest.approx(1.0)
    assert binom_p_above(10, 10, 0.5) == pytest.approx(1 / 1024)


@pytest.mark.parametrize("k, n, low, high", [
    (8, 10, 0.490162, 0.943318),
    (14, 57, 0.152328, 0.371023),
    (8, 55, 0.075593, 0.261609),  # the interval the Chapter 6 notes cite for baseline v1
])
def test_wilson_interval_matches_scipy(k, n, low, high):
    lo, hi = wilson_ci(k, n)
    assert lo == pytest.approx(low, abs=1e-6) and hi == pytest.approx(high, abs=1e-6)


def test_smallest_count_that_would_be_above_chance():
    k = min_k_above(57, 0.173, 0.05)
    assert binom_p_above(k, 57, 0.173) < 0.05 <= binom_p_above(k - 1, 57, 0.173)


def test_the_summary_carries_the_test_for_s3():
    rows = [{"scores": {"validity": {"parses": True, "issue_count": 0},
                        "logsource": {"exact_match": i < 3},
                        "attack": None, "detection_fields": None},
             "telemetry": {}, "elapsed_s": 100.0} for i in range(10)]
    s = summarise(rows)
    assert s["n_logsource"] == 10 and s["logsource_k"] == 3
    assert s["logsource_p_above_chance"] == pytest.approx(binom_p_above(3, 10, 0.173))
    assert s["logsource_ci"] == pytest.approx(wilson_ci(3, 10))
