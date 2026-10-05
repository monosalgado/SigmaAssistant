"""Tests for validating the synthetic replay before it scores any of our rules (R9.2; thresholds fixed in the log
2026-10-05): V1 each rule fires on its own built events (>= 95% of buildable rules); V2 synthetic vs real on SigmaHQ's
recordings (false fires on real non-pairs <= 1%; the related-pair hit reported); V3 unrelated gold rules fire on
<= 2% of pairs; V4 today - May replay hit, 95% CI above 0; V5 a shuffled-rules null <= 5% and below the real hit.
Offline; made-up data.
"""

from __future__ import annotations

from eval.validate_replay import THRESHOLDS, derangement, pair_counts, verdicts


def test_the_null_shuffle_moves_every_case_and_is_fixed():
    ids = [f"c{i}" for i in range(10)]
    d = derangement(ids, seed=0)
    assert sorted(d) == sorted(ids) and all(d[k] != k for k in d)
    assert derangement(ids, seed=0) == d


def test_pairs_are_counted_against_the_real_recordings():
    real = {("x", "x"), ("y", "y"), ("x", "y")}                 # x also fires on y's real recording
    synthetic = {("x", "x"), ("y", "y"), ("y", "x")}            # misses (x, y); a false fire on (y, x)
    c = pair_counts(["x", "y"], ["x", "y"], real, synthetic)
    assert c["related_pairs"] == 1 and c["related_caught"] == 0
    assert c["real_non_pairs"] == 1 and c["false_fires"] == 1
    assert c["self_pairs"] == 2 and c["self_caught"] == 2


def test_the_verdicts_use_the_thresholds_fixed_in_the_log():
    assert THRESHOLDS == {"V1": 0.95, "V2": 0.01, "V3": 0.02, "V5": 0.05}
    good = {"V1": 0.97, "V2": 0.004, "V3": 0.01, "V4_ci_low": 0.05, "V5": 0.02, "V5_real": 0.40}
    assert all(verdicts(good).values())
    bad = dict(good, V2=0.02, V4_ci_low=-0.01)
    v = verdicts(bad)
    assert v["V2"] is False and v["V4"] is False and v["V1"] and v["V3"] and v["V5"]
    assert verdicts(dict(good, V5=0.03, V5_real=0.04))["V5"] is False      # not far below the real hit
