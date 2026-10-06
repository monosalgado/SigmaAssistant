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


# --- the analysis stage's top log-source pick (Change 38, 2026-09-29) -----------------------

def _pick_row(rid, pick):
    row = _row(rid)
    row["pipeline"]["logsource_suggestions"] = [pick] if pick else []
    return row


def test_the_pick_is_scored_against_the_gold_and_the_other_human_rules():
    picks = {"x": ({"category": "proxy"}, [{"category": "dns"}])}           # (gold, other human rules)
    assert run_value(_pick_row("x", {"category": "proxy", "product": None}), "P", pick=picks["x"]) == 1.0
    assert run_value(_pick_row("x", {"category": "dns"}), "P", pick=picks["x"]) == 0.0
    assert run_value(_pick_row("x", {"category": "dns"}), "Pany", pick=picks["x"]) == 1.0
    assert run_value(_pick_row("x", None), "Pany", pick=picks["x"]) == 0.0      # no pick counts as wrong


def test_arms_are_compared_on_the_pick():
    picks = {"x": ({"category": "proxy"}, []), "y": ({"category": "dns"}, [])}
    a = [{"x": _pick_row("x", {"category": "process_creation"}), "y": _pick_row("y", {"category": "dns"})}]
    b = [{"x": _pick_row("x", {"category": "proxy"}), "y": _pick_row("y", {"category": "dns"})}]
    out = compare(a, b, "P", picks=picks)
    assert out["n"] == 2 and out["mean_a"] == 0.5 and out["mean_b"] == 1.0 and out["diff"] == 0.5


# --- S5v, the value-level detection score (Change 40's run, fixed before it; user 2026-10-03) ----------
# As S5: S5vu as the user gets it (a first rule that does not parse scores 0; undefined when the human rule
# has no values), S5v as the harness's convention (only rules that parse). The human rule is read from the
# row's `rule_path`; scored by `scorers.score_detection_values`.

def _valued_row(tmp_path, rid, ours, parses=True, gold_detection=None):
    gold = tmp_path / f"{rid}.yml"
    import yaml
    gold.write_text(yaml.safe_dump({"title": "g", "detection": gold_detection or
                                    {"selection": {"Image|endswith": "\\schtasks.exe",
                                                   "CommandLine|contains": "/create"},
                                     "condition": "selection"}}))
    rule = yaml.safe_dump({"title": "r", "logsource": {"category": "process_creation"},
                           "detection": {"selection": ours, "condition": "selection"}})
    return {"rule_id": rid, "rule_path": str(gold), "rules_yaml": [rule if parses else "title: [unclosed"],
            "scores": {"validity": {"parses": parses}}}


def test_s5v_scores_the_first_rules_values_against_the_human_rule(tmp_path):
    row = _valued_row(tmp_path, "a", {"Image|endswith": "\\schtasks.exe"})
    assert run_value(row, "S5vu") == pytest.approx(2 / 3)      # precision 1, recall 1/2
    assert run_value(row, "S5v") == pytest.approx(2 / 3)


def test_as_the_user_gets_it_an_unparsed_rule_scores_zero_on_values(tmp_path):
    row = _valued_row(tmp_path, "b", {}, parses=False)
    assert run_value(row, "S5vu") == 0.0 and run_value(row, "S5v") is None


def test_s5v_is_undefined_when_the_human_rule_has_no_values(tmp_path):
    row = _valued_row(tmp_path, "c", {"Image": "x.exe"}, gold_detection={"condition": "selection"})
    assert run_value(row, "S5vu") is None


def test_a_rule_with_no_values_scores_zero_as_the_user_gets_it(tmp_path):
    row = _valued_row(tmp_path, "d", {})
    assert run_value(row, "S5vu") == 0.0


def test_s5vu_is_a_primary_measure():
    from eval.compare_arms import PRIMARY, SECONDARY
    assert "S5vu" in PRIMARY and "S5v" in SECONDARY


# --- ATT&CK measures for Changes 42/43 (named in their run plan, 2026-10-05, before the run; added after the run,
# before any score was read) ----------------------------------------------------------------------------------------
# S4p: S4 by parent technique; S4prec: S4's exact precision (both the harness's convention: rules that parse).
# Tgold / Tgoldp: the analysis stage's technique list (`ttp_mappings`) holds a gold technique, exact / by parent
# (undefined when the gold rule names no technique). Tn: distinct techniques listed; T10: exactly 10 listed.

def _attack_row(tmp_path, rid, listed, gold_tags=("attack.t1059.001",), parses=True, attack=None):
    import yaml
    gold = tmp_path / f"{rid}.yml"
    gold.write_text(yaml.safe_dump({"title": "g", "tags": list(gold_tags), "detection": {"condition": "s"}}))
    scores = {"validity": {"parses": parses}}
    if parses:
        scores["attack"] = attack or {"exact": {"precision": 0.25, "f1": 0.4}, "parent": {"f1": 0.8}}
    return {"rule_id": rid, "rule_path": str(gold), "rules_yaml": ["title: r"], "scores": scores,
            "pipeline": {"ttp_mappings": [{"technique_id": t} for t in listed]}}


def test_s4_by_parent_and_s4_precision_follow_the_harness_convention(tmp_path):
    row = _attack_row(tmp_path, "a", [])
    assert run_value(row, "S4p") == 0.8 and run_value(row, "S4prec") == 0.25
    unparsed = _attack_row(tmp_path, "b", [], parses=False)
    assert run_value(unparsed, "S4p") is None and run_value(unparsed, "S4prec") is None


def test_the_analysis_lists_a_gold_technique_exact_or_by_parent(tmp_path):
    assert run_value(_attack_row(tmp_path, "a", ["T1105", " t1059.001 "]), "Tgold") == 1.0
    sibling = _attack_row(tmp_path, "b", ["T1059.003"])
    assert run_value(sibling, "Tgold") == 0.0 and run_value(sibling, "Tgoldp") == 1.0
    assert run_value(_attack_row(tmp_path, "c", ["T1105"]), "Tgoldp") == 0.0
    assert run_value(_attack_row(tmp_path, "d", []), "Tgold") == 0.0          # no analysis: nothing listed
    assert run_value(_attack_row(tmp_path, "e", ["T1105"], gold_tags=("attack.execution",)), "Tgold") is None


def test_techniques_listed_counts_distinct_ids_and_exactly_ten(tmp_path):
    ten = [f"T{1000 + i}" for i in range(10)]
    assert run_value(_attack_row(tmp_path, "a", ten), "Tn") == 10.0
    assert run_value(_attack_row(tmp_path, "a", ten), "T10") == 1.0
    assert run_value(_attack_row(tmp_path, "b", ten[:9] + ["t1000"]), "Tn") == 9.0   # a repeat counts once
    assert run_value(_attack_row(tmp_path, "b", ten[:9] + ["t1000"]), "T10") == 0.0
    assert run_value(_attack_row(tmp_path, "c", []), "Tn") == 0.0


def test_the_attack_measures_are_compared_paired(tmp_path):
    a = {"x": _attack_row(tmp_path, "x", ["T1105"]), "y": _attack_row(tmp_path, "y", ["T1105"])}
    b = {"x": _attack_row(tmp_path, "x", ["T1059.001"]), "y": _attack_row(tmp_path, "y", ["T1105"])}
    r = compare([a], [b], "Tgold")
    assert r["n"] == 2 and r["mean_a"] == 0.0 and r["mean_b"] == 0.5
    from eval.compare_arms import ATTACK
    assert set(ATTACK) == {"S4p", "S4prec", "Tgold", "Tgoldp", "Tn", "T10"}
