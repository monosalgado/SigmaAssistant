"""Tests for listing, case by case, where two runs disagree (professor's question, 2026-09-28:
why does the assistant write a good rule one time and a wrong one another?).

Offline. Uses `compare_runs.metric_value`, so the values are those the paired comparison
scores; adds each run's first-rule log source so a disagreement can be read.
"""

from __future__ import annotations

from eval.list_disagreements import disagreements


def _row(rid, s1, s3=None, s5=None, logsource=None, title="t"):
    rule = "title: r\nlogsource:\n" + "".join(f"    {k}: {v}\n" for k, v in (logsource or {}).items()) + \
           "detection:\n    s:\n        a: b\n    condition: s\n"
    return {"rule_id": rid, "title": title, "category": "c", "rules_yaml": [rule] if s1 else [],
            "scores": {"validity": {"parses": s1}, "logsource": {"exact_match": s3},
                       "detection_fields": {"f1": s5}}}


A = {r["rule_id"]: r for r in [
    _row("same", True, True, 0.5, {"category": "webserver"}),
    _row("s3", True, False, 0.0, {"category": "process_creation", "product": "windows"}),
    _row("s5", True, True, 0.2, {"category": "webserver"}),
    _row("s1", False),
]}
B = {r["rule_id"]: r for r in [
    _row("same", True, True, 0.5, {"category": "webserver"}),
    _row("s3", True, True, 1.0, {"category": "process_creation", "product": "linux"}),
    _row("s5", True, True, 0.9, {"category": "webserver"}),
    _row("s1", True, True, 1.0, {"category": "webserver"}),
]}


def test_cases_that_agree_are_not_listed():
    assert "same" not in [d["rule_id"] for d in disagreements(A, B)]


def test_a_flip_in_s1_or_s3_is_listed_before_an_s5_difference():
    rows = disagreements(A, B, s5_gap=0.5)
    assert [d["rule_id"] for d in rows] == ["s1", "s3", "s5"]


def test_each_row_says_what_differed_and_where_each_first_rule_looked():
    s3 = next(d for d in disagreements(A, B) if d["rule_id"] == "s3")
    assert s3["S3"] == (False, True)
    assert s3["logsource"] == ("process_creation/windows", "process_creation/linux")
    assert s3["S5"] == (0.0, 1.0)


def test_an_s5_difference_below_the_gap_is_not_listed():
    assert "s5" not in [d["rule_id"] for d in disagreements(A, B, s5_gap=0.8)]


def _with_stages(row, telemetry, suggestion):
    row = dict(row)
    row["pipeline"] = {"attack_vector": {"primary_telemetry": telemetry},
                       "logsource_suggestions": [suggestion] if suggestion else []}
    return row


def test_the_first_stage_where_two_runs_diverge_is_named():
    # The attack-vector stage runs first, then the analysis (its log-source suggestion),
    # then the rule writer (the first rule's log source).
    win = {"category": "process_creation", "product": "windows"}
    lin = {"category": "process_creation", "product": "linux"}
    a = {"x": _with_stages(A["s3"], "process_creation", win),
         "y": _with_stages(A["s3"], "process_creation", win),
         "z": _with_stages(A["s3"], "process_creation", win)}
    b = {"x": _with_stages(B["s3"], "auth_log", lin),
         "y": _with_stages(B["s3"], "process_creation", lin),
         "z": _with_stages(B["s3"], "process_creation", win)}
    for rid in a:
        a[rid]["rule_id"] = b[rid]["rule_id"] = rid
    stages = {d["rule_id"]: d["diverged_at"] for d in disagreements(a, b)}
    assert stages == {"x": "attack vector", "y": "analysis", "z": "rule writer"}


def test_how_often_each_stage_concludes_differently_over_all_paired_cases():
    from eval.list_disagreements import stage_differences
    win = {"category": "process_creation", "product": "windows"}
    lin = {"category": "process_creation", "product": "linux"}
    a = {"x": _with_stages(A["same"], "process_creation", win), "y": _with_stages(A["same"], "file_event", win)}
    b = {"x": _with_stages(B["same"], "process_creation", win), "y": _with_stages(B["same"], "registry_event", lin)}
    for rid in a:
        a[rid]["rule_id"] = b[rid]["rule_id"] = rid
    out = stage_differences(a, b)
    assert out == {"cases": 2, "attack vector": 1, "analysis": 1, "first rule's log source": 0}
