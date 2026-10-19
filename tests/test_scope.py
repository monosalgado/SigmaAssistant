"""Offline tests for the evaluation's scope (user, 2026-10-19: "the whole evaluation, Windows and Linux").

A case is in scope when its expert rule's log source names `product: windows` or `product: linux` - the manifest's
log source, which `load_cases` copies into every case and every result row. The tools that run or score cases
(`run_eval.py`, `summarise.py`, `compare_arms.py`, `draw_heldout.py`) take `--scope windows-linux`; without it they
behave as before. The chance baselines for the scope are measured by committed code (`null_baselines`): every gold rule
scored against every other gold rule of the same cases.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from eval.scope import SCOPES, in_scope, keep, null_baselines


def _row(rule_id, product, category="process_creation"):
    return {"rule_id": rule_id, "product": product, "category": category}


def test_windows_and_linux_are_in_and_everything_else_is_out():
    assert in_scope(_row("a", "windows"), "windows-linux")
    assert in_scope(_row("b", "linux", "file_event"), "windows-linux")
    assert in_scope(_row("c", "Windows"), "windows-linux")
    for product, category in [("none", "webserver"), ("none", "proxy"), ("macos", "process_creation"),
                              ("zeek", "none"), ("paloalto", "file_event"), (None, "process_creation"), ("", "")]:
        assert not in_scope(_row("x", product, category), "windows-linux"), (product, category)


def test_a_row_without_a_product_is_out():
    assert not in_scope({"rule_id": "x", "category": "process_creation"}, "windows-linux")


def test_an_unknown_scope_is_an_error_not_a_silent_pass():
    with pytest.raises(KeyError):
        in_scope(_row("a", "windows"), "windows-only")
    assert set(SCOPES) == {"windows-linux"}


def test_keep_filters_lists_and_dicts_and_no_scope_keeps_everything():
    rows = [_row("a", "windows"), _row("b", "none", "webserver"), _row("c", "linux")]
    assert [r["rule_id"] for r in keep(rows, "windows-linux")] == ["a", "c"]
    by_id = {r["rule_id"]: r for r in rows}
    assert sorted(keep(by_id, "windows-linux")) == ["a", "c"]
    assert keep(rows, None) is rows
    assert keep(by_id, None) is by_id


def _gold(product, category, tags, fields):
    return {"logsource": {"product": product, "category": category},
            "tags": tags,
            "detection": {"selection": {f: "x" for f in fields}, "condition": "selection"}}


def test_null_baselines_score_every_rule_against_every_other_rule():
    golds = [
        _gold("windows", "process_creation", ["attack.t1059"], ["Image"]),
        _gold("windows", "process_creation", ["attack.t1059"], ["Image", "CommandLine"]),
        _gold("linux", "file_event", [], ["TargetFilename"]),
    ]
    b = null_baselines(golds)
    # 6 ordered pairs; the log source agrees in 2 of them (rule 1 vs 2, and 2 vs 1).
    assert b["logsource_exact"] == pytest.approx(2 / 6)
    assert b["n_pairs"] == 6
    # ATT&CK F1 is defined only when both rules carry a technique: 2 pairs, both 1.0.
    assert b["attack_f1"] == pytest.approx(1.0)
    assert b["n_attack"] == 2
    # Detection fields: {Image} vs {Image, CommandLine} -> F1 2/3 both ways; the 4 pairs with rule 3 -> 0.
    assert b["detection_f1"] == pytest.approx((2 / 3 + 2 / 3) / 6)


def test_null_baselines_never_pair_a_rule_with_itself():
    same = _gold("windows", "process_creation", ["attack.t1059"], ["Image"])
    other = _gold("linux", "file_event", ["attack.t1105"], ["TargetFilename"])
    b = null_baselines([same, other])
    assert b["logsource_exact"] == 0.0
    assert b["attack_f1"] == 0.0


def test_null_baselines_need_two_rules():
    with pytest.raises(ValueError):
        null_baselines([_gold("windows", "process_creation", [], ["Image"])])


# --- the tools that take --scope ------------------------------------------------------------

def test_the_run_keeps_the_sample_and_drops_out_of_scope_cases_before_the_limit():
    from eval.run_eval import select_cases
    cases = [_row(f"r{i:02d}", "windows" if i % 3 else "none", "process_creation" if i % 3 else "webserver")
             for i in range(30)]
    args = SimpleNamespace(sample=12, seed=0, limit=0, scope=None)
    sampled = select_cases(cases, args)
    args.scope = "windows-linux"
    scoped = select_cases(cases, args)
    # The same seed-0 sample, without its out-of-scope cases, in the same order.
    assert [c["rule_id"] for c in scoped] == [c["rule_id"] for c in sampled if c["product"] == "windows"]
    args.limit = 3
    assert [c["rule_id"] for c in select_cases(cases, args)] == [c["rule_id"] for c in scoped][:3]


def test_the_run_records_its_scope():
    from eval.run_eval import run_config
    agent = SimpleNamespace(client=SimpleNamespace(model_name="m"), code_revision=None)
    args = SimpleNamespace(arm="x", no_web_enrich=True, web_snapshots=None, min_chars=2000, code=None,
                           scope="windows-linux")
    assert run_config(agent, args, head_revision=lambda: "abc")["scope"] == "windows-linux"
    del args.scope
    assert run_config(agent, args, head_revision=lambda: "abc")["scope"] is None


def test_the_summary_uses_the_scopes_own_chance_baseline():
    from eval.summarise import NULL_BASELINES, SCOPE_NULL_BASELINES, baselines_for, summarise
    assert baselines_for(None) is NULL_BASELINES
    assert set(baselines_for("windows-linux")) >= {"logsource_exact", "attack_f1", "detection_f1"}
    assert baselines_for("windows-linux") is SCOPE_NULL_BASELINES["windows-linux"]
    s = summarise([], baselines=baselines_for("windows-linux"))
    assert s["baselines"] is SCOPE_NULL_BASELINES["windows-linux"]


def test_the_draw_can_take_every_never_run_case_in_scope():
    from eval.draw_heldout import select_heldout
    cases = [_row(f"r{i:02d}", "windows" if i % 2 else "none", "process_creation" if i % 2 else "webserver")
             for i in range(20)]
    used = {"r01", "r03"}
    drawn = select_heldout(cases, used, 0, seed=0, scope="windows-linux")
    assert [c["rule_id"] for c in drawn] == [f"r{i:02d}" for i in range(5, 20, 2)]
    # Without a scope, n = 0 still means every never-run case.
    assert len(select_heldout(cases, used, 0, seed=0)) == 18
