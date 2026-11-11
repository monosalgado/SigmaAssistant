"""eval/change_measures.py: the mechanisms of Changes 57, 59, 60 and 61 read from two arms' rows (plan in the log,
2026-11-10, "towards one"). Offline: rows built here; no model, no saved run."""

from __future__ import annotations

import json

from eval.change_measures import (attack_vector_answer, backslash_patterns, main, measures, paired, regeneration,
                                  review_returned, rules_put_back, stage_tokens)


def _call(stage, prompt=100, completion=10):
    return {"stage": stage, "prompt_tokens": prompt, "completion_tokens": completion, "ok": True}


def _rule(value):
    return f"""title: T
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '{value}'
    condition: selection
"""


def _row(rid, calls=(), n_rules=1, product="windows", reverted=(), regen=None, sigs=(), covered=(), missed=(),
         rules=(), reasoning="", salvaged=None, returned=None, pre_review=(), elapsed=10.0):
    return {"rule_id": rid, "product": product, "n_rules": n_rules, "elapsed_s": elapsed, "llm_calls": list(calls),
            "rules_yaml": list(rules), "error": None,
            "pipeline": {"review_reverted": list(reverted), "regeneration_reason": regen,
                         "attack_vector": {"payload_signatures": [{"pattern": s} for s in sigs],
                                           "reasoning": reasoning, "salvaged": salvaged},
                         "coverage_check": {"payload_signatures_covered": list(covered),
                                            "payload_signatures_missed": list(missed)},
                         "review_returned": returned, "pre_review_rules": list(pre_review)}}


# --- tokens per step ------------------------------------------------------------------------------------------------

def test_a_steps_tokens_are_summed_over_every_call_of_that_step_in_the_case():
    row = _row("r", calls=[_call("generation", 900, 300), _call("review", 400, 120), _call("generation", 900, 280),
                           _call("review", 410, 100)])
    assert stage_tokens(row, "review", "completion_tokens") == 220
    assert stage_tokens(row, "generation", "prompt_tokens") == 1800


def test_a_step_that_was_not_called_counts_0_and_a_call_without_a_token_count_makes_it_unknown():
    assert stage_tokens(_row("r", calls=[_call("analysis")]), "review", "completion_tokens") == 0
    row = _row("r", calls=[_call("review"), {"stage": "review", "completion_tokens": None, "ok": True}])
    assert stage_tokens(row, "review", "completion_tokens") is None


# --- pairing --------------------------------------------------------------------------------------------------------

def test_a_measure_is_paired_on_the_cases_both_arms_have_b_minus_a_with_a_bootstrap_ci():
    a = {f"r{i}": _row(f"r{i}", calls=[_call("review", completion=200 + 10 * i)]) for i in range(6)}
    b = {f"r{i}": _row(f"r{i}", calls=[_call("review", completion=100 + 10 * i)]) for i in range(5)}
    out = paired(a, b, lambda r: stage_tokens(r, "review", "completion_tokens"))
    assert out["n"] == 5 and out["only_in_a"] == 1 and out["only_in_b"] == 0
    assert out["diff"] == -100 and out["ci"][0] == out["ci"][1] == -100
    assert out["unknown"] == 0


def test_a_case_whose_value_is_unknown_in_either_arm_is_left_out_and_counted():
    a = {"r1": _row("r1", calls=[_call("review")]), "r2": _row("r2", calls=[_call("review")])}
    b = {"r1": _row("r1", calls=[{"stage": "review", "completion_tokens": None}]), "r2": _row("r2", calls=[_call("review")])}
    out = paired(a, b, lambda r: stage_tokens(r, "review", "completion_tokens"))
    assert out["n"] == 1 and out["unknown"] == 1


# --- per-case records -----------------------------------------------------------------------------------------------

def test_rules_put_back_by_change_55s_check_are_counted_per_case():
    assert rules_put_back(_row("r", reverted=[{"rule": 2}, {"rule": 4}])) == 2
    assert rules_put_back(_row("r")) == 0


def test_a_case_is_regenerated_when_the_rule_writer_ran_more_than_once_and_its_reason_is_read_where_recorded():
    once = _row("r", calls=[_call("generation"), _call("review")])
    twice = _row("r", calls=[_call("generation"), _call("review"), _call("generation"), _call("review")],
                 regen={"kind": "coverage", "triggers": ["patterns", "do_not_use"]})
    unrecorded = _row("r", calls=[_call("generation"), _call("generation")])
    assert regeneration(once) == {"regenerated": False, "reason": None}
    assert regeneration(twice) == {"regenerated": True, "reason": "coverage: patterns, do_not_use"}
    assert regeneration(unrecorded) == {"regenerated": True, "reason": "not recorded"}
    assert regeneration(_row("r", calls=[_call("generation")] * 2, regen={"kind": "validation", "triggers": []})) == \
        {"regenerated": True, "reason": "validation"}


def test_backslash_patterns_the_check_found_and_those_it_missed_although_a_final_rule_holds_them():
    path, escaped, plain = "C:\\Users\\Public\\a.dll", "ipv4\\.dll", "whoami"
    row = _row("r", sigs=[path, escaped, plain], covered=[escaped, plain], missed=[path],
               rules=[_rule("C:\\Users\\Public\\a.dll")])
    assert backslash_patterns(row) == {"checked": 2, "found": 1, "missed_but_in_a_rule": 1}
    row = _row("r", sigs=[path], covered=[], missed=[path], rules=[_rule("C:\\Windows\\b.exe")])
    assert backslash_patterns(row) == {"checked": 1, "found": 0, "missed_but_in_a_rule": 0}


def test_an_attack_vector_answer_is_ok_salvaged_or_failed():
    assert attack_vector_answer(_row("r", reasoning="The exploit arrives over HTTP.")) == "ok"
    assert attack_vector_answer(_row("r", reasoning="The answer was not valid JSON (...)", salvaged=["protocol"])) == \
        "salvaged"
    assert attack_vector_answer(_row("r", reasoning="Extraction failed: Expecting ',' delimiter")) == "failed"


def test_rules_review_returned_against_the_rules_it_was_given():
    row = _row("r", returned={"rules": [2], "ignored": [], "readable": True}, pre_review=["a", "b", "c"])
    assert review_returned(row) == {"returned": 1, "reviewed": 3, "readable": True}
    assert review_returned(_row("r")) is None


# --- the whole reading ----------------------------------------------------------------------------------------------

def _arms():
    a = {f"r{i}": _row(f"r{i}", n_rules=5, calls=[_call("attack_vector", 14000), _call("analysis", 15000),
                                                   _call("generation"), _call("review", completion=1500)],
                       reverted=[{"rule": 1}]) for i in range(4)}
    b = {f"r{i}": _row(f"r{i}", n_rules=3, calls=[_call("attack_vector", 13000), _call("analysis", 12000),
                                                   _call("generation"), _call("review", completion=400)],
                       returned={"rules": [1], "ignored": [], "readable": True}, pre_review=["x", "y", "z"])
         for i in range(4)}
    a["mac"] = _row("mac", product="macos")
    b["mac"] = _row("mac", product="macos")
    return a, b


def test_the_reading_names_each_changes_measure_and_keeps_to_the_scope():
    a, b = _arms()
    out = measures(a, b, scope="windows-linux")
    assert out["cases"] == {"a": 4, "b": 4, "paired": 4}
    assert out["change60"]["review_answer_tokens"]["diff"] == -1100
    assert out["change60"]["rules_put_back"] == {"a": {"rules": 4, "cases": 4}, "b": {"rules": 0, "cases": 0}}
    assert out["change60"]["review_returned"]["b"] == {"returned": 4, "reviewed": 12, "cases": 4, "unreadable": 0}
    assert out["change59"]["rules_per_case"]["diff"] == -2
    assert out["change61"]["attack_vector_prompt_tokens"]["diff"] == -1000
    assert out["change61"]["analysis_prompt_tokens"]["diff"] == -3000
    assert out["change57"]["regenerated"]["a"] == {"cases": 0, "reasons": {}}
    assert out["change57"]["attack_vector_answers"]["b"] == {"ok": 4, "salvaged": 0, "failed": 0}
    assert set(out["change57"]["backslash_patterns"]["a"]) == {"checked", "found", "missed_but_in_a_rule"}
    assert out["seconds_per_case"]["n"] == 4


def test_the_command_line_writes_the_reading(tmp_path):
    a, b = _arms()
    paths = []
    for name, rows in (("a", a), ("b", b)):
        path = tmp_path / f"{name}.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in rows.values()))
        paths.append(path)
    out = tmp_path / "out.json"
    assert main(["--a", str(paths[0]), "--b", str(paths[1]), "--scope", "windows-linux", "--out", str(out)]) == 0
    assert json.loads(out.read_text())["cases"]["paired"] == 4
