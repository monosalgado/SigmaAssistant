"""Tests for P-C, self-consistency (user 2026-10-03: "lets do option 1"): the analysis stage answers the
same input several times at a sampling temperature; the log source most answers put first is the vote,
and how many agree is the confidence. Reports whose answers disagree would go to the analyst.

Why: the stage's own confidence is 0.95 on nearly every pick, right or wrong (log 2026-09-29), so it
cannot say when to ask a human; and at temperature 0 a repeated request gets the identical answer (P-B),
so agreement needs independent samples. The model decides each pick; code only counts votes and records.
Offline: stand-in stages and rows; no LLM.
"""

from __future__ import annotations

from eval.probe_self_consistency import case_result, forced_temperature, pick_key, report, vote

PROC = {"category": "process_creation", "product": "windows", "service": None}
FILE = {"category": "file_event", "product": "windows", "service": None}
WEB = {"category": "webserver", "product": None, "service": None}
A, B, C = pick_key(PROC), pick_key(FILE), pick_key(WEB)


# --- counting votes ------------------------------------------------------------------------

def test_a_pick_is_its_cleaned_log_source():
    assert pick_key({"category": "Process_Creation", "product": "windows", "service": "-"}) == \
        ("process_creation", "windows", None)
    assert pick_key(None) is None


def test_the_vote_is_the_log_source_most_answers_put_first():
    v = vote([A, A, B, A, C])
    assert v["majority"] == A and v["votes"] == 3 and v["k"] == 5


def test_a_tie_goes_to_the_earliest_answer_among_the_tied():
    assert vote([B, A, A, B])["majority"] == B


def test_an_answer_with_no_pick_is_a_vote_for_no_pick():
    v = vote([None, None, A])
    assert v["majority"] is None and v["votes"] == 2


# --- sampling ------------------------------------------------------------------------------

class _Stage:
    name = "analysis"

    def __init__(self):
        self.temperatures = []

    def llm_call(self, prompt, temperature=0.0, **kwargs):
        self.temperatures.append(temperature)
        return "{}"

    def run(self, context):
        self.llm_call("p", temperature=0.0, json_mode=True)
        return context


def test_the_stage_is_asked_at_the_sampling_temperature_and_restored_after():
    stage = _Stage()
    with forced_temperature(stage, 0.7):
        stage.run({})
    stage.run({})
    assert stage.temperatures == [0.7, 0.0]
    assert "llm_call" not in vars(stage)


# --- one case ------------------------------------------------------------------------------

def _row(rid, single, samples):
    return {"rule_id": rid, "error": None,
            "samples": [{"temperature": 0.0, "top": single}] + [{"temperature": 0.7, "top": s} for s in samples]}


GOLD = {"category": "process_creation", "product": "windows"}


def test_a_case_is_scored_for_the_single_answer_and_for_the_vote():
    r = case_result(_row("a", FILE, [PROC, PROC, FILE, PROC, WEB]), GOLD, [])
    assert r["single"] == "neither" and r["majority"] == "gold"
    assert r["votes"] == 3 and r["k"] == 5 and r["distinct"] == 3 and r["single_is_majority"] is False


# --- the report ----------------------------------------------------------------------------

ROWS = [
    _row("u1", PROC, [PROC] * 5),                       # unanimous, right
    _row("u2", PROC, [PROC] * 5),                       # unanimous, right
    _row("u3", FILE, [FILE] * 5),                       # unanimous, wrong
    _row("s1", FILE, [PROC, PROC, PROC, FILE, WEB]),     # 3 of 5, vote right, single wrong
    _row("s2", WEB, [WEB, FILE, PROC, WEB, FILE]),       # 2 of 5, wrong
]
PICKS = {r["rule_id"]: (GOLD, []) for r in ROWS}


def test_the_report_compares_the_vote_with_the_single_answer():
    rep = report(ROWS, PICKS)
    assert rep["cases"] == 5
    assert rep["P_single"] == 2 and rep["P_majority"] == 3
    assert rep["mcnemar"]["only_b"] == 1 and rep["mcnemar"]["only_a"] == 0


def test_the_report_says_how_right_the_vote_is_at_each_level_of_agreement():
    rep = report(ROWS, PICKS)
    assert rep["by_votes"][5] == {"cases": 3, "P_majority": 2, "Pany_majority": 2}
    assert rep["by_votes"][3]["P_majority"] == 1 and rep["by_votes"][2]["P_majority"] == 0


def test_accepting_only_agreed_answers_trades_coverage_for_accuracy():
    sel = {s["min_votes"]: s for s in report(ROWS, PICKS)["selective"]}
    assert sel[5] == {"min_votes": 5, "accepted": 3, "accepted_right": 2, "escalated": 2}
    assert sel[3]["accepted"] == 4 and sel[3]["accepted_right"] == 3
    assert sel[1]["accepted"] == 5 and sel[1]["escalated"] == 0


def test_the_report_tests_whether_unanimous_answers_are_more_often_right():
    u = report(ROWS, PICKS)["unanimous_vs_not"]
    assert u["unanimous"] == (2, 3) and u["not"] == (1, 2)
    assert 0 < u["fisher_p"] <= 1


def test_the_report_counts_cases_whose_samples_did_not_vary():
    rep = report(ROWS, PICKS)
    assert rep["samples_all_identical"] == 3 and rep["single_is_majority"] == 4
