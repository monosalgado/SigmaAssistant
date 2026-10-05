"""Tests for measuring the analysis answer's length (#7, pipeline quality; user 2026-10-05: "continue with #7").

Why: an analysis answer cut at the output limit (16,384 tokens, Change 24) on every attempt leaves the case with no
analysis - no indicators, techniques or log-source suggestion. Per run: the analysis calls' completion tokens, calls
cut, cases with a cut and cases where every attempt was cut; across runs, the cases cut repeatedly; and which parts of
the saved analysis (indicators, techniques, log-source suggestions, attack summary) take the space, as JSON characters.
Offline; made-up rows.
"""

from __future__ import annotations

from eval.analysis_length import part_sizes, repeat_offenders, run_lengths


def _call(tokens, cut=False, stage="analysis"):
    return {"stage": stage, "completion_tokens": tokens, "output_limited": cut, "ok": True}


ROWS = [
    {"rule_id": "a", "llm_calls": [_call(2000), _call(900, stage="generation")],
     "pipeline": {"indicators": [{"value": "x" * 50}] * 3, "ttp_mappings": [{"technique_id": "T1"}],
                  "logsource_suggestions": [{"category": "c"}], "attack_summary": "s" * 10}},
    {"rule_id": "b", "llm_calls": [_call(16384, True), _call(3000)],
     "pipeline": {"indicators": [], "ttp_mappings": [], "logsource_suggestions": [], "attack_summary": ""}},
    {"rule_id": "c", "llm_calls": [_call(16384, True), _call(16384, True), _call(16384, True)],
     "pipeline": {"indicators": [], "ttp_mappings": [], "logsource_suggestions": [], "attack_summary": ""}},
]


def test_a_run_reports_lengths_and_cuts():
    r = run_lengths(ROWS)
    assert r["calls"] == 6 and r["cut_calls"] == 4
    assert r["cases_with_a_cut"] == 2 and r["cases_all_cut"] == ["c"]
    assert r["median_tokens_finished"] == 2500 and r["max_tokens_finished"] == 3000


def test_the_saved_parts_are_sized_in_json_characters():
    sizes = part_sizes(ROWS[0])
    assert sizes["indicators"] > sizes["ttp_mappings"] > 0
    assert set(sizes) == {"indicators", "ttp_mappings", "logsource_suggestions", "attack_summary"}


def test_cases_cut_in_several_runs_are_listed():
    runs = {"r1": {"cases_all_cut": ["c", "d"]}, "r2": {"cases_all_cut": ["c"]}, "r3": {"cases_all_cut": []}}
    assert repeat_offenders(runs) == {"c": ["r1", "r2"], "d": ["r1"]}
