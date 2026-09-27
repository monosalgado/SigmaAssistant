"""Tests for the simulated-analyst run (plan 5.3): the harness's oracle mode.

Fully offline: a stand-in orchestrator; no LLM, no network.

Per case the analysis runs ONCE; then two generations from that same analysis: arm U with
no review (the automated path) and arm O with the gold rule's log source given as the
analyst's choice - when SigmaHQ's table has it. Nothing else from the gold rule reaches the
pipeline, and nothing at all reaches arm U. Both rows are written only when both arms ran,
so a stopped case is redone whole.
"""

from __future__ import annotations

import json

from backend.telemetry import TELEMETRY
from eval.run_eval import (
    DIAGNOSIS_FIELDS, gold_logsource, load_done, oracle_review, run_oracle_case, run_oracle_cases,
)

TABLE = {
    "with_category": [{"category": "process_creation", "products": ["linux", "windows"], "fields": []}],
    "without_category": [{"product": "linux", "service": "auditd", "fields": []}],
}


def _rule(product):
    return f"""title: Sudo negative user id
logsource:
    category: process_creation
    product: {product}
detection:
    selection:
        CommandLine|contains: '-u#-1'
    condition: selection
"""


GOLD = {
    "title": "Gold",
    "logsource": {"category": "process_creation", "product": "linux"},
    "detection": {"selection": {"CommandLine|contains": "-u#-1"}, "condition": "selection"},
}


def _record(tokens, ok=True):
    TELEMETRY.record(backend="fake", tier="economy", model="m", operation="generate",
                     latency_s=1.0, prompt_chars=10, usage={"total_tokens": tokens}, ok=ok,
                     error=None if ok else "timed out")


class _Orchestrator:
    def __init__(self, analysis_raises=None, failed_call_in=None):
        self.analysed, self.reviews = [], []
        self.analysis_raises, self.failed_call_in = analysis_raises, failed_call_in

    def analyse_for_review(self, description, history=None, media_file=None):
        self.analysed.append(description)
        if self.analysis_raises:
            raise self.analysis_raises
        _record(100)
        yield {"event": "stage", "data": {"stage": "analysis", "status": "complete", "detail": ""}}
        yield {"event": "checkpoint", "data": {"state": {"saved": True}, "pipeline_metadata": {}, "context": {}}}

    def generate_after_review(self, state, review, history=None):
        assert state == {"saved": True}
        self.reviews.append(review)
        oracle = bool(review)
        _record(20 if oracle else 10, ok=not (self.failed_call_in == ("oracle" if oracle else "unreviewed")))
        meta = {"analyst_check": {"departures": [], "rewritten": False}} if oracle else {}
        rule = _rule("linux" if oracle else "windows")
        return iter([{"event": "stage", "data": {"stage": "generation", "status": "complete", "detail": ""}},
                     {"event": "result", "data": {"rule": "```yaml\n" + rule + "```", "context": {},
                                                  "pipeline_metadata": meta}}])


class _Agent:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.client = type("C", (), {"web_search": lambda self, q: {}})()


def _case(gold=GOLD, rule_id="r-1"):
    return {"rule_id": rule_id, "rule_path": "x.yml", "title": "t",
            "category": "process_creation", "product": "linux",
            "urls": ["https://example.com/a", "https://example.com/b"], "url_to_path": {},
            "text_chars": 5000, "gold": gold}


def _run(orchestrator, case=None):
    return run_oracle_case(_Agent(orchestrator), case or _case(), config={"arm": "oracle_ls60"},
                           no_web_enrich=True, table=TABLE)


# --- the oracle's decision -------------------------------------------------------------

def test_the_gold_log_source_in_sigmas_form():
    assert gold_logsource({"logsource": {"category": "process_creation", "product": "Linux", "service": ""}}) == \
        {"category": "process_creation", "product": "linux", "service": None}
    assert gold_logsource({"title": "no log source"}) is None


def test_the_oracle_review_is_the_gold_log_source_when_sigmahq_has_it():
    assert oracle_review(GOLD, TABLE) == {"logsource": {"category": "process_creation", "product": "linux", "service": None}}
    assert oracle_review({"logsource": {"category": "email"}}, TABLE) is None


# --- one case -------------------------------------------------------------------------

def test_the_analysis_runs_once_and_both_arms_generate_from_it():
    orch = _Orchestrator()
    _run(orch)
    assert orch.analysed == ["https://example.com/a https://example.com/b"]
    assert len(orch.reviews) == 2


def test_the_unreviewed_arm_gets_nothing_from_the_gold_rule():
    orch = _Orchestrator()
    _run(orch)
    assert orch.reviews[0] == {}
    assert orch.reviews[1] == {"logsource": {"category": "process_creation", "product": "linux", "service": None}}


def test_each_arm_is_scored_against_the_gold_rule():
    row_u, row_o = _run(_Orchestrator())
    assert row_u["scores"]["logsource"]["exact_match"] is False     # windows
    assert row_o["scores"]["logsource"]["exact_match"] is True      # linux


def test_each_arm_counts_the_analysis_and_its_own_generation():
    row_u, row_o = _run(_Orchestrator())
    assert row_u["telemetry"]["total_tokens"] == 110
    assert row_o["telemetry"]["total_tokens"] == 120
    assert len(row_u["llm_calls"]) == 2 and len(row_o["llm_calls"]) == 2


def test_rows_are_labelled_by_arm_and_keep_the_review_and_its_check():
    row_u, row_o = _run(_Orchestrator())
    assert row_u["config"]["arm"] == "oracle_ls60_unreviewed" and "oracle_review" not in row_u
    assert row_o["config"]["arm"] == "oracle_ls60_oracle"
    assert row_o["oracle_review"]["logsource"]["product"] == "linux"
    assert "analyst_check" in DIAGNOSIS_FIELDS
    assert row_o["pipeline"]["analyst_check"]["rewritten"] is False


def test_a_gold_log_source_sigmahq_does_not_have_gives_no_oracle_row():
    orch = _Orchestrator()
    row_u, row_o = _run(orch, _case(gold=dict(GOLD, logsource={"category": "email"})))
    assert row_o is None and orch.reviews == [{}]
    assert row_u["error"] is None


def test_an_analysis_crash_is_an_error_in_both_arms():
    row_u, row_o = _run(_Orchestrator(analysis_raises=ValueError("boom")))
    assert row_u["error"] == "ValueError: boom" and row_o["error"] == "ValueError: boom"
    assert row_u["scores"] is None and row_o["scores"] is None


# --- the loop ---------------------------------------------------------------------------

def _loop(orch, tmp_path, cases):
    out_u, out_o = tmp_path / "u.jsonl", tmp_path / "o.jsonl"
    with open(out_u, "a") as fu, open(out_o, "a") as fo:
        result = run_oracle_cases(_Agent(orch), cases, {"arm": "x"}, True, fu, fo, table=TABLE)
    read = lambda p: [json.loads(l)["rule_id"] for l in p.read_text().splitlines() if l.strip()]  # noqa: E731
    return result, read(out_u), read(out_o)


def test_both_rows_are_written_for_every_case(tmp_path):
    (n_ok, n_failed, stopped), u, o = _loop(_Orchestrator(), tmp_path, [_case(rule_id="a"), _case(rule_id="b")])
    assert (n_ok, n_failed, stopped) == (2, 0, None)
    assert u == ["a", "b"] and o == ["a", "b"]


def test_a_failed_llm_call_in_either_arm_stops_before_writing_the_case(tmp_path):
    (n_ok, _, stopped), u, o = _loop(_Orchestrator(failed_call_in="oracle"), tmp_path, [_case(rule_id="a")])
    assert stopped and "a" in stopped
    assert u == [] and o == []


def test_resuming_skips_the_cases_already_written(tmp_path):
    path = tmp_path / "u.jsonl"
    path.write_text(json.dumps({"rule_id": "a"}) + "\n\n" + json.dumps({"rule_id": "b"}) + "\n")
    assert load_done(path) == {"a", "b"}
    assert load_done(tmp_path / "missing.jsonl") == set()
