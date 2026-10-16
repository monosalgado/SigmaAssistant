"""Tests for the qwen3.6 probe's part-2 table (`eval/model_probe_table.py`): per step - requests, prompt tokens, answer
tokens, thinking tokens, seconds, cut answers, failed requests; per run - rules and first rules that parse. Offline."""

from __future__ import annotations

from eval.model_probe_table import run_summary, stage_rows


def _call(stage, prompt, answer, seconds, thinking=None, cut=False, ok=True):
    return {"stage": stage, "prompt_tokens": prompt, "completion_tokens": answer, "latency_s": seconds,
            "thinking_tokens": thinking, "output_limited": cut, "ok": ok}


ROWS = [{"n_rules": 3, "scores": {"validity": {"parses": True}},
         "llm_calls": [_call("analysis", 9000, 2000, 60, thinking=1500), _call("review", 3000, 900, 20)]},
        {"n_rules": 0, "scores": {"validity": {"parses": False}},
         "llm_calls": [_call("analysis", 11000, 16384, 300, thinking=15000, cut=True),
                       _call("review", 0, 0, 1, ok=False)]}]


def test_per_step_sizes_times_and_problems():
    table = {r["stage"]: r for r in stage_rows(ROWS)}
    a = table["analysis"]
    assert (a["requests"], a["prompt_max"], a["answer_max"], a["thinking_total"], a["thinking_max"]) == \
        (2, 11000, 16384, 16500, 15000)
    assert (a["seconds"], a["cut"], a["failed"]) == (360, 1, 0)
    assert table["review"]["failed"] == 1 and table["review"]["thinking_total"] == 0


def test_per_run_rules():
    assert run_summary(ROWS) == {"reports": 2, "rules": 3, "first_rule_parses": 1, "seconds": 381}
