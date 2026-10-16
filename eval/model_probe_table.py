#!/usr/bin/env python3
"""The qwen3.6 probe's part-2 table (plan: log 2026-10-16): for each result file, per step - requests, prompt tokens
(median, max), answer tokens (max), thinking tokens (total, max), seconds, answers cut at the limit, failed requests;
per run - reports, rules, first rules that parse, seconds. Offline; reads saved rows. Not a quality measure.

Usage:
    .venv/bin/python eval/model_probe_table.py <run.jsonl> [<run.jsonl> ...]
"""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

ORDER = ("poc_analysis", "web_enrichment", "attack_vector", "analysis", "generation", "review")


def stage_rows(rows: list) -> list:
    by = {}
    for row in rows:
        for c in row.get("llm_calls") or []:
            by.setdefault(c.get("stage") or "?", []).append(c)
    out = []
    for stage in sorted(by, key=lambda s: (ORDER.index(s) if s in ORDER else len(ORDER), s)):
        calls = by[stage]
        prompts = [c.get("prompt_tokens") or 0 for c in calls]
        thinking = [c.get("thinking_tokens") or 0 for c in calls]
        out.append({"stage": stage, "requests": len(calls), "prompt_median": int(statistics.median(prompts)),
                    "prompt_max": max(prompts), "answer_max": max(c.get("completion_tokens") or 0 for c in calls),
                    "thinking_total": sum(thinking), "thinking_max": max(thinking),
                    "seconds": round(sum(c.get("latency_s") or 0 for c in calls)),
                    "cut": sum(1 for c in calls if c.get("output_limited")),
                    "failed": sum(1 for c in calls if not c.get("ok", True))})
    return out


def run_summary(rows: list) -> dict:
    return {"reports": len(rows), "rules": sum(r.get("n_rules") or 0 for r in rows),
            "first_rule_parses": sum(1 for r in rows if ((r.get("scores") or {}).get("validity") or {}).get("parses")),
            "seconds": round(sum(c.get("latency_s") or 0 for r in rows for c in r.get("llm_calls") or []))}


def main(argv: list) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1
    for path in argv[1:]:
        rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
        config = (rows[0].get("config") or {}) if rows else {}
        print(f"\n{Path(path).name}  model {config.get('primary_model')}  thinking {config.get('thinking_stages')}  "
              f"{run_summary(rows)}")
        print(f"  {'step':15} {'req':>3} {'prompt med/max':>15} {'answer max':>10} {'thinking tot/max':>17} "
              f"{'sec':>5} {'cut':>3} {'fail':>4}")
        for r in stage_rows(rows):
            print(f"  {r['stage']:15} {r['requests']:3} {r['prompt_median']:7}/{r['prompt_max']:<7} "
                  f"{r['answer_max']:10} {r['thinking_total']:8}/{r['thinking_max']:<8} {r['seconds']:5} "
                  f"{r['cut']:3} {r['failed']:4}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
