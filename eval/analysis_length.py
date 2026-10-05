#!/usr/bin/env python3
"""How long is the analysis stage's answer, how often is it cut, and what takes the space? (#7, pipeline quality,
2026-10-05; offline, from saved rows)

Every model call is recorded per row (`llm_calls`: stage, completion tokens, `output_limited`). An analysis answer cut
at the output limit (16,384 tokens, Change 24) is retried twice; when every attempt is cut the case has no analysis -
no indicators, techniques or log-source suggestion. Per run: analysis calls, their completion tokens (finished ones),
calls cut, cases with a cut, cases where every attempt was cut; across runs, the cases cut repeatedly; and the size of
the saved analysis's parts in JSON characters (a proxy for what fills the answer).

Usage:
    .venv/bin/python eval/analysis_length.py eval/results/<run>.jsonl [...]
"""

from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

PARTS = ("indicators", "ttp_mappings", "logsource_suggestions", "attack_summary")


def _analysis_calls(row: dict) -> list:
    return [c for c in row.get("llm_calls") or [] if c.get("stage") == "analysis"]


def run_lengths(rows: list) -> dict:
    calls = [c for r in rows for c in _analysis_calls(r)]
    finished = [c.get("completion_tokens") or 0 for c in calls if not c.get("output_limited")]
    with_cut = [r for r in rows if any(c.get("output_limited") for c in _analysis_calls(r))]
    all_cut = [r["rule_id"] for r in rows if _analysis_calls(r) and all(c.get("output_limited") for c in _analysis_calls(r))]
    latency = [c.get("latency_s") or 0 for c in calls if not c.get("output_limited") and c.get("latency_s")]
    return {"cases": len(rows), "calls": len(calls), "cut_calls": sum(bool(c.get("output_limited")) for c in calls),
            "cases_with_a_cut": len(with_cut), "cases_all_cut": all_cut,
            "median_tokens_finished": statistics.median(finished) if finished else None,
            "p90_tokens_finished": sorted(finished)[int(0.9 * (len(finished) - 1))] if finished else None,
            "max_tokens_finished": max(finished) if finished else None,
            "median_seconds_finished": statistics.median(latency) if latency else None}


def part_sizes(row: dict) -> dict:
    pipeline = row.get("pipeline") or {}
    return {part: len(json.dumps(pipeline.get(part) if pipeline.get(part) is not None else "")) for part in PARTS}


def repeat_offenders(runs: dict) -> dict:
    out = defaultdict(list)
    for name, result in runs.items():
        for rid in result["cases_all_cut"]:
            out[rid].append(name)
    return dict(out)


def main(argv: list) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1
    runs, sizes = {}, defaultdict(list)
    for path in argv[1:]:
        rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
        name = Path(path).stem
        runs[name] = r = run_lengths(rows)
        for row in rows:
            if row["rule_id"] not in r["cases_all_cut"] and _analysis_calls(row):
                for part, size in part_sizes(row).items():
                    sizes[part].append(size)
        print(f"{name:22} calls {r['calls']:>3}, cut {r['cut_calls']:>2}; cases with a cut {r['cases_with_a_cut']:>2}, "
              f"every attempt cut {len(r['cases_all_cut'])} {[c[:8] for c in r['cases_all_cut']]}; finished answers: "
              f"median {r['median_tokens_finished']} tokens, p90 {r['p90_tokens_finished']}, max {r['max_tokens_finished']}; "
              f"median {r['median_seconds_finished']:.0f} s")
    print("\ncases whose every analysis attempt was cut, by run:")
    for rid, names in sorted(repeat_offenders(runs).items(), key=lambda kv: -len(kv[1])):
        print(f"  {rid[:8]}  {len(names)} of {len(runs)} runs")
    total = {p: sum(v) for p, v in sizes.items()}
    whole = sum(total.values()) or 1
    print("\nsaved analysis parts (JSON characters; cases with an analysis): median, and share of all characters")
    for part in PARTS:
        print(f"  {part:22} median {statistics.median(sizes[part]):>6.0f}   share {total[part] / whole:.0%}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
