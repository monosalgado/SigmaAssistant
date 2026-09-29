#!/usr/bin/env python3
"""Where two runs disagree, case by case: S1 (first rule parses), S3 (log source right),
S5 (detection-field F1), and where each run's first rule looked. Offline; paired by rule_id
with `compare_runs.metric_value`, so the values are those the paired comparison scores.

Written for the professor's question (2026-09-28): why does the assistant write a good rule
one time and a wrong one another? Run on two runs of the same code, it shows the cases where
chance alone changed the outcome.

Usage:
    .venv/bin/python eval/list_disagreements.py <run A>.jsonl <run B>.jsonl [--s5-gap 0.5]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.compare_runs import load, metric_value  # noqa: E402


def first_logsource(row: dict) -> str:
    rules = row.get("rules_yaml") or []
    if not rules:
        return "(no rule)"
    try:
        logsource = (yaml.safe_load(rules[0]) or {}).get("logsource") or {}
    except yaml.YAMLError:
        return "(does not parse)"
    parts = [str(logsource[f]) for f in ("category", "product", "service") if logsource.get(f)]
    return "/".join(parts) or "(none)"


def _stage_outputs(row: dict) -> list:
    """What each model stage concluded about where to look, in pipeline order."""
    pipeline = row.get("pipeline") or {}
    telemetry = (pipeline.get("attack_vector") or {}).get("primary_telemetry")
    suggestions = pipeline.get("logsource_suggestions") or []
    top = suggestions[0] if suggestions and isinstance(suggestions[0], dict) else {}
    suggestion = "/".join(str(top[f]) for f in ("category", "product", "service") if top.get(f)) or None
    return [("attack vector", telemetry), ("analysis", suggestion)]


def diverged_at(row_a: dict, row_b: dict) -> str:
    """The first stage whose conclusion differs between the two runs: the attack-vector stage
    (its telemetry), the analysis (its first log-source suggestion), else the rule writer."""
    for (stage, value_a), (_, value_b) in zip(_stage_outputs(row_a), _stage_outputs(row_b)):
        if value_a != value_b:
            return stage
    return "rule writer"


def stage_differences(a: dict, b: dict) -> dict:
    """Over every paired case: how often each stage concluded differently in the two runs."""
    out = {"cases": 0, "attack vector": 0, "analysis": 0, "first rule's log source": 0}
    for rid in a:
        if rid not in b:
            continue
        out["cases"] += 1
        for (stage, value_a), (_, value_b) in zip(_stage_outputs(a[rid]), _stage_outputs(b[rid])):
            out[stage] += value_a != value_b
        out["first rule's log source"] += first_logsource(a[rid]) != first_logsource(b[rid])
    return out


def disagreements(a: dict, b: dict, s5_gap: float = 0.5) -> list:
    """Cases whose S1 or S3 differs, then cases whose S5 differs by at least `s5_gap`."""
    flips, gaps = [], []
    for rid in a:
        if rid not in b:
            continue
        s1 = (metric_value(a[rid], "S1"), metric_value(b[rid], "S1"))
        s3 = (metric_value(a[rid], "S3"), metric_value(b[rid], "S3"))
        s5 = (metric_value(a[rid], "S5"), metric_value(b[rid], "S5"))
        row = {"rule_id": rid, "title": a[rid].get("title", ""), "category": a[rid].get("category", ""),
               "S1": s1, "S3": s3, "S5": s5, "logsource": (first_logsource(a[rid]), first_logsource(b[rid])),
               "diverged_at": diverged_at(a[rid], b[rid])}
        if s1[0] != s1[1] or (None not in s3 and s3[0] != s3[1]):
            flips.append(row)
        elif None not in s5 and abs(s5[1] - s5[0]) >= s5_gap:
            gaps.append(row)
    flips.sort(key=lambda r: (r["S1"][0] == r["S1"][1], r["rule_id"]))
    gaps.sort(key=lambda r: -abs(r["S5"][1] - r["S5"][0]))
    return flips + gaps


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("a")
    parser.add_argument("b")
    parser.add_argument("--s5-gap", type=float, default=0.5)
    args = parser.parse_args()
    run_a, run_b = load(Path(args.a)), load(Path(args.b))
    rows = disagreements(run_a, run_b, args.s5_gap)
    diff = stage_differences(run_a, run_b)
    print(f"Over all {diff['cases']} paired cases, the two runs concluded differently at:")
    for stage in ("attack vector", "analysis", "first rule's log source"):
        print(f"  {stage:<25} {diff[stage]:>3}")
    print(f"A: {args.a}\nB: {args.b}\n{len(rows)} cases disagree (S1/S3 flip, or S5 apart by >= {args.s5_gap})\n")
    for stage in ("attack vector", "analysis", "rule writer"):
        print(f"  first diverged at the {stage}: {sum(1 for r in rows if r['diverged_at'] == stage)}")
    print()
    for r in rows:
        fmt = lambda v: "-" if v is None else (f"{v:.2f}" if isinstance(v, float) else str(v))  # noqa: E731
        print(f"{r['rule_id'][:8]} {r['category']:<17} S1 {fmt(r['S1'][0])}->{fmt(r['S1'][1])}  "
              f"S3 {fmt(r['S3'][0])}->{fmt(r['S3'][1])}  S5 {fmt(r['S5'][0])}->{fmt(r['S5'][1])}  "
              f"| {r['logsource'][0]}  ->  {r['logsource'][1]}  | from: {r['diverged_at']} | {r['title'][:50]}")


if __name__ == "__main__":
    main()
