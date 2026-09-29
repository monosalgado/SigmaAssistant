#!/usr/bin/env python3
"""Two versions of the pipeline, each run k times on the same cases: which writes better rules,
and which is more consistent from run to run. Offline; reads finished result files.

Written for the May-vs-now rerun (user, 2026-09-28): the May code (`2ec05f6`, via
`run_eval.py --code`) and `main`, k runs each on the held-out cases. The measures were fixed
before the runs (log 2026-09-28, "May vs now rerun: measurement plan").

A case's value in an arm is the mean over the arm's k runs; the arms are compared case by case
on the cases every run of both arms has (paired), with a bootstrap 95% CI of the mean difference
(`compare_runs.bootstrap_ci`, 10,000 resamples, seed 0).
- **As the user gets it (primary)** - S3u, S5u: a first rule that does not parse is a wrong rule
  (0). S5u is undefined only for a case whose gold rule names no fields (known from any run
  whose rule parsed), and a parsed rule naming no fields scores 0 against a gold that names some.
- **The harness's convention (secondary)** - S1, S3, S4, S5 as `compare_runs.metric_value`:
  content scores only for runs whose rule parses.
- **Consistency** - the same first-rule log source in all k runs of an arm (paired exact
  McNemar between the arms), and how often each stage concluded differently between two runs of
  the same arm (`list_disagreements.stage_differences`, averaged over every pair of runs).

Usage:
    .venv/bin/python eval/compare_arms.py --a may_r1.jsonl may_r2.jsonl may_r3.jsonl \\
        --b main_r1.jsonl main_r2.jsonl main_r3.jsonl [--label-a May --label-b main]
"""

from __future__ import annotations

import argparse
import sys
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.compare_runs import bootstrap_ci, load, mcnemar, metric_value  # noqa: E402
from eval.list_disagreements import first_logsource, stage_differences  # noqa: E402

PRIMARY = ("S3u", "S5u")
SECONDARY = ("S1", "S3", "S4", "S5", "rules", "seconds", "tokens")
STAGES = ("attack vector", "analysis", "first rule's log source")


def _parses(row: dict) -> bool:
    return bool(((row.get("scores") or {}).get("validity") or {}).get("parses"))


def run_value(row: dict, metric: str, gold_has_fields: bool = None):
    """One run's value for one case."""
    if metric == "S3u":
        if not _parses(row):
            return 0.0
        return 1.0 if ((row["scores"].get("logsource") or {}).get("exact_match")) else 0.0
    if metric == "S5u":
        if not gold_has_fields:
            return None
        if not _parses(row):
            return 0.0
        return (row["scores"].get("detection_fields") or {}).get("f1") or 0.0
    return metric_value(row, metric)


def gold_fields(runs: list) -> dict:
    """{case: whether its gold rule names detection fields}, from any run whose rule parsed."""
    out = {}
    for run in runs:
        for rid, row in run.items():
            if _parses(row) and rid not in out:
                n_gold = ((row["scores"].get("detection_fields") or {}).get("n_gold"))
                if n_gold is not None:
                    out[rid] = n_gold > 0
    return out


def _common(runs: list) -> set:
    return set.intersection(*(set(run) for run in runs)) if runs else set()


def case_means(runs: list, metric: str, fields: dict = None) -> dict:
    """{case: mean of its defined values over the runs}, for the cases every run has."""
    fields = gold_fields(runs) if fields is None and metric == "S5u" else fields or {}
    out = {}
    for rid in _common(runs):
        values = [run_value(run[rid], metric, fields.get(rid)) for run in runs]
        values = [float(v) for v in values if v is not None]
        if values:
            out[rid] = sum(values) / len(values)
    return out


def compare(a_runs: list, b_runs: list, metric: str) -> dict:
    """Arm B minus arm A, paired over the cases every run of both arms has."""
    cases = _common(a_runs + b_runs)
    everything = set().union(*(set(run) for run in a_runs + b_runs))
    fields = gold_fields(a_runs + b_runs) if metric == "S5u" else None
    mean_a, mean_b = case_means(a_runs, metric, fields), case_means(b_runs, metric, fields)
    pairs = [(mean_a[rid], mean_b[rid]) for rid in sorted(cases) if rid in mean_a and rid in mean_b]
    diffs = [y - x for x, y in pairs]
    n = len(pairs)
    return {"metric": metric, "n": n, "excluded": sorted(everything - cases),
            "mean_a": sum(x for x, _ in pairs) / n if n else None,
            "mean_b": sum(y for _, y in pairs) / n if n else None,
            "diff": sum(diffs) / n if n else None,
            "ci": bootstrap_ci(diffs) if n else None}


def consistency(runs: list) -> dict:
    """Per case: how many different first-rule log sources the runs chose."""
    distinct = {rid: len({first_logsource(run[rid]) for run in runs}) for rid in sorted(_common(runs))}
    return {"distinct": distinct, "same_in_all": {rid: d == 1 for rid, d in distinct.items()}}


def stage_differences_within(runs: list) -> dict:
    """How often each stage concluded differently between two runs of the same arm: the mean
    count over every pair of runs."""
    pairs = list(combinations(runs, 2))
    out = {"pairs": len(pairs)}
    for stage in STAGES + ("cases",):
        counts = [stage_differences(a, b)[stage] for a, b in pairs]
        out[stage] = sum(counts) / len(counts) if counts else None
    return out


def s3_stability(runs: list, cases: set) -> dict:
    """Cases right in every run, wrong in every run, or mixed (S3 as the user gets it)."""
    out = {"always right": 0, "always wrong": 0, "mixed": 0}
    for rid in cases:
        values = {run_value(run[rid], "S3u") for run in runs}
        out["always right" if values == {1.0} else "always wrong" if values == {0.0} else "mixed"] += 1
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--a", nargs="+", required=True, help="arm A's result files (one per run)")
    parser.add_argument("--b", nargs="+", required=True, help="arm B's result files (one per run)")
    parser.add_argument("--label-a", default="A")
    parser.add_argument("--label-b", default="B")
    args = parser.parse_args()
    a_runs, b_runs = [load(Path(p)) for p in args.a], [load(Path(p)) for p in args.b]
    la, lb = args.label_a, args.label_b
    cases = _common(a_runs + b_runs)
    print(f"{la}: {len(a_runs)} runs; {lb}: {len(b_runs)} runs; {len(cases)} cases in every run of both")

    def show(metric):
        r = compare(a_runs, b_runs, metric)
        if not r["n"]:
            print(f"  {metric:<8} no cases")
            return
        print(f"  {metric:<8} n={r['n']:<3} {la} {r['mean_a']:.3f}   {lb} {r['mean_b']:.3f}   "
              f"{lb} - {la} {r['diff']:+.3f}  95% CI [{r['ci'][0]:+.3f}, {r['ci'][1]:+.3f}]")

    print("\nPrimary - as the user gets it (a rule that does not parse is wrong); case = mean of its runs")
    for metric in PRIMARY:
        show(metric)
    print("\nSecondary - the harness's convention (content scores only for rules that parse)")
    for metric in SECONDARY:
        show(metric)

    print("\nConsistency - the same first-rule log source in every run")
    con_a, con_b = consistency(a_runs), consistency(b_runs)
    pairs = [(con_a["same_in_all"][rid], con_b["same_in_all"][rid]) for rid in sorted(cases)]
    m = mcnemar(pairs)
    print(f"  {la}: {m['a_true']} of {m['n']}   {lb}: {m['b_true']} of {m['n']}   "
          f"(only {la} {m['only_a']}, only {lb} {m['only_b']}; exact McNemar p = {m['p']:.3f})")
    for label, runs in ((la, a_runs), (lb, b_runs)):
        st = s3_stability(runs, cases)
        diff = stage_differences_within(runs)
        print(f"  {label}: S3 right in every run {st['always right']}, wrong in every run "
              f"{st['always wrong']}, mixed {st['mixed']}")
        if diff["pairs"]:
            print(f"  {label}: per pair of runs ({diff['pairs']} pairs), cases concluded differently at - "
                  + ", ".join(f"{s} {diff[s]:.1f}" for s in STAGES) + f" (of {diff['cases']:.0f})")


if __name__ == "__main__":
    main()
