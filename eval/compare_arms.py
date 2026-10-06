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
        --b main_r1.jsonl main_r2.jsonl main_r3.jsonl [--label-a May --label-b main] [--manifest M]

ATT&CK (Changes 42/43's run plan, 2026-10-05): S4 by parent technique and S4's exact precision (rules that parse);
whether the analysis stage's technique list (`ttp_mappings`) holds a gold technique, exact and by parent (undefined
when the gold rule names none); distinct techniques listed per case, and cases listing exactly 10.

With --manifest (Change 38): P / Pany - the analysis stage's top log-source pick is the gold's / the
gold's or another human rule's for the same report (`alternative_logsources.py`, emerging-threats rules).
"""

from __future__ import annotations

import argparse
import statistics
import sys
from functools import lru_cache
from itertools import combinations
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.compare_runs import bootstrap_ci, load, mcnemar, metric_value  # noqa: E402
from eval.list_disagreements import first_logsource, stage_differences  # noqa: E402

PRIMARY = ("S3u", "S5u", "S5vu")
SECONDARY = ("S1", "S3", "S4", "S5", "S5v", "rules", "seconds", "tokens")
# Changes 42/43's run plan (2026-10-05): S4 by parent, S4's exact precision; the analysis's technique list holds a
# gold technique (exact / parent); distinct techniques listed; exactly 10 listed.
ATTACK = ("S4p", "S4prec", "Tgold", "Tgoldp", "Tn", "T10")
STAGES = ("attack vector", "analysis", "first rule's log source")


def _parses(row: dict) -> bool:
    return bool(((row.get("scores") or {}).get("validity") or {}).get("parses"))


@lru_cache(maxsize=None)
def _gold_detection(rule_path: str):
    path = Path(rule_path)
    path = path if path.is_absolute() else REPO / path
    return (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("detection")


@lru_cache(maxsize=None)
def _gold_techniques(rule_path: str) -> frozenset:
    from eval.scorers import extract_techniques
    path = Path(rule_path)
    path = path if path.is_absolute() else REPO / path
    return frozenset(extract_techniques((yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("tags")))


def _listed_techniques(row: dict) -> set:
    mappings = (row.get("pipeline") or {}).get("ttp_mappings") or []
    return {str(m.get("technique_id") or "").strip().lower() for m in mappings if isinstance(m, dict)} - {""}


def _attack_value(row: dict, metric: str):
    """S4p / S4prec as the harness's convention; Tgold / Tgoldp over the analysis's `ttp_mappings` (undefined when
    the gold rule names no technique); Tn distinct techniques listed; T10 exactly 10 listed."""
    if metric in ("S4p", "S4prec"):
        if not _parses(row):
            return None
        attack = row["scores"].get("attack") or {}
        return ((attack.get("parent") or {}).get("f1") if metric == "S4p"
                else (attack.get("exact") or {}).get("precision"))
    listed = _listed_techniques(row)
    if metric == "Tn":
        return float(len(listed))
    if metric == "T10":
        return 1.0 if len(listed) == 10 else 0.0
    gold = set(_gold_techniques(row["rule_path"]))
    if not gold:
        return None
    if metric == "Tgoldp":
        gold, listed = {g.split(".")[0] for g in gold}, {t.split(".")[0] for t in listed}
    return 1.0 if gold & listed else 0.0


def _first_detection(row: dict):
    rules = row.get("rules_yaml") or []
    try:
        rule = yaml.safe_load(rules[0]) if rules else None
    except yaml.YAMLError:
        return None
    return rule.get("detection") if isinstance(rule, dict) else None


def _s5v(row: dict, as_the_user_gets_it: bool):
    """S5v (`scorers.score_detection_values`) of the first rule against the human rule (`rule_path`):
    undefined when the human rule has no values; as the user gets it, a rule that does not parse, or that
    has no values, scores 0."""
    from eval.scorers import extract_detection_values, score_detection_values
    gold = _gold_detection(row["rule_path"])
    if not extract_detection_values(gold):
        return None
    if not _parses(row):
        return 0.0 if as_the_user_gets_it else None
    f1 = score_detection_values(_first_detection(row), gold)["f1"]
    return (f1 or 0.0) if as_the_user_gets_it else f1


def run_value(row: dict, metric: str, gold_has_fields: bool = None, pick: tuple = None):
    """One run's value for one case. P / Pany (Change 38): the analysis stage's top log-source pick is
    the gold's / the gold's or another human rule's for the same report (`pick` = (gold log source,
    the other rules' log sources), `alternative_logsources`); no pick counts as wrong."""
    if metric in ("P", "Pany"):
        from eval.alternative_logsources import classify
        from eval.compare_suggestions import top_suggestion
        verdict = classify(top_suggestion(row), pick[0], pick[1])
        return 1.0 if verdict == "gold" or (metric == "Pany" and verdict == "another human rule") else 0.0
    if metric == "S3u":
        if not _parses(row):
            return 0.0
        return 1.0 if ((row["scores"].get("logsource") or {}).get("exact_match")) else 0.0
    if metric in ("S5vu", "S5v"):
        return _s5v(row, metric == "S5vu")
    if metric in ATTACK:
        return _attack_value(row, metric)
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


def case_means(runs: list, metric: str, fields: dict = None, picks: dict = None) -> dict:
    """{case: mean of its defined values over the runs}, for the cases every run has."""
    fields = gold_fields(runs) if fields is None and metric == "S5u" else fields or {}
    picks = picks or {}
    out = {}
    for rid in _common(runs):
        if metric in ("P", "Pany") and rid not in picks:
            continue
        values = [run_value(run[rid], metric, fields.get(rid), picks.get(rid)) for run in runs]
        values = [float(v) for v in values if v is not None]
        if values:
            out[rid] = sum(values) / len(values)
    return out


def compare(a_runs: list, b_runs: list, metric: str, picks: dict = None) -> dict:
    """Arm B minus arm A, paired over the cases every run of both arms has."""
    cases = _common(a_runs + b_runs)
    everything = set().union(*(set(run) for run in a_runs + b_runs))
    fields = gold_fields(a_runs + b_runs) if metric == "S5u" else None
    mean_a, mean_b = case_means(a_runs, metric, fields, picks), case_means(b_runs, metric, fields, picks)
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


def fmt_p(p: float) -> str:
    return f"{p:.2g}"


def flagged_rows(a_runs: list, b_runs: list) -> list:
    """The contamination-flagged cases (a page that may quote the gold rule), with each arm's
    S3u, S5u and consistency - reported apart, as every run since plan 1.3b."""
    cases = _common(a_runs + b_runs)
    ids = sorted(rid for rid in cases
                 if any((run[rid].get("contamination") or {}).get("flagged") for run in a_runs + b_runs))
    fields = gold_fields(a_runs + b_runs)
    out = []
    con_a, con_b = consistency(a_runs), consistency(b_runs)
    for rid in ids:
        pair = lambda metric: (case_means(a_runs, metric, fields).get(rid),  # noqa: E731
                               case_means(b_runs, metric, fields).get(rid))
        out.append({"rule_id": rid, "category": a_runs[0][rid].get("category", ""), "S3u": pair("S3u"),
                    "S5u": pair("S5u"), "same_in_all": (con_a["same_in_all"][rid], con_b["same_in_all"][rid])})
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--a", nargs="+", required=True, help="arm A's result files (one per run)")
    parser.add_argument("--b", nargs="+", required=True, help="arm B's result files (one per run)")
    parser.add_argument("--label-a", default="A")
    parser.add_argument("--label-b", default="B")
    parser.add_argument("--manifest", help="the cases' manifest: also score the analysis stage's top "
                                           "log-source pick (P, Pany)")
    args = parser.parse_args()
    a_runs, b_runs = [load(Path(p)) for p in args.a], [load(Path(p)) for p in args.b]
    la, lb = args.label_a, args.label_b
    cases = _common(a_runs + b_runs)
    print(f"{la}: {len(a_runs)} runs; {lb}: {len(b_runs)} runs; {len(cases)} cases in every run of both")

    picks = None
    if args.manifest:
        import json
        from eval.alternative_logsources import EMERGING, alternatives, reference_index
        manifest = {json.loads(l)["rule_id"]: json.loads(l) for l in open(args.manifest, encoding="utf-8") if l.strip()}
        index = reference_index([EMERGING])
        picks = {rid: (manifest[rid].get("logsource") or {}, alternatives(manifest[rid], index))
                 for rid in cases if rid in manifest}

    def show(metric):
        r = compare(a_runs, b_runs, metric, picks)
        if not r["n"]:
            print(f"  {metric:<8} no cases")
            return
        print(f"  {metric:<8} n={r['n']:<3} {la} {r['mean_a']:.3f}   {lb} {r['mean_b']:.3f}   "
              f"{lb} - {la} {r['diff']:+.3f}  95% CI [{r['ci'][0]:+.3f}, {r['ci'][1]:+.3f}]")

    if picks:
        from eval.compare_suggestions import top_suggestion
        print("\nThe analysis stage's top log-source pick (no pick = wrong); case = mean of its runs")
        for metric in ("P", "Pany"):
            show(metric)
        for label, runs in ((la, a_runs), (lb, b_runs)):
            missing = sum(1 for run in runs for rid in cases if top_suggestion(run[rid]) is None)
            print(f"  {label}: answers with no pick {missing} of {len(runs) * len(cases)}")
    print("\nPrimary - as the user gets it (a rule that does not parse is wrong); case = mean of its runs")
    for metric in PRIMARY:
        show(metric)
    print("\nSecondary - the harness's convention (content scores only for rules that parse)")
    for metric in SECONDARY:
        show(metric)
    print("\nATT&CK (Changes 42/43) - S4 by parent, S4 precision; the analysis lists a gold technique (exact, parent);"
          " techniques listed, exactly 10")
    for metric in ATTACK:
        show(metric)
    for label, runs in ((la, a_runs), (lb, b_runs)):
        listed = sorted(case_means(runs, "Tn").get(rid, 0.0) for rid in cases)
        print(f"  {label}: techniques listed per case, median {statistics.median(listed) if listed else '-'}")

    print("\nConsistency - the same first-rule log source in every run")
    con_a, con_b = consistency(a_runs), consistency(b_runs)
    pairs = [(con_a["same_in_all"][rid], con_b["same_in_all"][rid]) for rid in sorted(cases)]
    m = mcnemar(pairs)
    print(f"  {la}: {m['a_true']} of {m['n']}   {lb}: {m['b_true']} of {m['n']}   "
          f"(only {la} {m['only_a']}, only {lb} {m['only_b']}; exact McNemar p = {fmt_p(m['p'])})")
    for label, runs in ((la, a_runs), (lb, b_runs)):
        st = s3_stability(runs, cases)
        diff = stage_differences_within(runs)
        print(f"  {label}: S3 right in every run {st['always right']}, wrong in every run "
              f"{st['always wrong']}, mixed {st['mixed']}")
        if diff["pairs"]:
            print(f"  {label}: per pair of runs ({diff['pairs']} pairs), cases concluded differently at - "
                  + ", ".join(f"{s} {diff[s]:.1f}" for s in STAGES) + f" (of {diff['cases']:.0f})")

    flagged = flagged_rows(a_runs, b_runs)
    print(f"\nContamination-flagged cases (included above; listed apart): {len(flagged)}")
    num = lambda v: "-" if v is None else f"{v:.2f}"  # noqa: E731
    for r in flagged:
        print(f"  {r['rule_id'][:8]} {r['category']:<18} S3u {la} {num(r['S3u'][0])} {lb} {num(r['S3u'][1])}   "
              f"S5u {la} {num(r['S5u'][0])} {lb} {num(r['S5u'][1])}   same log source in every run: "
              f"{la} {r['same_in_all'][0]}, {lb} {r['same_in_all'][1]}")


if __name__ == "__main__":
    main()
