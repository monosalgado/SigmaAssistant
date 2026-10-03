#!/usr/bin/env python3
"""P-C, self-consistency: can agreement between the analysis stage's answers say when to ask the analyst?

For each case the stages before the analysis run once (preprocessing, PoC, attack vector; saved pages, no
web search, as every run since September); then the analysis stage answers that identical input once at
temperature 0 (today's pipeline: the "single" answer) and k times at a sampling temperature. The log
source most of the k answers put first is the vote (a tie goes to the earliest answer among the tied; an
answer with no pick is a vote for no pick); how many of the k agree with it is the confidence.

Measures (all against the gold log source, and against the gold or another human rule for the same report,
as P / Pany in `compare_arms.py`): the vote vs the single answer (paired, exact McNemar); how often the vote
is right at each level of agreement; accepting only answers with at least m votes - how many cases would go
to the analyst, and how right the accepted ones are; whether unanimous answers are more often right than the
others (one-sided Fisher exact). Also: cases whose k answers were all the same.

The model decides every pick; code only counts votes and records.

Usage (needs the Spark tunnel):
    .venv/bin/python eval/probe_self_consistency.py --out eval/results/pc_tuning60.jsonl [--k 5 --temperature 0.7]
    .venv/bin/python eval/probe_self_consistency.py --report eval/results/pc_tuning60.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from backend.pipeline.sigma_logsource import _clean  # noqa: E402
from eval.alternative_logsources import classify  # noqa: E402
from eval.compare_runs import mcnemar  # noqa: E402

FIELDS = ("category", "product", "service")
RIGHT = ("gold", "another human rule")


def pick_key(suggestion):
    if not isinstance(suggestion, dict):
        return None
    return tuple(_clean(suggestion.get(f)) for f in FIELDS)


def _as_pick(key):
    return None if key is None else dict(zip(FIELDS, key))


def vote(keys: list) -> dict:
    counts = Counter(keys)
    best = max(counts.values())
    majority = next(k for k in keys if counts[k] == best)      # the earliest among the tied
    return {"majority": majority, "votes": best, "k": len(keys)}


@contextmanager
def forced_temperature(stage, temperature: float):
    """Every model call the stage makes while inside is made at this temperature."""
    had_own = "llm_call" in vars(stage)
    original = stage.llm_call

    def sampling(prompt, *args, **kwargs):
        kwargs["temperature"] = temperature
        return original(prompt, *args, **kwargs)

    stage.llm_call = sampling
    try:
        yield
    finally:
        if had_own:
            stage.llm_call = original
        else:
            del stage.llm_call


def case_result(row: dict, gold: dict, alts: list) -> dict:
    samples = row.get("samples") or []
    single = pick_key(samples[0].get("top")) if samples else None
    keys = [pick_key(s.get("top")) for s in samples[1:]]
    v = vote(keys) if keys else {"majority": None, "votes": 0, "k": 0}
    return {"rule_id": row["rule_id"],
            "single": classify(_as_pick(single), gold, alts),
            "majority": classify(_as_pick(v["majority"]), gold, alts),
            "votes": v["votes"], "k": v["k"], "distinct": len(set(keys)),
            "single_is_majority": single == v["majority"]}


def report(rows: list, picks: dict) -> dict:
    """picks: rule_id -> (gold log source, other human rules' log sources)."""
    results = [case_result(r, *picks[r["rule_id"]]) for r in rows if r["rule_id"] in picks and r.get("samples")]
    k = max((r["k"] for r in results), default=0)
    right = lambda r: r["majority"] == "gold"
    out = {"cases": len(results), "k": k,
           "P_single": sum(r["single"] == "gold" for r in results),
           "P_majority": sum(right(r) for r in results),
           "Pany_single": sum(r["single"] in RIGHT for r in results),
           "Pany_majority": sum(r["majority"] in RIGHT for r in results),
           "mcnemar": mcnemar([(r["single"] == "gold", right(r)) for r in results]),
           "samples_all_identical": sum(r["distinct"] == 1 for r in results),
           "single_is_majority": sum(r["single_is_majority"] for r in results),
           "by_votes": {}, "selective": []}
    for votes in sorted({r["votes"] for r in results}, reverse=True):
        group = [r for r in results if r["votes"] == votes]
        out["by_votes"][votes] = {"cases": len(group), "P_majority": sum(right(r) for r in group),
                                  "Pany_majority": sum(r["majority"] in RIGHT for r in group)}
    for m in range(k, 0, -1):
        accepted = [r for r in results if r["votes"] >= m]
        out["selective"].append({"min_votes": m, "accepted": len(accepted),
                                 "accepted_right": sum(right(r) for r in accepted),
                                 "escalated": len(results) - len(accepted)})
    unanimous = [r for r in results if r["votes"] == k]
    others = [r for r in results if r["votes"] < k]
    u = (sum(right(r) for r in unanimous), len(unanimous))
    o = (sum(right(r) for r in others), len(others))
    from scipy.stats import fisher_exact
    _, p = fisher_exact([[u[0], u[1] - u[0]], [o[0], o[1] - o[0]]], alternative="greater")
    out["unanimous_vs_not"] = {"unanimous": u, "not": o, "fisher_p": float(p)}
    return out


def print_report(rep: dict) -> None:
    n, k = rep["cases"], rep["k"]
    m = rep["mcnemar"]
    print(f"\n{n} cases; k = {k} sampled answers each, plus the single answer at temperature 0")
    print(f"  P    single {rep['P_single']} of {n}   vote {rep['P_majority']} of {n}   "
          f"(only single right {m['only_a']}, only vote right {m['only_b']}; exact McNemar p = {m['p']:.3g})")
    print(f"  Pany single {rep['Pany_single']} of {n}   vote {rep['Pany_majority']} of {n}")
    print(f"  the k answers all the same: {rep['samples_all_identical']} of {n}; "
          f"the single answer = the vote: {rep['single_is_majority']} of {n}")
    print("  the vote's agreement (votes of k) -> how often the vote is right")
    for votes, g in rep["by_votes"].items():
        print(f"    {votes} of {k}: {g['cases']:>3} cases, P {g['P_majority']:>3}, Pany {g['Pany_majority']:>3}")
    print("  accept only votes with at least m of k; the rest go to the analyst")
    for s in rep["selective"]:
        share = s["accepted_right"] / s["accepted"] if s["accepted"] else float("nan")
        print(f"    m = {s['min_votes']}: accepted {s['accepted']:>3} (right {s['accepted_right']:>3}, {share:.0%}), "
              f"to the analyst {s['escalated']:>3}")
    u = rep["unanimous_vs_not"]
    print(f"  unanimous right {u['unanimous'][0]} of {u['unanimous'][1]}; the others {u['not'][0]} of {u['not'][1]}; "
          f"one-sided Fisher exact p = {u['fisher_p']:.3g}")


def _picks(rows: list, manifest_path: Path) -> dict:
    from eval.alternative_logsources import EMERGING, alternatives, reference_index
    manifest = {json.loads(l)["rule_id"]: json.loads(l) for l in open(manifest_path, encoding="utf-8") if l.strip()}
    index = reference_index([EMERGING])
    return {r["rule_id"]: (manifest[r["rule_id"]].get("logsource") or {}, alternatives(manifest[r["rule_id"]], index))
            for r in rows if r["rule_id"] in manifest}


def _name(suggestion: dict) -> str:
    return "/".join(v for v in (pick_key(suggestion) or ()) if v)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out")
    parser.add_argument("--report", help="only print the report of an existing results file")
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--temperature", type=float, default=0.7)
    parser.add_argument("--sample", type=int, default=60)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--limit", type=int, default=0, help="first N of the selected cases (0 = all)")
    parser.add_argument("--manifest", default="eval/manifest.jsonl")
    parser.add_argument("--scoring-manifest", default="eval/manifest.jsonl",
                        help="where the gold log sources are read (the corpus manifest holds every case)")
    args = parser.parse_args()
    if args.report:
        rows = [json.loads(l) for l in open(args.report, encoding="utf-8") if l.strip()]
        print_report(report(rows, _picks(rows, REPO / args.scoring_manifest)))
        return 0
    if not args.out:
        parser.error("--out or --report")

    from eval.run_eval import (load_cases, load_github_manifest, poc_snapshots_instead_of_network,
                               snapshots_instead_of_network, stratified_sample, web_enrichment_disabled)
    from eval.probe_json_repair import capture_answers, readability
    cases = load_cases(REPO / args.manifest, REPO, 2000)
    if args.sample and args.sample < len(cases):
        cases = stratified_sample(cases, args.sample, args.seed)
    if args.limit:
        cases = cases[:args.limit]
    poc_url_map = load_github_manifest(REPO / "eval/github_manifest.jsonl")
    from backend.agent import SigmaAgent
    agent = SigmaAgent()
    orch = agent.orchestrator
    done = set()
    if Path(args.out).exists():
        done = {json.loads(l)["rule_id"] for l in open(args.out, encoding="utf-8") if l.strip()}
    print(f"{len(cases)} cases, {len(done)} already in {args.out}; k = {args.k} at temperature {args.temperature}",
          flush=True)
    with open(args.out, "a", encoding="utf-8") as out:
        for n, case in enumerate(cases, 1):
            if case["rule_id"] in done:
                continue
            started = time.monotonic()
            row = {"rule_id": case["rule_id"], "title": case["title"], "category": case.get("category"),
                   "product": case.get("product"), "k": args.k, "temperature": args.temperature,
                   "error": None, "samples": []}
            with snapshots_instead_of_network(case["url_to_path"]), \
                    poc_snapshots_instead_of_network(poc_url_map), \
                    web_enrichment_disabled(agent.client, True):
                try:
                    context = {"original_query": " ".join(case["urls"]), "history": [], "media_file": None}
                    for stage in (orch.preprocess, orch.web_enrich, orch.poc_analysis, orch.attack_vector):
                        context = stage.run(context)
                    for i in range(args.k + 1):
                        temperature = 0.0 if i == 0 else args.temperature
                        t0 = time.monotonic()
                        with capture_answers(orch.analysis) as answers, forced_temperature(orch.analysis, temperature):
                            result = orch.analysis.run(dict(context))     # the identical input every time
                        suggestions = [s for s in (result.get("logsource_suggestion") or {}).get("suggestions") or []
                                       if isinstance(s, dict)]
                        row["samples"].append({
                            "temperature": temperature,
                            "top": {f: suggestions[0].get(f) for f in FIELDS} if suggestions else None,
                            "suggestions": [_name(s) for s in suggestions],
                            "readable": readability(answers[-1] or "", orch.analysis)["new"] if answers else None,
                            "chars": len(answers[-1] or "") if answers else 0,
                            "seconds": round(time.monotonic() - t0, 1)})
                except Exception as exc:
                    row["error"] = f"{type(exc).__name__}: {exc}"
            row["seconds"] = round(time.monotonic() - started, 1)
            out.write(json.dumps(row) + "\n")
            out.flush()
            tops = [s["suggestions"][0] if s["suggestions"] else "-" for s in row["samples"]]
            print(f"[{n}/{len(cases)}] {case['rule_id'][:8]} {row['seconds']}s single {tops[:1]} "
                  f"samples {tops[1:]} {row['error'] or ''}", flush=True)
    rows = [json.loads(l) for l in open(args.out, encoding="utf-8") if l.strip()]
    print_report(report(rows, _picks(rows, REPO / args.scoring_manifest)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
