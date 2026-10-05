#!/usr/bin/env python3
"""Validate the synthetic replay on known answers before it scores any of our rules (R9.2; plan and thresholds
fixed in the log 2026-10-05). If any test fails, the replay is not used for our rules.

- V1 builder self-check: each rule fires on its own built events - SigmaHQ's recording rules and the corpus's gold
  rules, >= 95% of buildable rules in each.
- V2 real vs synthetic on SigmaHQ's recordings (logic only): for rule X and recording Y, *real* = X fires on Y's
  recorded events (`matcher_validation.jsonl`: self-pairs and off-target pairs), *synthetic* = X fires on events built
  from Y's rule. Pass: synthetic false fires on real non-pairs <= 1%. The related-pair hit is reported (the size of the
  "minimal events under-detect" bias).
- V3 unrelated gold rules stay quiet: each corpus gold rule against the other gold rules' events (with the log-source
  rule; pairs from the same report excluded). Pass: <= 2% of pairs fire.
- V4 a known ordering: replay hit (primary), today's code - the May code on the held-out cases, k = 3 each (mean per
  case, paired bootstrap). Pass: 95% CI above 0.
- V5 null: each held-out case scored with another case's rules (a fixed derangement, seed 0) on today's runs.
  Pass: null hit <= 5% and at most half the real hit.

Usage:
    .venv/bin/python eval/validate_replay.py [--out eval/results/replay_validation.json]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

THRESHOLDS = {"V1": 0.95, "V2": 0.01, "V3": 0.02, "V5": 0.05}


def derangement(ids: list, seed: int = 0) -> dict:
    """{case: another case}, no case mapped to itself; the same for the same seed."""
    ids = list(ids)
    rng = random.Random(seed)
    while True:
        shuffled = ids[:]
        rng.shuffle(shuffled)
        if all(a != b for a, b in zip(ids, shuffled)):
            return dict(zip(ids, shuffled))


def pair_counts(xs: list, ys: list, real: set, synthetic: set) -> dict:
    c = {"self_pairs": 0, "self_caught": 0, "related_pairs": 0, "related_caught": 0, "real_non_pairs": 0,
         "false_fires": 0}
    for x in xs:
        for y in ys:
            fired = (x, y) in synthetic
            if x == y:
                c["self_pairs"] += 1
                c["self_caught"] += fired
            elif (x, y) in real:
                c["related_pairs"] += 1
                c["related_caught"] += fired
            else:
                c["real_non_pairs"] += 1
                c["false_fires"] += fired
    return c


def verdicts(m: dict) -> dict:
    return {"V1": m["V1"] >= THRESHOLDS["V1"], "V2": m["V2"] <= THRESHOLDS["V2"], "V3": m["V3"] <= THRESHOLDS["V3"],
            "V4": m["V4_ci_low"] > 0,
            "V5": m["V5"] <= THRESHOLDS["V5"] and m["V5"] <= 0.5 * m["V5_real"]}


def _v1(rules: dict) -> dict:
    """rules: id -> text. Per rule: built events, verified events, cannot-build reasons."""
    from eval.event_builder import build_events, verified_events
    from eval.rule_matcher import CannotEvaluate, parse_rule
    out = {}
    for rid, text in rules.items():
        try:
            parsed = parse_rule(text)
            built = build_events(parsed)
        except CannotEvaluate as exc:
            out[rid] = {"built": 0, "verified": 0, "cannot": [f"rule: {str(exc)[:80]}"]}
            continue
        out[rid] = {"built": len(built["events"]), "verified": len(verified_events(parsed, built["events"])),
                    "cannot": built["cannot_build"]}
    return out


def _rate(v1: dict) -> tuple:
    buildable = [r for r in v1.values() if r["built"]]
    ok = [r for r in buildable if r["verified"] == r["built"]]
    return len(ok), len(buildable)


def main() -> int:
    import yaml
    from collections import Counter
    from eval.alternative_logsources import EMERGING, reference_index
    from eval.compare_runs import bootstrap_ci
    from eval.replay import alternative_rule_ids, applies, case_score, human_set
    from eval.rule_matcher import CannotEvaluate, parse_rule, rule_matches
    from eval.validate_matcher import SIGMA, rule_index

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=str(REPO / "eval/results/replay_validation.json"))
    args = parser.parse_args()
    index = rule_index([d for d in SIGMA.iterdir() if d.is_dir() and (d.name.startswith("rules") or d.name == "deprecated")])
    text = lambda rid: index[rid].read_text(encoding="utf-8")                      # noqa: E731
    result = {}

    # --- V1, V2: SigmaHQ's recordings ------------------------------------------------------------
    recs = [json.loads(l) for l in open(REPO / "eval/results/matcher_validation.jsonl", encoding="utf-8")]
    evaluable = [r for r in recs if r["verdict"] in ("agree", "disagree") and r["rule_id"] in index]
    rec_rules = {r["rule_id"]: text(r["rule_id"]) for r in evaluable}
    v1_rec = _v1(rec_rules)
    sets_rec = {rid: human_set(t, rid) for rid, t in rec_rules.items()}
    real = {(r["rule_id"], r["rule_id"]) for r in evaluable} | {(r["rule_id"], y) for r in evaluable for y, _ in r["off_target"]}
    parsed_rec = {}
    for rid, t in rec_rules.items():
        try:
            parsed_rec[rid] = parse_rule(t)
        except CannotEvaluate:
            pass
    ys = [rid for rid, s in sets_rec.items() if s["events"]]
    synthetic = set()
    for x, px in parsed_rec.items():
        for y in ys:
            if any(rule_matches(px, e) for e in sets_rec[y]["events"]):
                synthetic.add((x, y))
    v2 = pair_counts(list(parsed_rec), ys, real, synthetic)
    v2["related_missed"] = sorted([(x, y) for x, y in real if x != y and y in ys and (x, y) not in synthetic])

    # --- V1, V3: the corpus's gold rules ----------------------------------------------------------
    manifest = {json.loads(l)["rule_id"]: json.loads(l) for l in open(REPO / "eval/manifest.jsonl", encoding="utf-8") if l.strip()}
    gold_rules = {rid: (REPO / c["rule_path"]).read_text(encoding="utf-8") for rid, c in manifest.items()
                  if (REPO / c["rule_path"]).exists()}
    v1_gold = _v1(gold_rules)
    sets_gold = {rid: human_set(t, rid) for rid, t in gold_rules.items()}
    ref_index = reference_index([EMERGING])
    same_report = {rid: set(alternative_rule_ids(manifest[rid], ref_index)) for rid in manifest}
    parsed_gold = {}
    for rid, t in gold_rules.items():
        try:
            p = parse_rule(t)
            ls = p.rule.logsource
            parsed_gold[rid] = (p, {"category": ls.category, "product": ls.product, "service": ls.service})
        except CannotEvaluate:
            pass
    v3_pairs = v3_fires = 0
    v3_list = []
    for x, (px, lx) in parsed_gold.items():
        for y, sy in sets_gold.items():
            if x == y or not sy["events"] or y in same_report.get(x, ()) or x in same_report.get(y, ()):
                continue
            v3_pairs += 1
            if applies(lx, sy["logsource"]) and any(rule_matches(px, e) for e in sy["events"]):
                v3_fires += 1
                v3_list.append((x, y))

    # --- V4, V5: held-out runs ---------------------------------------------------------------------
    held = [json.loads(l)["rule_id"] for l in open(REPO / "eval/manifest_heldout.jsonl", encoding="utf-8") if l.strip()]
    rule_by_id = {**{rid: t for rid, t in gold_rules.items()}}
    def case_sets(rid):
        ids = [rid] + alternative_rule_ids(manifest[rid], ref_index)
        out = []
        for i in ids:
            if i in sets_gold:
                out.append(sets_gold[i])
            elif i in index:
                out.append(human_set(text(i), i))
        return out
    held_sets = {rid: case_sets(rid) for rid in held if rid in manifest}
    def load(name):
        return {json.loads(l)["rule_id"]: json.loads(l) for l in open(REPO / f"eval/results/{name}.jsonl", encoding="utf-8")}
    runs = {arm: [load(f"{arm}_heldout_r{i}") for i in (1, 2, 3)] for arm in ("may", "main")}
    def hit(rules, rid):
        s = case_score(rules, held_sets[rid])
        return None if s["miss"] == "no human events" else float(s["hit"])
    per_case = {}
    for arm, arm_runs in runs.items():
        for rid in held_sets:
            vals = [hit(run[rid].get("rules_yaml") or [], rid) for run in arm_runs if rid in run]
            vals = [v for v in vals if v is not None]
            if vals:
                per_case.setdefault(rid, {})[arm] = sum(vals) / len(vals)
    paired = [(v["may"], v["main"]) for v in per_case.values() if "may" in v and "main" in v]
    diffs = [b - a for a, b in paired]
    v4 = {"n": len(paired), "may": sum(a for a, _ in paired) / len(paired), "main": sum(b for _, b in paired) / len(paired),
          "diff": sum(diffs) / len(diffs), "ci": bootstrap_ci(diffs)}
    perm = derangement(sorted(held_sets), seed=0)
    null_case = {}
    for rid in held_sets:
        vals = [hit(run[perm[rid]].get("rules_yaml") or [], rid) for run in runs["main"] if perm[rid] in run]
        vals = [v for v in vals if v is not None]
        if vals:
            null_case[rid] = sum(vals) / len(vals)
    v5 = {"n": len(null_case), "null": sum(null_case.values()) / len(null_case),
          "real": v4["main"]}

    ok1r, n1r = _rate(v1_rec)
    ok1g, n1g = _rate(v1_gold)
    metrics = {"V1": min(ok1r / n1r, ok1g / n1g), "V2": v2["false_fires"] / v2["real_non_pairs"],
               "V3": v3_fires / v3_pairs, "V4_ci_low": v4["ci"][0], "V5": v5["null"], "V5_real": v5["real"]}
    result = {"metrics": metrics, "verdicts": verdicts(metrics),
              "V1": {"recordings": {"ok": ok1r, "buildable": n1r, "rules": len(v1_rec),
                                    "unbuildable": sum(1 for r in v1_rec.values() if not r["built"]),
                                    "failing": [k for k, r in v1_rec.items() if r["built"] and r["verified"] < r["built"]],
                                    "cannot": dict(Counter(c for r in v1_rec.values() for c in r["cannot"]))},
                     "gold": {"ok": ok1g, "buildable": n1g, "rules": len(v1_gold),
                              "unbuildable": sum(1 for r in v1_gold.values() if not r["built"]),
                              "failing": [k for k, r in v1_gold.items() if r["built"] and r["verified"] < r["built"]],
                              "cannot": dict(Counter(c for r in v1_gold.values() for c in r["cannot"]))}},
              "V2": v2, "V3": {"pairs": v3_pairs, "fires": v3_fires, "fired": v3_list}, "V4": v4, "V5": v5}
    Path(args.out).write_text(json.dumps(result, indent=1), encoding="utf-8")

    r1 = result["V1"]
    print(f"V1 rule fires on its own built events: recordings {ok1r}/{n1r} (unbuildable {r1['recordings']['unbuildable']} of "
          f"{r1['recordings']['rules']}), gold {ok1g}/{n1g} (unbuildable {r1['gold']['unbuildable']} of {r1['gold']['rules']})")
    print(f"   cannot build: recordings {r1['recordings']['cannot']}; gold {r1['gold']['cannot']}")
    print(f"   failing: recordings {[f[:8] for f in r1['recordings']['failing']]}; gold {[f[:8] for f in r1['gold']['failing']]}")
    print(f"V2 synthetic vs real (logic): false fires {v2['false_fires']} of {v2['real_non_pairs']} real non-pairs "
          f"({metrics['V2']:.4f}); related pairs caught {v2['related_caught']} of {v2['related_pairs']}; self {v2['self_caught']} of {v2['self_pairs']}")
    print(f"V3 unrelated gold rules: {v3_fires} of {v3_pairs} pairs fire ({metrics['V3']:.4f})")
    print(f"V4 replay hit on held-out (k=3): May {v4['may']:.3f}, today {v4['main']:.3f}, diff {v4['diff']:+.3f} "
          f"95% CI [{v4['ci'][0]:+.3f}, {v4['ci'][1]:+.3f}] (n={v4['n']})")
    print(f"V5 null (shuffled rules): {v5['null']:.3f} vs real {v5['real']:.3f} (n={v5['n']})")
    print("VERDICTS:", result["verdicts"], "-> ALL PASS" if all(result["verdicts"].values()) else "-> NOT ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
