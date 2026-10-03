#!/usr/bin/env python3
"""Change 38 v3's ranking step, measured inside one run.

Every row of a v3 run records the analysis's own order of log sources (`logsource_ranking.before`) and the
order after the ranking step (`after`; the saved suggestions). Both top picks are scored against the gold
and the other human rules for the same report (`alternative_logsources.classify`, as P / Pany in
`compare_arms.py`), so the step's effect is read on the same answers - free of run-to-run variation. For the
cases whose top pick changed, the first rule's log source is compared with the new and the old top pick.

Usage:
    .venv/bin/python eval/ranking_effect.py eval/results/c38v3_tuning60.jsonl [--manifest eval/manifest.jsonl]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from backend.pipeline.sigma_logsource import _clean  # noqa: E402
from eval.alternative_logsources import classify  # noqa: E402

FIELDS = ("category", "product", "service")
RIGHT = ("gold", "another human rule")


def _name(logsource: dict) -> str:
    """A log source in the record's form: its cleaned fields joined by '/'."""
    return "/".join(v for v in (_clean(logsource.get(f)) for f in FIELDS) if v)


def top_before_after(row: dict):
    """(the analysis's own top pick, the top pick after the ranking step); None when there was none."""
    pipeline = row.get("pipeline") or {}
    suggestions = [s for s in pipeline.get("logsource_suggestions") or [] if isinstance(s, dict)]
    before = (pipeline.get("logsource_ranking") or {}).get("before") or []
    if not suggestions or not before:
        return None, None
    by_name = {_name(s): s for s in suggestions}      # the step keeps every earlier suggestion
    return by_name.get(before[0]), suggestions[0]


def first_rule_name(row: dict) -> str:
    rules = row.get("rules_yaml") or []
    if not rules:
        return "(no rule)"
    try:
        rule = yaml.safe_load(rules[0])
    except yaml.YAMLError:
        return "(does not parse)"
    if not isinstance(rule, dict):
        return "(does not parse)"
    return _name(rule.get("logsource") or {}) or "(none)"


def effect(rows: list, picks: dict) -> dict:
    """picks: rule_id -> (gold log source, other human rules' log sources)."""
    out = {"cases": 0, "ran": 0, "errors": 0, "changed_top": 0, "added": 0, "refused": 0,
           "P_before": 0, "P_after": 0, "Pany_before": 0, "Pany_after": 0,
           "moves": Counter(), "rule_follows": Counter(), "changed": []}
    for row in rows:
        if row["rule_id"] not in picks:
            continue
        gold, alts = picks[row["rule_id"]]
        record = (row.get("pipeline") or {}).get("logsource_ranking") or {}
        out["cases"] += 1
        out["ran"] += bool(record.get("ran"))
        out["errors"] += bool(record.get("error"))
        out["added"] += bool(record.get("added"))
        out["refused"] += bool(record.get("dropped"))
        before, after = top_before_after(row)
        b, a = classify(before, gold, alts), classify(after, gold, alts)
        out["P_before"] += b == "gold"
        out["P_after"] += a == "gold"
        out["Pany_before"] += b in RIGHT
        out["Pany_after"] += a in RIGHT
        if before is not None and _name(before) != _name(after):
            out["changed_top"] += 1
            out["moves"][(b, a)] += 1
            out["changed"].append((row["rule_id"], _name(before), _name(after), _name(gold)))
            rule = first_rule_name(row)
            out["rule_follows"]["new top" if rule == _name(after) else
                                "old top" if rule == _name(before) else "other"] += 1
    out["moves"], out["rule_follows"] = dict(out["moves"]), dict(out["rule_follows"])
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run")
    parser.add_argument("--manifest", default=str(REPO / "eval/manifest.jsonl"))
    parser.add_argument("--list", action="store_true", help="list the cases whose top pick changed")
    args = parser.parse_args()
    from eval.alternative_logsources import EMERGING, alternatives, reference_index
    manifest = {json.loads(l)["rule_id"]: json.loads(l) for l in open(args.manifest, encoding="utf-8") if l.strip()}
    rows = [json.loads(l) for l in open(args.run, encoding="utf-8") if l.strip()]
    index = reference_index([EMERGING])
    picks = {r["rule_id"]: (manifest[r["rule_id"]].get("logsource") or {}, alternatives(manifest[r["rule_id"]], index))
             for r in rows if r["rule_id"] in manifest}
    e = effect(rows, picks)
    n = e["cases"]
    print(f"{Path(args.run).stem}: {n} cases; ranking ran in {e['ran']}, failed in {e['errors']}; "
          f"it added a log source in {e['added']}, code refused an addition in {e['refused']}")
    print(f"  top pick changed in {e['changed_top']} of {e['ran']}")
    print(f"  P    (top = gold)                   before the step {e['P_before']} of {n}, after {e['P_after']}")
    print(f"  Pany (top = gold or a human rule)   before the step {e['Pany_before']} of {n}, after {e['Pany_after']}")
    print("  where the top changed (before -> after):")
    for (b, a), count in sorted(e["moves"].items(), key=lambda kv: -kv[1]):
        print(f"    {count:>3}  {b} -> {a}")
    print(f"  the first rule's log source, where the top changed: {e['rule_follows']}")
    moved_to = Counter(after for _, _, after, _ in e["changed"])
    print(f"  new top, where it changed: {dict(moved_to.most_common())}")
    if args.list:
        for rid, before, after, gold in e["changed"]:
            print(f"    {rid[:8]}  {before:<30} -> {after:<30} gold {gold}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
