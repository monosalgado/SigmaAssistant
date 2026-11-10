#!/usr/bin/env python3
"""Change 55, step 1 (plan in the log 2026-11-09): the change's own rule - `keep_runnable` from the review stage - applied
to the saved rows of runs that kept the rules before review (`pipeline.pre_review_rules`).

**A simulation, labelled so.** Exact for the revert itself (the decision depends only on the rules before and after
review, both saved); the coverage-directed regeneration after review may behave differently live, and is not
simulated. Both sides are scored with today's scorer (`score_case`), so that only the rules differ.

Per run, paired by case: final rules that cannot run, S1r (the first rule runs), S3u and S5u (as the user gets them,
`compare_arms`), as recorded and as simulated, with bootstrap 95% CIs of the differences.

Usage:
    .venv/bin/python eval/simulate_keep_runnable.py <result files...> [--scope windows-linux] [--out <file.json>]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from backend.pipeline.stage_review import keep_runnable  # noqa: E402
from eval.compare_arms import run_value  # noqa: E402
from eval.compare_runs import bootstrap_ci  # noqa: E402
from eval.runnable_rules import can_run  # noqa: E402
from eval.scope import SCOPES, in_scope  # noqa: E402
from eval.scorers import score_case, score_detection_fields  # noqa: E402

METRICS = ("S1r", "S3u", "S5u")


def simulate_rules(row: dict) -> tuple:
    """(the final rules as Change 55 would return them, the reverts)."""
    before = [{"yaml_content": t} for t in (row.get("pipeline") or {}).get("pre_review_rules") or []]
    after = [{"yaml_content": t, "changes_made": []} for t in row.get("rules_yaml") or []]
    final, reverted = keep_runnable(before, after)
    return [r["yaml_content"] for r in final], reverted


def _values(row: dict, rules: list, gold: dict, gold_has_fields: bool) -> dict:
    scored = {**row, "rules_yaml": rules, "scores": score_case(rules[0] if rules else "", gold)}
    out = {m: run_value(scored, m, gold_has_fields) for m in METRICS}
    out["cannot_run"] = sum(not can_run(t)["runs"] for t in rules)
    return out


def simulate_run(rows: list) -> dict:
    rows = [r for r in rows if (r.get("pipeline") or {}).get("pre_review_rules") and r.get("rules_yaml") is not None]
    golds, recorded, simulated, reverted_rules, with_revert = {}, [], [], 0, 0
    for row in rows:
        path = REPO / row["rule_path"]
        gold = golds.setdefault(str(path), yaml.safe_load(path.read_text(encoding="utf-8")) or {})
        has_fields = (score_detection_fields({}, gold.get("detection")) or {}).get("n_gold", 0) > 0
        sim_rules, reverted = simulate_rules(row)
        reverted_rules += sum(1 if r.get("rule") else len(row.get("rules_yaml") or []) for r in reverted)
        with_revert += bool(reverted)
        recorded.append(_values(row, row.get("rules_yaml") or [], gold, has_fields))
        simulated.append(_values(row, sim_rules, gold, has_fields))
    out = {"cases": len(rows), "reverted_rules": reverted_rules, "cases_with_a_revert": with_revert,
           "cannot_run": {"recorded": sum(r["cannot_run"] for r in recorded),
                          "simulated": sum(s["cannot_run"] for s in simulated)}}
    for metric in METRICS:
        pairs = [(float(r[metric]), float(s[metric])) for r, s in zip(recorded, simulated)
                 if r[metric] is not None and s[metric] is not None]
        diffs = [s - r for r, s in pairs]
        n = len(pairs)
        out[metric] = {"n": n, "recorded": sum(r for r, _ in pairs) / n if n else None,
                       "simulated": sum(s for _, s in pairs) / n if n else None,
                       "diff": sum(diffs) / n if n else None, "ci": bootstrap_ci(diffs) if n else None}
    return out


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results", nargs="+", type=Path)
    parser.add_argument("--scope", choices=sorted(SCOPES), default=None)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    report = {}
    print(f"{'run':22} {'cases':>5} {'reverted':>8} {'cannot run rec→sim':>18}   "
          + "   ".join(f"{m} rec→sim (diff, 95% CI)" for m in METRICS))
    for path in args.results:
        rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        if args.scope:
            rows = [r for r in rows if in_scope(r, args.scope)]
        s = simulate_run(rows)
        report[path.name] = s
        cells = []
        for m in METRICS:
            v = s[m]
            cells.append(f"{v['recorded']:.3f}→{v['simulated']:.3f} ({v['diff']:+.3f}, [{v['ci'][0]:+.3f}, {v['ci'][1]:+.3f}])"
                         if v["n"] else "-")
        print(f"{path.stem[:22]:22} {s['cases']:>5} {s['reverted_rules']:>8} "
              f"{s['cannot_run']['recorded']:>8}→{s['cannot_run']['simulated']:<8}   " + "   ".join(cells))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({"scope": args.scope, "runs": report}, indent=1) + "\n", encoding="utf-8")
        print(f"\nsummary: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
