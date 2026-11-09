#!/usr/bin/env python3
"""How often our rules cannot run, before and after review, in the past runs (plan in the log 2026-11-09; offline,
post-hoc; no earlier result changes).

A rule **runs** when pySigma loads it (`SigmaCollection.from_yaml`, as S1 does) **and every condition parses**
(`parsed_condition[i].parse()`, which S1 skips). A lower bound: a conversion can also fail for other reasons.

Per run: final rules that cannot run; S1 as recorded and corrected (the share of first rules that run); first rules
S1 calls valid that cannot run; first rules that cannot run whose log source S3 counts as right. For runs that saved
the rules before review (`pipeline.pre_review_rules`, since Change 42): rules that cannot run before review, and rules
broken and fixed by review (compared by position when review kept the number of rules).

Usage:
    .venv/bin/python eval/runnable_rules.py <result files...> [--scope windows-linux] [--out <file.json>]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from sigma.collection import SigmaCollection  # noqa: E402

from eval.scope import SCOPES, in_scope  # noqa: E402
from eval.scorers import strip_code_fences  # noqa: E402


def can_run(rule_text: str) -> dict:
    text = strip_code_fences(rule_text or "")
    if not text:
        return {"loads": False, "runs": False, "error": "empty"}
    try:
        collection = SigmaCollection.from_yaml(text)
    except Exception as e:  # noqa: BLE001 - pySigma raises several undeclared types, as S1 handles them
        return {"loads": False, "runs": False, "error": f"{type(e).__name__}: {e}"[:200]}
    if not collection.rules:
        return {"loads": False, "runs": False, "error": "no rules in document"}
    try:
        for rule in collection.rules:
            for condition in rule.detection.parsed_condition:
                condition.parse()
    except Exception as e:  # noqa: BLE001
        return {"loads": True, "runs": False, "error": f"{type(e).__name__}: {e}"[:200]}
    return {"loads": True, "runs": True, "error": None}


def review_effect(before: list, after: list) -> dict:
    """1-based positions of rules broken (ran before review, not after) and fixed (the reverse), when review kept the
    number of rules; None when it changed it."""
    if len(before) != len(after):
        return {"same_count": False, "broken": None, "fixed": None}
    ran_before = [can_run(t)["runs"] for t in before]
    ran_after = [can_run(t)["runs"] for t in after]
    return {"same_count": True,
            "broken": [i for i, (b, a) in enumerate(zip(ran_before, ran_after), 1) if b and not a],
            "fixed": [i for i, (b, a) in enumerate(zip(ran_before, ran_after), 1) if a and not b]}


def run_summary(rows: list) -> dict:
    cases = len(rows)
    rules = [t for r in rows for t in (r.get("rules_yaml") or [])]
    s1 = s1c = first_valid_not_run = first_not_run_s3 = 0
    for row in rows:
        scores = row.get("scores") or {}
        parses = bool((scores.get("validity") or {}).get("parses"))
        first = (row.get("rules_yaml") or [None])[0]
        runs = can_run(first)["runs"] if first is not None else False
        s1 += parses
        s1c += runs
        first_valid_not_run += parses and not runs
        first_not_run_s3 += (not runs) and bool((scores.get("logsource") or {}).get("exact_match"))
    with_pre = [r for r in rows if (r.get("pipeline") or {}).get("pre_review_rules")]
    out = {"cases": cases, "rules": len(rules), "rules_cannot_run": sum(not can_run(t)["runs"] for t in rules),
           "s1": s1 / cases if cases else None, "s1_corrected": s1c / cases if cases else None,
           "first_valid_but_cannot_run": first_valid_not_run, "first_cannot_run_but_s3_right": first_not_run_s3,
           "cases_with_before_review": len(with_pre), "before_rules": None, "before_cannot_run": None,
           "broken_by_review": None, "fixed_by_review": None, "review_changed_count": None}
    if with_pre:
        before = [t for r in with_pre for t in r["pipeline"]["pre_review_rules"]]
        effects = [review_effect(r["pipeline"]["pre_review_rules"], r.get("rules_yaml") or []) for r in with_pre]
        out.update(before_rules=len(before), before_cannot_run=sum(not can_run(t)["runs"] for t in before),
                   broken_by_review=sum(len(e["broken"]) for e in effects if e["same_count"]),
                   fixed_by_review=sum(len(e["fixed"]) for e in effects if e["same_count"]),
                   review_changed_count=sum(not e["same_count"] for e in effects))
    return out


def _rows(path) -> list:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results", nargs="+", type=Path)
    parser.add_argument("--scope", choices=sorted(SCOPES), default=None)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    report = {}
    print(f"{'run':30} {'cases':>5} {'rules':>6} {'cannot run':>10} {'S1':>6} {'S1 corr':>7} {'1st valid, no run':>17} "
          f"{'1st no run, S3 right':>20} {'before: cannot run':>18} {'broken':>6} {'fixed':>5}")
    for path in args.results:
        rows = [r for r in _rows(path) if r.get("rules_yaml") is not None]
        if args.scope:
            rows = [r for r in rows if in_scope(r, args.scope)]
        s = run_summary(rows)
        report[path.name] = s
        before = (f"{s['before_cannot_run']}/{s['before_rules']}" if s["before_rules"] is not None else "-")
        print(f"{path.stem[:30]:30} {s['cases']:>5} {s['rules']:>6} {s['rules_cannot_run']:>10} {s['s1']:>6.3f} "
              f"{s['s1_corrected']:>7.3f} {s['first_valid_but_cannot_run']:>17} {s['first_cannot_run_but_s3_right']:>20} "
              f"{before:>18} {str(s['broken_by_review'] if s['broken_by_review'] is not None else '-'):>6} "
              f"{str(s['fixed_by_review'] if s['fixed_by_review'] is not None else '-'):>5}")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({"scope": args.scope, "runs": report}, indent=1) + "\n", encoding="utf-8")
        print(f"\nsummary: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
