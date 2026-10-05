#!/usr/bin/env python3
"""Validate the rule evaluator (`rule_matcher.py`) on SigmaHQ's regression recordings (definition fixed in the log
2026-10-04, before the first pass).

Each recording (`data/sigma/regression_data/**/info.yml`) names one rule by id and the number of events it must
match (`match_count`; absent = at least 1). The rule, found by id under `data/sigma/rules*` and `deprecated`, runs over
the recording's JSON events; it **agrees** when the number of matching events is the expected one. No JSON, no rule,
or "cannot evaluate" is listed apart with its reason. Descriptive: every evaluable rule against the other
recordings' events (off-target matches, each listed - some may be genuine).

Usage:
    .venv/bin/python eval/validate_matcher.py [--out eval/results/matcher_validation.jsonl]
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

from eval.rule_matcher import CannotEvaluate, load_events, parse_rule, rule_matches  # noqa: E402

SIGMA = REPO / "data/sigma"


def rule_index(dirs: list) -> dict:
    index = {}
    for d in dirs:
        for path in Path(d).rglob("*.yml"):
            try:
                rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(rule, dict) and rule.get("id"):
                index.setdefault(str(rule["id"]), path)
    return index


def _count(parsed, events) -> int:
    return sum(1 for e in events if rule_matches(parsed, e))


def check_recording(info_path, index: dict) -> dict:
    info_path = Path(info_path)
    info = yaml.safe_load(info_path.read_text(encoding="utf-8")) or {}
    rule_id = str(((info.get("rule_metadata") or [{}])[0]).get("id"))
    tests = [t for t in info.get("regression_tests_info") or [] if isinstance(t, dict)]
    expected = tests[0].get("match_count") if tests else None
    out = {"rule_id": rule_id, "recording": str(info_path.parent.relative_to(info_path.parents[2])
                                                 if len(info_path.parents) > 2 else info_path.parent),
           "expected": expected, "matched": None, "events": None, "verdict": None, "reason": ""}
    jsons = sorted(info_path.parent.glob("*.json"))
    if not jsons:
        out["verdict"] = "no JSON"
        return out
    if rule_id not in index:
        out.update(verdict="rule not found")
        return out
    try:
        parsed = parse_rule(index[rule_id].read_text(encoding="utf-8"))
        events = [e for j in jsons for e in load_events(j)]
        matched = _count(parsed, events)
    except CannotEvaluate as exc:
        out.update(verdict="cannot evaluate", reason=str(exc)[:200])
        return out
    agree = matched >= 1 if expected is None else matched == expected
    out.update(matched=matched, events=len(events), verdict="agree" if agree else "disagree")
    return out


def off_target(rule_id: str, index: dict, recordings: list) -> list:
    """[(other recording's rule id, events of it this rule matches)], for those with at least one."""
    parsed = parse_rule(index[rule_id].read_text(encoding="utf-8"))
    out = []
    for rec in recordings:
        if rec["rule_id"] == rule_id:
            continue
        try:
            n = _count(parsed, rec["events"])
        except CannotEvaluate:
            continue
        if n:
            out.append((rec["rule_id"], n))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=str(REPO / "eval/results/matcher_validation.jsonl"))
    args = parser.parse_args()
    index = rule_index([d for d in SIGMA.iterdir() if d.is_dir() and (d.name.startswith("rules") or d.name == "deprecated")])
    infos = sorted((SIGMA / "regression_data").rglob("info.yml"))
    results = [check_recording(i, index) for i in infos]
    recordings = []
    for info, r in zip(infos, results):
        jsons = sorted(info.parent.glob("*.json"))
        if jsons:
            recordings.append({"rule_id": r["rule_id"], "events": [e for j in jsons for e in load_events(j)]})
    for r in results:
        r["off_target"] = off_target(r["rule_id"], index, recordings) if r["verdict"] in ("agree", "disagree") else []
    with open(args.out, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
    verdicts = Counter(r["verdict"] for r in results)
    evaluable = verdicts["agree"] + verdicts["disagree"]
    print(f"{len(results)} recordings: {dict(verdicts)}")
    print(f"agreement on the evaluable ones: {verdicts['agree']} of {evaluable}")
    for r in results:
        if r["verdict"] not in ("agree",):
            print(f"  {r['verdict']:16} {r['rule_id'][:8]} matched {r['matched']} of {r['events']} (expected "
                  f"{r['expected']}) {r['reason'][:110]}")
    hits = [r for r in results if r["off_target"]]
    print(f"rules matching other recordings' events: {len(hits)}")
    for r in hits:
        print(f"  {r['rule_id'][:8]} -> {[(o[:8], n) for o, n in r['off_target']]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
