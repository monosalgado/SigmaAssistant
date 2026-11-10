#!/usr/bin/env python3
"""Change 54's mechanism measures, as fixed in its plan (log 2026-11-08; read C against B since 2026-11-09).

  M1  cases where the second run's footprint has a step on SigmaHQ's table
  M2  cases with at least one rule using a parent-process field (`ParentImage`, `ParentCommandLine`), first run
      against second, paired, exact McNemar - the measure that must rise
  M3  adherence, in the second run: of the cases with a footprint step on the table, those with a rule in such a
      step's log source; and, of the cases with a `starts` step on the table, those with a rule that uses a
      parent-process field. The plan does not say whether that rule must be in the step's own log source, so both
      readings are counted.
  Descriptive (log 2026-11-09): rules that treat a module as a program - `Image` ending in `.dll` or `.sys` in a
  `process_creation` rule - in both runs.

Usage:
    .venv/bin/python eval/footprint_measures.py --a B.jsonl --b C.jsonl --scope windows-linux
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from backend.pipeline.sigma_logsource import _clean, detection_fields  # noqa: E402
from eval.compare_runs import mcnemar  # noqa: E402
from eval.scope import SCOPES, in_scope  # noqa: E402
from eval.scorers import strip_code_fences  # noqa: E402

PARENT_FIELDS = frozenset({"ParentImage", "ParentCommandLine"})
MODULE_ENDINGS = (".dll", ".sys")


def _rule(text: str) -> Optional[dict]:
    try:
        rule = yaml.safe_load(strip_code_fences(text or ""))
    except yaml.YAMLError:
        return None
    return rule if isinstance(rule, dict) else None


def _source(rule: dict) -> tuple:
    logsource = rule.get("logsource") if isinstance(rule.get("logsource"), dict) else {}
    return _clean(logsource.get("category")), _clean(logsource.get("product")), _clean(logsource.get("service"))


def uses_parent_field(rule_text: str) -> bool:
    rule = _rule(rule_text)
    return bool(rule) and bool(PARENT_FIELDS & detection_fields(rule.get("detection")))


def _in_step_source(step: dict, rule: dict) -> bool:
    label = str(step.get("log_source") or "").strip().lower()
    category, product, service = _source(rule)
    if "/" in label:
        want_product, want_service = (part.strip() or None for part in label.split("/", 1))
        return category is None and product == want_product and service == want_service
    return bool(label) and category == label


def step_followed(step: dict, rule_texts: list) -> bool:
    """Is a rule in the step's log source: its category, or its product and service?"""
    return any(_in_step_source(step, rule) for rule in map(_rule, rule_texts or []) if rule)


def module_as_program(rule_text: str) -> bool:
    """A `process_creation` rule whose `Image` ends in `.dll` or `.sys`."""
    rule = _rule(rule_text)
    if not rule or _source(rule)[0] != "process_creation":
        return False
    detection = rule.get("detection") if isinstance(rule.get("detection"), dict) else {}
    found = []

    def walk(node, is_image):
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, str(key).split("|")[0].strip() == "Image")
        elif isinstance(node, list):
            for item in node:
                walk(item, is_image)
        elif is_image and node is not None:
            found.append(str(node).strip().strip("*").lower())

    for name, selection in detection.items():
        if str(name).strip().lower() not in ("condition", "timeframe"):
            walk(selection, False)
    return any(value.endswith(MODULE_ENDINGS) for value in found)


def case_measures(row: dict) -> dict:
    rules = list(row.get("rules_yaml") or [])
    steps = [s for s in ((row.get("pipeline") or {}).get("attack_vector") or {}).get("host_footprint") or []
             if isinstance(s, dict)]
    on_table = [s for s in steps if s.get("on_table")]
    starts = [s for s in on_table if str(s.get("action") or "").strip().lower() == "starts"]
    parents = [rule for rule in map(_rule, rules) if rule and PARENT_FIELDS & detection_fields(rule.get("detection"))]
    return {
        "rule_id": row.get("rule_id"),
        "steps": len(steps), "on_table": len(on_table),
        "actions": [str(s.get("action") or "").strip().lower() for s in steps],
        "m1": bool(on_table),
        "parent_rule": bool(parents),
        "m3_source": any(step_followed(s, rules) for s in on_table) if on_table else None,
        "m3_parent": bool(parents) if starts else None,
        "m3_parent_in_source": (any(_in_step_source(s, rule) for s in starts for rule in parents) if starts else None),
        "module_as_program": sum(1 for text in rules if module_as_program(text)),
    }


def _followed(cases: list, key: str) -> dict:
    asked = [c for c in cases if c[key] is not None]
    return {"followed": sum(1 for c in asked if c[key]), "of": len(asked)}


def _modules(cases: list) -> dict:
    return {"rules": sum(c["module_as_program"] for c in cases), "cases": sum(1 for c in cases if c["module_as_program"])}


def summary(rows_a: list, rows_b: list) -> dict:
    a = {r["rule_id"]: case_measures(r) for r in rows_a}
    b = {r["rule_id"]: case_measures(r) for r in rows_b}
    both = [rid for rid in a if rid in b]
    cases_a, cases_b = [a[rid] for rid in both], [b[rid] for rid in both]
    return {
        "cases": len(both),
        "steps": {"total": sum(c["steps"] for c in cases_b), "on_table": sum(c["on_table"] for c in cases_b),
                  "by_action": dict(Counter(action for c in cases_b for action in c["actions"]))},
        "m1": sum(1 for c in cases_b if c["m1"]),
        "m2": mcnemar([(a[rid]["parent_rule"], b[rid]["parent_rule"]) for rid in both]),
        "m3_source": _followed(cases_b, "m3_source"),
        "m3_parent": _followed(cases_b, "m3_parent"),
        "m3_parent_in_source": _followed(cases_b, "m3_parent_in_source"),
        "module_as_program": {"a": _modules(cases_a), "b": _modules(cases_b)},
    }


def _rows(path: Path, scope: Optional[str]) -> list:
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    return [r for r in rows if r.get("rules_yaml") is not None and (not scope or in_scope(r, scope))]


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--a", required=True, type=Path, help="the run without the footprint")
    parser.add_argument("--b", required=True, type=Path, help="the run with it")
    parser.add_argument("--scope", choices=sorted(SCOPES), default=None)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    s = summary(_rows(args.a, args.scope), _rows(args.b, args.scope))
    m2 = s["m2"]
    print(f"A: {args.a.name}   B: {args.b.name}   cases in both: {s['cases']}")
    print(f"footprint steps in B: {s['steps']['total']} ({s['steps']['on_table']} on SigmaHQ's table); by action "
          f"{s['steps']['by_action']}")
    print(f"M1  cases whose footprint has a step on the table: {s['m1']}/{s['cases']}")
    print(f"M2  cases with a rule using ParentImage or ParentCommandLine: A {m2['a_true']}, B {m2['b_true']} "
          f"(only A {m2['only_a']}, only B {m2['only_b']}; exact McNemar p = {m2['p']:.3f})")
    print(f"M3  a rule in the log source of a step on the table: {s['m3_source']['followed']}/{s['m3_source']['of']}")
    print(f"M3  cases with a `starts` step on the table that have a rule with a parent-process field: "
          f"{s['m3_parent']['followed']}/{s['m3_parent']['of']} (in that step's own log source: "
          f"{s['m3_parent_in_source']['followed']}/{s['m3_parent_in_source']['of']})")
    mods = s["module_as_program"]
    print(f"descriptive  rules that treat a module as a program: A {mods['a']['rules']} in {mods['a']['cases']} cases, "
          f"B {mods['b']['rules']} in {mods['b']['cases']} cases")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({"a": args.a.name, "b": args.b.name, "scope": args.scope, **s}, indent=1) + "\n",
                            encoding="utf-8")
        print(f"summary: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
