#!/usr/bin/env python3
"""Change 33's measures (prompt review item 1: the rule writer's worked example), fixed
before its run. Offline: reads a finished result file's final rules.

Per case:
- underscore / hyphen  multi-word ATT&CK tactic tags in each style (`attack.initial_access`
                       vs SigmaHQ's `attack.initial-access`); techniques and one-word tactics
                       are not counted
- example_id           rules carrying the old example's id (a valid UUID, so Change 9 kept it)
- duplicate_ids        ids used by more than one rule of the case
- placeholder_id       rules still carrying the new example's placeholder id (Change 9
                       should replace it: it is not a UUID)
- tag_warnings         pySigma "Invalid MITRE ATT&CK tagging" issues in the recorded review

Usage:
    .venv/bin/python eval/count_rule_conventions.py eval/results/<run>.jsonl
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

EXAMPLE_ID = "12345678-1234-1234-1234-123456789abc"
PLACEHOLDER_ID = "<new uuid>"
_TACTIC = re.compile(r"^attack\.([a-z]+(?:[-_][a-z]+)+)$")
_TECHNIQUE = re.compile(r"^attack\.t\d{4}", re.I)
TAG_WARNING = "Invalid MITRE ATT&CK tagging"


def tactic_tag_styles(tags) -> dict:
    styles = Counter()
    for tag in tags or []:
        tag = str(tag).strip().lower()
        if _TECHNIQUE.match(tag):
            continue
        m = _TACTIC.match(tag)
        if m:
            styles["underscore" if "_" in m.group(1) else "hyphen"] += 1
    return {"underscore": styles["underscore"], "hyphen": styles["hyphen"]}


def _rules(row: dict) -> list:
    texts = row.get("rules_yaml") or []
    parsed = []
    for text in [texts] if isinstance(texts, str) else texts:
        try:
            rule = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if isinstance(rule, dict):
            parsed.append(rule)
    return parsed


def case_measures(row: dict) -> dict:
    rules = _rules(row)
    styles = Counter()
    for rule in rules:
        styles.update(tactic_tag_styles(rule.get("tags")))
    ids = [str(r.get("id") or "").strip().lower() for r in rules if r.get("id")]
    issues = (row.get("pipeline") or {}).get("validation_issues") or []
    return {
        "underscore": styles["underscore"],
        "hyphen": styles["hyphen"],
        "example_id": ids.count(EXAMPLE_ID),
        "duplicate_ids": sum(1 for _, n in Counter(ids).items() if n > 1),
        "placeholder_id": ids.count(PLACEHOLDER_ID),
        "tag_warnings": sum(1 for i in issues
                            if isinstance(i, dict) and TAG_WARNING in str(i.get("message", ""))),
    }


def summarise(measures: list) -> dict:
    total = lambda key: sum(m[key] for m in measures)
    return {
        "n": len(measures),
        "underscore": total("underscore"),
        "hyphen": total("hyphen"),
        "tag_warnings": total("tag_warnings"),
        "example_id_rules": total("example_id"),
        "cases_with_duplicate_ids": sum(1 for m in measures if m["duplicate_ids"]),
        "placeholder_id_rules": total("placeholder_id"),
    }


def main(argv: list) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 1
    rows = [json.loads(l) for l in Path(argv[1]).read_text(encoding="utf-8").splitlines() if l.strip()]
    s = summarise([case_measures(r) for r in rows])
    print(f"{argv[1]}: {s['n']} cases")
    print(f"  multi-word tactic tags: underscore {s['underscore']}, hyphen {s['hyphen']}")
    print(f"  pySigma 'Invalid MITRE ATT&CK tagging' issues: {s['tag_warnings']}")
    print(f"  rules with the old example id: {s['example_id_rules']}; cases with a duplicate id: "
          f"{s['cases_with_duplicate_ids']}; rules with the placeholder id: {s['placeholder_id_rules']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
