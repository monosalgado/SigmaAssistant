#!/usr/bin/env python3
"""Technique counts for Changes 31 (plan 2.7, ATT&CK ID check) and 32 (plan 2.8, at most
10 techniques), fixed before their run. Offline: reads a finished result file.

Per case:
- written       technique IDs the analysis stage wrote (after Change 31: the kept
                `ttp_mappings` plus the recorded `ttp_dropped_ids`)
- invalid       written IDs that ATT&CK does not have (e.g. T1562.339 from a loop)
- rule_invalid  technique tags in the generated rules that ATT&CK does not have
- cut           answers cut at the output limit (Change 24)
The valid IDs are `backend/pipeline/attack_technique_ids.json`, built from the local
ATT&CK collection by `scripts/build_attack_technique_ids.py`.

Usage:
    .venv/bin/python eval/count_techniques.py eval/results/<run>.jsonl
"""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.scorers import extract_techniques  # noqa: E402

VALID_IDS_PATH = REPO / "backend/pipeline/attack_technique_ids.json"


def load_valid_ids(path: Path = VALID_IDS_PATH) -> set:
    return {str(i).strip().upper() for i in json.loads(Path(path).read_text(encoding="utf-8"))}


def technique_ids(mappings) -> list:
    ids = []
    for m in mappings or []:
        if isinstance(m, dict):
            tid = str(m.get("technique_id") or "").strip().upper()
            if tid:
                ids.append(tid)
    return ids


def written_ids(row: dict) -> list:
    pipeline = row.get("pipeline") or {}
    dropped = [str(i).strip().upper() for i in pipeline.get("ttp_dropped_ids") or []]
    return technique_ids(pipeline.get("ttp_mappings")) + dropped


def rule_tag_ids(row: dict) -> set:
    rules = row.get("rules_yaml") or []
    found = set()
    for text in [rules] if isinstance(rules, str) else rules:
        try:
            rule = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if isinstance(rule, dict):
            found |= {t.upper() for t in extract_techniques(rule.get("tags"))}
    return found


def case_measures(row: dict, valid: set) -> dict:
    written = written_ids(row)
    return {
        "written": len(written),
        "invalid": [i for i in written if i not in valid],
        "rule_invalid": sorted(i for i in rule_tag_ids(row) if i not in valid),
        "cut": (row.get("telemetry") or {}).get("calls_output_limited", 0),
    }


def summarise(measures: list) -> dict:
    written = [m["written"] for m in measures]
    return {
        "n": len(measures),
        "median": statistics.median(written) if written else 0,
        "max": max(written) if written else 0,
        "over_10": sum(1 for w in written if w > 10),
        "invalid_cases": sum(1 for m in measures if m["invalid"]),
        "invalid_total": sum(len(m["invalid"]) for m in measures),
        "rule_invalid_cases": sum(1 for m in measures if m["rule_invalid"]),
        "cut_cases": sum(1 for m in measures if m["cut"]),
    }


def main(argv: list) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 1
    if not VALID_IDS_PATH.is_file():
        print(f"{VALID_IDS_PATH} not found: run scripts/build_attack_technique_ids.py first.")
        return 1
    valid = load_valid_ids()
    rows = [json.loads(l) for l in Path(argv[1]).read_text(encoding="utf-8").splitlines() if l.strip()]
    measures = [case_measures(r, valid) for r in rows]
    s = summarise(measures)
    print(f"{argv[1]}: {s['n']} cases ({len(valid)} valid ATT&CK IDs)")
    print(f"  techniques written per case : median {s['median']}, max {s['max']}, over 10 in {s['over_10']} cases")
    print(f"  invented IDs (not in ATT&CK): {s['invalid_total']} in {s['invalid_cases']} cases")
    print(f"  rules tagged with an invented technique: {s['rule_invalid_cases']} cases")
    print(f"  cases with an answer cut at the limit   : {s['cut_cases']}")
    for r, m in zip(rows, measures):
        if m["invalid"] or m["rule_invalid"]:
            print(f"    {r['rule_id'][:8]}  written {m['invalid'][:6]}{'…' if len(m['invalid']) > 6 else ''}"
                  f"  rules {m['rule_invalid']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
