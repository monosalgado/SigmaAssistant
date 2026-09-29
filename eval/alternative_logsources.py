#!/usr/bin/env python3
"""Wrong, or just different? The analysis stage's top log-source pick against the gold rule AND the
other human-written SigmaHQ rules for the same report (user 2026-09-29, better log-source picks).

S3 compares a pick with one gold rule, but a report often supports several valid rules: SigmaHQ has,
for Operation Triangulation, a DNS rule and a proxy rule. A pick that is not the gold's but matches
another human rule for the same report is a different valid choice, not simply a wrong one.

"The same report": a rule citing one of the case's input URLs (`references_usable`), where that URL is
cited by at most MAX_CITING rules (a generic reference - a tool's GitHub page - would link unrelated
rules). Two rule sets: SigmaHQ's emerging-threats rules (where the gold rules come from) and, as a
wider view, its main rule set too. Matching is S3's (`scorers.score_logsource`, exact).

Post-hoc and descriptive: written after looking at the tuning set's picks, to judge how much room for
improvement the log-source pick has. Offline.

Usage:
    .venv/bin/python eval/alternative_logsources.py eval/results/<run>.jsonl [...]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urldefrag

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.compare_suggestions import FIELDS, gold_form, top_suggestion  # noqa: E402
from eval.scorers import score_logsource  # noqa: E402
from backend.pipeline.sigma_logsource import _clean  # noqa: E402

MAX_CITING = 5
EMERGING = REPO / "data/sigma/rules-emerging-threats"
MAIN = REPO / "data/sigma/rules"


def norm_url(url: str) -> str:
    return urldefrag(str(url).strip())[0].rstrip("/").lower()


def reference_index(dirs: list) -> dict:
    """{normalised URL: [(rule id, log source)]} over every readable rule in the folders."""
    index = {}
    for folder in dirs:
        for path in sorted(Path(folder).rglob("*.yml")):
            try:
                rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (yaml.YAMLError, UnicodeDecodeError):
                continue
            if not isinstance(rule, dict) or not isinstance(rule.get("logsource"), dict):
                continue
            for ref in rule.get("references") or []:
                index.setdefault(norm_url(ref), []).append((str(rule.get("id")), rule["logsource"]))
    return index


def alternatives(case: dict, index: dict, max_citing: int = MAX_CITING) -> list:
    """The log sources of the other rules citing the case's report (distinct, in order found)."""
    out = []
    for url in case.get("references_usable") or []:
        citing = index.get(norm_url(url), [])
        if len(citing) > max_citing:
            continue
        for rule_id, logsource in citing:
            clean = {f: _clean(logsource.get(f)) for f in FIELDS}
            clean = {f: v for f, v in clean.items() if v}
            if rule_id != case["rule_id"] and clean not in out:
                out.append(clean)
    return out


def classify(pick, gold: dict, alts: list) -> str:
    if pick is None:
        return "no pick"
    pick = {f: _clean(pick.get(f)) for f in FIELDS}
    if score_logsource(pick, gold)["exact_match"]:
        return "gold"
    if any(score_logsource(pick, alt)["exact_match"] for alt in alts):
        return "another human rule"
    return "neither"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("runs", nargs="+")
    parser.add_argument("--manifest", default=str(REPO / "eval/manifest.jsonl"))
    parser.add_argument("--list", action="store_true", help="list the cases whose pick matches another human rule")
    args = parser.parse_args()
    cases = {json.loads(l)["rule_id"]: json.loads(l) for l in open(args.manifest, encoding="utf-8") if l.strip()}
    views = {"emerging-threats rules": reference_index([EMERGING]),
             "emerging-threats + main rules": reference_index([EMERGING, MAIN])}
    for run in args.runs:
        rows = [json.loads(l) for l in open(run, encoding="utf-8") if l.strip()]
        print(f"\n{Path(run).stem}: {len(rows)} cases (top suggestion of the analysis stage)")
        for view, index in views.items():
            counts, by_form, listed = Counter(), Counter(), []
            with_alt = 0
            for row in rows:
                case = cases[row["rule_id"]]
                gold = case.get("logsource") or {}
                alts = alternatives(case, index)
                with_alt += bool(alts)
                verdict = classify(top_suggestion(row), gold, alts)
                counts[verdict] += 1
                by_form[(gold_form(gold), verdict)] += 1
                if verdict == "another human rule":
                    listed.append((row["rule_id"][:8], top_suggestion(row), gold, row.get("title", "")[:45]))
            print(f"  {view}: cases with another rule for the same report {with_alt}; picks = gold "
                  f"{counts['gold']}, another human rule {counts['another human rule']}, neither "
                  f"{counts['neither']}, no pick {counts['no pick']}")
            for form in ("service", "web", "category"):
                n = sum(v for (f, _), v in by_form.items() if f == form)
                print(f"      gold {form:<8} (n={n}): gold {by_form[(form, 'gold')]}, another "
                      f"{by_form[(form, 'another human rule')]}, neither {by_form[(form, 'neither')]}, "
                      f"no pick {by_form[(form, 'no pick')]}")
            if args.list:
                for rid, pick, gold, title in listed:
                    print(f"      {rid} pick {pick} | gold {gold} | {title}")


if __name__ == "__main__":
    main()
