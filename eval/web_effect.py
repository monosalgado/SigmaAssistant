#!/usr/bin/env python3
"""What the web stage changes in the rules (Change 45's two-arm run; measures fixed in the log before the run).

Per case:
- web strings: the strings the digest kept (`pipeline.web_enrichment.digest.kept`); **new** ones are absent from the
  report's text (>= 6 characters, `diagnose_detection.grounded`, as CH6 §6.5c);
- used: the new web strings the first rule's detection values match (`scorers.value_matches`, the web string as the
  reference); and any rule's (only the first is scored; any shows whether web strings reach the rules at all);
- the human rule's values the report lacks (>= 6 characters), those the web offers (a kept string matches), and those
  the first rule has - per arm, the mechanism: does the web bring the human's missing values into the rule?
- leaks: pages the stage kept whose text holds the gold rule's `id` (rule pages are dropped in the evaluation; this
  checks what got through), read from the saved answers file.

Usage:
    .venv/bin/python eval/web_effect.py --a A.jsonl --b B.jsonl --snapshots eval/web_snapshots/tuning60.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.diagnose_detection import grounded  # noqa: E402
from eval.scorers import extract_detection_values, normalise_value, value_matches  # noqa: E402

MIN_CHARS = 6


def kept_strings(row: dict) -> list:
    digest = (((row.get("pipeline") or {}).get("web_enrichment") or {}).get("digest") or {})
    return [s for item in digest.get("kept") or [] for s in item.get("strings") or []]


def new_strings(strings: list, report_text: str, min_chars: int = MIN_CHARS) -> list:
    out = []
    for s in strings:
        v = normalise_value(s)
        if v and grounded(v, report_text, min_chars) is False and v not in out:
            out.append(v)
    return out


def rule_values(row: dict, first_only: bool = True) -> set:
    rules = row.get("rules_yaml") or []
    out = set()
    for text in rules[:1] if first_only else rules:
        try:
            rule = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        detection = rule.get("detection") if isinstance(rule, dict) else None
        out |= {v for _, v in extract_detection_values(detection)}
    return out


def uses(rule_vals: set, web: list) -> list:
    return [w for w in web if any(value_matches(w, v) for v in rule_vals)]


def human_gain(gold_values: set, report_text: str, web: list, rule_vals: set) -> dict:
    lacking = [g for _, g in gold_values if grounded(g, report_text, MIN_CHARS) is False]
    return {"lacking": len(lacking),
            "offered": sum(1 for g in lacking if any(value_matches(g, w) for w in web)),
            "found": sum(1 for g in lacking if any(value_matches(g, v) for v in rule_vals))}


def leaks(row: dict, gold_rule: dict, pages: dict) -> int:
    web = (row.get("pipeline") or {}).get("web_enrichment") or {}
    query = (web.get("search_queries") or [""])[0]
    gid = str(gold_rule.get("id") or "").lower()
    if not gid:
        return 0
    return sum(1 for r in web.get("results") or [] if r.get("reason") is None
               and gid in (pages.get((query, r.get("url"))) or "").lower())


def case_measures(row: dict, gold_rule: dict, report_text: str, pages: dict) -> dict:
    web_all = kept_strings(row)
    web_new = new_strings(web_all, report_text)
    vals = rule_values(row)
    gain = human_gain(extract_detection_values(gold_rule.get("detection")), report_text,
                      [normalise_value(s) for s in web_all if normalise_value(s)], vals)
    return {"web_strings": len(web_all), "new_strings": len(web_new), "used_new": len(uses(vals, web_new)),
            "used_new_any_rule": len(uses(rule_values(row, first_only=False), web_new)),
            **gain, "leaks": leaks(row, gold_rule, pages)}


def load_pages(path) -> dict:
    """{(query, url): page text} from a saved answers file."""
    pages = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            for p in r.get("results") or []:
                pages[(r["query"], p.get("url"))] = p.get("content") or ""
    return pages


def summarise(measures: dict) -> dict:
    ms = list(measures.values())
    out = {k: sum(m[k] for m in ms) for k in ("web_strings", "new_strings", "used_new", "used_new_any_rule",
                                              "lacking", "offered", "found", "leaks")}
    out.update(cases=len(ms), with_web=sum(1 for m in ms if m["web_strings"]),
               using_new=sum(1 for m in ms if m["used_new"]),
               using_new_any=sum(1 for m in ms if m["used_new_any_rule"]), with_found=sum(1 for m in ms if m["found"]),
               with_leak=sum(1 for m in ms if m["leaks"]))
    return out


def main(argv: list = None) -> int:
    import contextlib
    import io

    from eval.diagnose_detection import _case_text
    from eval.run_eval import load_cases, load_github_manifest
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--a", required=True, help="web off")
    parser.add_argument("--b", required=True, help="web on")
    parser.add_argument("--snapshots", required=True, help="the saved answers arm B read")
    args = parser.parse_args(argv)
    with contextlib.redirect_stdout(io.StringIO()):
        cases = {c["rule_id"]: c for c in load_cases(REPO / "eval/manifest.jsonl", REPO, 2000)}
    url_map = load_github_manifest(REPO / "eval/github_manifest.jsonl")
    pages = load_pages(args.snapshots)
    arms = {}
    for label, path in (("A", args.a), ("B", args.b)):
        arms[label] = {json.loads(l)["rule_id"]: json.loads(l) for l in open(path, encoding="utf-8") if l.strip()}
    common = sorted(set(arms["A"]) & set(arms["B"]))
    texts, results = {}, {"A": {}, "B": {}}
    for rid in common:
        if rid not in cases:
            continue
        texts[rid] = _case_text(cases[rid], url_map)
        for label in ("A", "B"):
            row = arms[label][rid]
            gold = yaml.safe_load((REPO / row["rule_path"]).read_text(encoding="utf-8")) or {}
            results[label][rid] = case_measures(row, gold, texts[rid], pages)
    print(f"{len(results['B'])} cases in both arms")
    for label in ("A", "B"):
        s = summarise(results[label])
        print(f"\n{label}: web strings kept {s['web_strings']} in {s['with_web']} cases; new to the report "
              f"{s['new_strings']}; used by the first rule {s['used_new']} (cases {s['using_new']}), by any rule "
              f"{s['used_new_any_rule']} (cases {s['using_new_any']})")
        print(f"   human values the report lacks {s['lacking']}; offered by the web {s['offered']}; "
              f"found by the first rule {s['found']} (cases {s['with_found']}); leaks {s['leaks']} "
              f"(cases {s['with_leak']})")
    a, b = results["A"], results["B"]
    more = sum(1 for rid in b if b[rid]["found"] > a[rid]["found"])
    fewer = sum(1 for rid in b if b[rid]["found"] < a[rid]["found"])
    print(f"\npaired: the first rule has more of the human's missing values in B in {more} cases, fewer in {fewer}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
