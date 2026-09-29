#!/usr/bin/env python3
"""The rules the assistant wrote in its saved chats (`data/sessions.json`, local, not in git):
one row per answer with rules - the report asked about, the date, the pipeline version, each
rule's log source and whether it is complete - and the reports that were run more than once.

Written for the professor's question (2026-09-28): why were rules good one time and wrong the
next? The saved chats are the only record of the rules written before the evaluation harness
existed (September); nothing in them can be scored against a gold rule, because none of their
reports is in the evaluation corpus.

A chat carries no timestamp. A run is dated by its rules' `date:` field (the earliest), which
the generation prompt has filled from `{current_date}` since the pipeline's first commit
(7271080, 2026-03-20). The pipeline version is told apart by the stage results the chat saved:
`attack_vector` arrived with f457855 (committed 2026-05-14, in use from mid-April), the
per-attempt `generations` with ae91c46 (2026-09-23); results were saved at all only from
f11b701 (2026-04-12).

Usage:
    .venv/bin/python eval/old_sessions.py [--sessions data/sessions.json] [--until 2026-06-01]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.pipeline.sigma_logsource import load_logsource_table, on_table  # noqa: E402

_YAML_BLOCK = re.compile(r"```yaml\n(.*?)```", re.S)
_URL = re.compile(r"https?://[^\s,;)\]]+")


def rule_summary(text: str, table: dict = None) -> dict:
    """The rule's log source (category/product/service), its `date:`, whether it is complete
    (a `detection` mapping that holds a `condition`) and, given SigmaHQ's log-source table,
    whether its log source is one SigmaHQ's rules use (`sigma_logsource.on_table`)."""
    try:
        rule = yaml.safe_load(text)
    except yaml.YAMLError:
        rule = None
    if not isinstance(rule, dict):
        return {"logsource": "(does not parse)", "date": None, "complete": False,
                "on_table": None if table is None else False}
    logsource = rule.get("logsource") if isinstance(rule.get("logsource"), dict) else {}
    parts = [str(logsource[f]) for f in ("category", "product", "service") if logsource.get(f)]
    detection = rule.get("detection")
    date = rule.get("date")
    return {"logsource": "/".join(parts) or "(none)",
            "date": None if date is None else str(date).replace("/", "-"),
            "complete": isinstance(detection, dict) and "condition" in detection,
            "on_table": None if table is None else on_table(logsource, table)}


def code_era(meta) -> str:
    """The commit that introduced the newest stage result the answer saved."""
    if not meta:
        return "no stage results saved"
    if "generations" in meta:
        return "ae91c46"
    if "attack_vector" in meta:
        return "f457855"
    return "f41d0a5"


def _asked(text: str) -> str:
    match = _URL.search(text or "")
    if not match:
        return (text or "").strip()
    return match.group(0).split("#")[0].rstrip("/.")


def runs(sessions: dict, table: dict = None) -> list:
    """One row per assistant answer that holds at least one ```yaml rule, with the request
    of the user message before it."""
    rows = []
    for session_id, messages in sessions.items():
        asked = ""
        for i, msg in enumerate(messages if isinstance(messages, list) else []):
            if not isinstance(msg, dict):
                continue
            if msg.get("role") == "user":
                asked = _asked(msg.get("content", ""))
                continue
            blocks = _YAML_BLOCK.findall(msg.get("content") or "")
            if msg.get("role") != "assistant" or not blocks:
                continue
            rules = [rule_summary(b, table) for b in blocks]
            dates = sorted(r["date"] for r in rules if r["date"])
            meta = msg.get("pipeline_metadata") or {}
            rows.append({"session": session_id, "message": i, "url": asked,
                         "date": dates[0] if dates else None, "era": code_era(meta),
                         "rules": len(rules), "complete": sum(r["complete"] for r in rules),
                         "on_table": None if table is None else sum(bool(r["on_table"]) for r in rules),
                         "logsources": [r["logsource"] for r in rules],
                         "enrichment_sources": len(meta.get("enrichment_sources") or [])})
    return rows


def result_runs(result_rows: list, table: dict = None) -> list:
    """An evaluation result file's cases as runs, one per case with at least one rule, so a
    September run is counted by the same code as the April chats."""
    out = []
    for row in result_rows:
        rules = [rule_summary(r, table) for r in row.get("rules_yaml") or []]
        if not rules:
            continue
        out.append({"session": row.get("rule_id", ""), "message": None, "url": row.get("rule_id", ""),
                    "date": None, "era": (row.get("config") or {}).get("arm", "?"),
                    "rules": len(rules), "complete": sum(r["complete"] for r in rules),
                    "on_table": None if table is None else sum(bool(r["on_table"]) for r in rules),
                    "logsources": [r["logsource"] for r in rules], "enrichment_sources": 0})
    return out


def models_used(result_rows: list) -> dict:
    """{model: number of calls} over a result file's recorded LLM calls."""
    counts = {}
    for row in result_rows:
        for call in row.get("llm_calls") or []:
            counts[call.get("model")] = counts.get(call.get("model"), 0) + 1
    return counts


def repeats(rows: list) -> dict:
    """The requests run more than once, each with its runs in date order."""
    groups = {}
    for row in rows:
        groups.setdefault(row["url"], []).append(row)
    out = {}
    for url, group in groups.items():
        if len(group) < 2:
            continue
        group = sorted(group, key=lambda r: (r["date"] or "", r["session"]))
        first = [r["logsources"][0] for r in group]
        out[url] = {"runs": group, "first_logsources": first, "distinct_first_logsources": len(set(first))}
    return out


def totals(rows: list) -> dict:
    """Answers, rules, complete rules and rules with a log source SigmaHQ's rules use: per
    pipeline version and over all runs."""
    out = {}
    for row in rows:
        for key in (row["era"], "all"):
            t = out.setdefault(key, {"answers": 0, "rules": 0, "complete": 0, "on_table": 0})
            t["answers"] += 1
            t["rules"] += row["rules"]
            t["complete"] += row["complete"]
            t["on_table"] += row["on_table"] or 0
    return out


def mentions(rows: list, sessions: dict, terms: list) -> list:
    """(run, the terms found) for each run whose answer or saved stage results contain any of
    the terms - e.g. to check whether a prompt's worked example came from a report the
    assistant had already been run on."""
    found = []
    for row in rows:
        text = json.dumps(sessions[row["session"]][row["message"]], ensure_ascii=False)
        hits = [t for t in terms if t in text]
        if hits:
            found.append((row, hits))
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sessions", default=str(ROOT / "data" / "sessions.json"))
    parser.add_argument("--since", default="", help="keep runs dated on or after this day (YYYY-MM-DD)")
    parser.add_argument("--until", default="9999", help="keep runs dated before this day (YYYY-MM-DD)")
    parser.add_argument("--results", nargs="+", metavar="JSONL",
                        help="count evaluation result files' rules the same way, instead of the chats")
    parser.add_argument("--find", nargs="+", metavar="STRING",
                        help="only list the runs whose answer or stage results contain these strings")
    args = parser.parse_args()
    if args.results:
        table = load_logsource_table()
        print("Result file            cases  rules  complete  log source SigmaHQ's rules use")
        for path in args.results:
            rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
            t = totals(result_runs(rows, table)).get("all", {"answers": 0, "rules": 0, "complete": 0, "on_table": 0})
            used = ", ".join(f"{m} x{n}" for m, n in models_used(rows).items())
            print(f"{Path(path).stem:<22} {t['answers']:>5} {t['rules']:>6} {t['complete']:>9} {t['on_table']:>9}"
                  f"   calls: {used}")
        return
    sessions = json.loads(Path(args.sessions).read_text(encoding="utf-8"))
    rows = [r for r in runs(sessions, load_logsource_table()) if r["date"] and args.since <= r["date"] < args.until]
    if args.find:
        found = mentions(rows, sessions, args.find)
        print(f"{len(found)} of {len(rows)} answers with rules contain at least one of {args.find}\n")
        for r, hits in sorted(found, key=lambda f: (f[0]["date"], f[0]["session"])):
            print(f"{r['date']}  {r['session'][:8]}  {r['era']:<8} {r['url'][:60]}\n{'':<12}found: {', '.join(hits)}")
        return
    print(f"{len(rows)} answers with rules, dated {args.since or 'any'} to before {args.until}\n")
    for r in sorted(rows, key=lambda r: (r["date"], r["session"])):
        print(f"{r['date']}  {r['session'][:8]}  {r['era']:<8} rules {r['rules']} (complete {r['complete']},"
              f" SigmaHQ log source {r['on_table']})  web sources {r['enrichment_sources']:>2}  {r['url'][:60]}")
        print(f"{'':<12}log sources: {', '.join(r['logsources'])}")
    print("\nPipeline version     answers  rules  complete  log source SigmaHQ's rules use")
    for era, t in totals(rows).items():
        print(f"{era:<22} {t['answers']:>5} {t['rules']:>6} {t['complete']:>9} {t['on_table']:>9}")
    reps = repeats(rows)
    print(f"\nRequests run more than once: {len(reps)}")
    for url, group in reps.items():
        print(f"\n{url}\n  {len(group['runs'])} runs, {group['distinct_first_logsources']} different first-rule log sources:")
        for r, first in zip(group["runs"], group["first_logsources"]):
            print(f"    {r['date']}  {r['era']:<8} {first}")


if __name__ == "__main__":
    main()
