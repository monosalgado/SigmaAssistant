#!/usr/bin/env python3
"""Build the evaluation's saved web search answers (Change 45), once per case set.

The evaluation never searches live (`run_eval.py --web-snapshots FILE`): every run, arm and rerun reads the same saved
answers, and the free account's limits (~25 searches per hour, ~50 per "session") apply only here. For each case the
web stage's own query is computed offline (the report preprocessed from its snapshots, then
`WebEnrichStage._build_search_query`). A query already in the output file is skipped; one the probe answered with
exactly the same query is copied from the probe's file (nothing sent); only the rest is searched (5 results, as the
stage). On either limit the builder waits and asks again (hourly: 10 min, session: 30 min; at most 12 hours); an
interrupted build continues on a rerun.

Usage:
    .venv/bin/python eval/build_web_snapshots.py --sample 60 --seed 0 --out eval/web_snapshots/tuning60.jsonl \\
        [--reuse eval/web_snapshots/probe_tuning60.jsonl] [--dry-run]
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

# User 2026-10-06: "when it hit the quota ... it can just continue" - both limits are waited out, at most 12 hours.
LIMIT_WAIT_MAX_S = 12 * 3600


def _answered(path: Path, stage_only: bool) -> dict:
    """{query: results} for every answered record of a JSON-lines file (the probe's or the output's format)."""
    out = {}
    if path and Path(path).exists():
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("error") or (stage_only and r.get("variant", "stage") != "stage"):
                continue
            out[r["query"]] = r["results"]
    return out


def plan(queries: list, out: Path, reuse: list) -> dict:
    """{query: "saved" | "copy" | "search"}."""
    saved = _answered(out, stage_only=False)
    reusable = {}
    for path in reuse:
        reusable.update(_answered(path, stage_only=True))
    return {q: "saved" if q in saved else "copy" if q in reusable else "search" for q in queries}


def copy_answer(query: str, reuse: list, out: Path) -> None:
    for path in reuse:
        answers = _answered(path, stage_only=True)
        if query in answers:
            Path(out).parent.mkdir(parents=True, exist_ok=True)
            with Path(out).open("a", encoding="utf-8") as f:
                f.write(json.dumps({"query": query, "results": answers[query], "error": None,
                                    "copied_from": str(path)}) + "\n")
            return
    raise KeyError(query)


def limit_kind(error: Optional[str]) -> Optional[str]:
    text = str(error or "")
    if "hourly request limit" in text:
        return "hourly"
    if "session request limit" in text:
        return "session"
    return None


def wait_seconds(kind: Optional[str]) -> Optional[int]:
    """How long to wait before asking again: 10 minutes after the hourly limit, 30 after the session limit."""
    return {"hourly": 600, "session": 1800}.get(kind)


def stage_queries(cases: list) -> dict:
    """{rule_id: the web stage's query}, computed offline from the snapshots."""
    from backend.pipeline.stage_preprocess import PreprocessStage
    from backend.pipeline.stage_web_enrich import WebEnrichStage
    from eval.run_eval import snapshots_instead_of_network
    out = {}
    for case in cases:
        with snapshots_instead_of_network(case["url_to_path"]), contextlib.redirect_stdout(io.StringIO()):
            ctx = PreprocessStage(None, "").run({"original_query": " ".join(case["urls"]), "history": [],
                                                 "media_file": None})
        out[case["rule_id"]] = WebEnrichStage(None, "")._build_search_query(ctx["preprocessed"])
    return out


def main(argv: list = None) -> int:
    from dotenv import load_dotenv

    from backend.web_search import OllamaWebSearch
    from eval.run_eval import load_cases, stratified_sample
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", default="eval/manifest.jsonl")
    parser.add_argument("--sample", type=int, default=0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", required=True)
    parser.add_argument("--reuse", nargs="*", default=[], help="the probe's raw answers to copy from")
    parser.add_argument("--dry-run", action="store_true", help="report the plan; send nothing")
    args = parser.parse_args(argv)
    with contextlib.redirect_stdout(io.StringIO()):
        cases = load_cases(REPO / args.manifest, REPO, 2000)
        if args.sample:
            cases = stratified_sample(cases, args.sample, args.seed)
    out, reuse = REPO / args.out, [REPO / p for p in args.reuse]
    queries = stage_queries(cases)
    empty = [rid for rid, q in queries.items() if not q]
    steps = plan([q for q in queries.values() if q], out, reuse)
    counts = {k: sum(1 for v in steps.values() if v == k) for k in ("saved", "copy", "search")}
    print(f"{len(cases)} cases, {len(steps)} distinct queries ({len(empty)} cases build none): already saved "
          f"{counts['saved']}, copied from the probe {counts['copy']}, to search {counts['search']}")
    if args.dry_run:
        return 0
    for query, step in steps.items():
        if step == "copy":
            copy_answer(query, reuse, out)
    load_dotenv(REPO / ".env")
    key = os.getenv("OLLAMA_API_KEY", "").strip()
    to_search = [q for q, s in steps.items() if s == "search"]
    if to_search and not key:
        print("OLLAMA_API_KEY is not set in .env")
        return 1
    searcher = OllamaWebSearch(key, cache_path=out)
    done = 0
    for n, query in enumerate(to_search, 1):
        time.sleep(1)
        record, waited = searcher.search(query), 0
        while wait_seconds(limit_kind(record["error"])) and waited < LIMIT_WAIT_MAX_S:
            pause = wait_seconds(limit_kind(record["error"]))
            print(f"  {limit_kind(record['error'])} search limit reached; waiting {pause // 60} min "
                  f"({waited // 60} min so far)")
            time.sleep(pause)
            waited += pause
            record = searcher.search(query)
        if record["error"]:
            print(f"  stopped at {n}/{len(to_search)}: {record['error'][:100]} (saved answers are kept; rerun to "
                  f"continue)")
            break
        done += 1
        print(f"  {n:>2}/{len(to_search)} {len(record['results'])} results  {query[:80]}")
    left = sum(1 for s in plan(list(steps), out, reuse).values() if s == "search")
    print(f"\nsearched now {done}; still to search {left} -> {out.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
