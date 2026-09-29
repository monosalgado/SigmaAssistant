#!/usr/bin/env python3
"""Change 37's measure: how many JSON answers of the PoC, attack-vector and analysis stages could not be
read before the change, and how many can now - on identical answers.

For each case the pipeline's own analysis path runs (`analyse_for_review`: preprocessing, PoC,
attack vector, analysis; saved pages, no web search, as every run since September), and every answer
those stages receive is captured and read twice: with the reader before Change 37 (`old_parse`) and
with today's (`PipelineStage.parse_json`, which repairs stray backslashes). Reading the same answer
both ways leaves out run-to-run variation. The case's log-source suggestions (after the repair) are
recorded too. By construction the repair can change only answers the old reader could not read.

Usage (needs the Spark tunnel):
    .venv/bin/python eval/probe_json_repair.py --out eval/results/json_repair_probe.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from contextlib import contextmanager
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

STAGES = ("poc_analysis", "attack_vector", "analysis")


def old_parse(text: str):
    """`PipelineStage.parse_json` as it was before Change 37."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    return json.loads(text)


def readability(raw: str, stage) -> dict:
    out = {"old": True, "new": True, "error": None}
    try:
        old_parse(raw)
    except Exception as exc:
        out["old"], out["error"] = False, f"{type(exc).__name__}: {exc}"
    try:
        stage.parse_json(raw)
    except Exception:
        out["new"] = False
    return out


@contextmanager
def capture_answers(stage):
    """Record every answer the stage's model call returns, as the stage runs."""
    had_own = "llm_call" in vars(stage)
    original = stage.llm_call
    answers = []

    def recording(*args, **kwargs):
        text = original(*args, **kwargs)
        answers.append(text)
        return text

    stage.llm_call = recording
    try:
        yield answers
    finally:
        if had_own:
            stage.llm_call = original
        else:
            del stage.llm_call


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True)
    parser.add_argument("--sample", type=int, default=60)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--manifest", default="eval/manifest.jsonl")
    args = parser.parse_args()

    from eval.run_eval import (load_cases, load_github_manifest, poc_snapshots_instead_of_network,
                               snapshots_instead_of_network, stratified_sample, web_enrichment_disabled)
    cases = stratified_sample(load_cases(REPO / args.manifest, REPO, 2000), args.sample, args.seed)
    poc_url_map = load_github_manifest(REPO / "eval/github_manifest.jsonl")
    from backend.agent import SigmaAgent
    agent = SigmaAgent()
    orch = agent.orchestrator
    stages = {name: getattr(orch, name) for name in STAGES}
    done = set()
    if Path(args.out).exists():
        done = {json.loads(l)["rule_id"] for l in open(args.out, encoding="utf-8") if l.strip()}
    with open(args.out, "a", encoding="utf-8") as out:
        for n, case in enumerate(cases, 1):
            if case["rule_id"] in done:
                continue
            started = time.monotonic()
            meta, error = {}, None
            with snapshots_instead_of_network(case["url_to_path"]), \
                    poc_snapshots_instead_of_network(poc_url_map), \
                    web_enrichment_disabled(agent.client, True), \
                    capture_answers(stages["poc_analysis"]) as poc, \
                    capture_answers(stages["attack_vector"]) as av, \
                    capture_answers(stages["analysis"]) as an:
                try:
                    for event in orch.analyse_for_review(description=" ".join(case["urls"])):
                        if event.get("event") == "checkpoint":
                            meta = event["data"].get("pipeline_metadata") or {}
                except Exception as exc:
                    error = f"{type(exc).__name__}: {exc}"
            row = {"rule_id": case["rule_id"], "title": case["title"], "error": error,
                   "suggestions": len(meta.get("logsource_suggestions") or []),
                   "seconds": round(time.monotonic() - started, 1), "answers": {}}
            for name, answers in (("poc_analysis", poc), ("attack_vector", av), ("analysis", an)):
                row["answers"][name] = [dict(readability(a or "", stages[name]), chars=len(a or ""))
                                        for a in answers]
            out.write(json.dumps(row) + "\n")
            out.flush()
            flags = {k: [(a["old"], a["new"]) for a in v] for k, v in row["answers"].items() if v}
            print(f"[{n}/{len(cases)}] {case['rule_id'][:8]} {row['seconds']}s suggestions={row['suggestions']} "
                  f"(old, new) readable: {flags} {error or ''}", flush=True)
    report([json.loads(l) for l in open(args.out, encoding="utf-8") if l.strip()])
    return 0


def report(rows: list) -> None:
    print(f"\n{len(rows)} cases")
    for name in STAGES:
        answers = [a for r in rows for a in r["answers"].get(name, [])]
        old_bad = sum(not a["old"] for a in answers)
        new_bad = sum(not a["new"] for a in answers)
        print(f"  {name:<14} answers {len(answers):>3}  unreadable before {old_bad:>2}  unreadable now {new_bad:>2}  "
              f"repaired {sum((not a['old']) and a['new'] for a in answers):>2}")
    print(f"  cases with no log-source suggestion: {sum(1 for r in rows if not r['suggestions'])}")


if __name__ == "__main__":
    sys.exit(main())
