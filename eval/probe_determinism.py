#!/usr/bin/env python3
"""Is the model's answer at temperature 0 repeatable? (plan P-B, user 2026-09-29)

Two runs of identical code on identical saved pages concluded differently at the attack-vector
stage - temperature 0, the pipeline's first model stage - in 12 of 60 cases (log 2026-09-28).
This probe asks why. For each case it captures the exact prompt that stage sends (the saved
pages, the PoC stage run once), then sends that same prompt again and again:
- one at a time, as the pipeline sends it (no seed);
- one at a time with a fixed seed;
- several at once (the server batches concurrent requests), without and with the seed.
It counts how many different answers each condition gives, as raw text and as the stage's
`primary_telemetry` (the label the log source follows).

Every request is exactly the pipeline's (`request_kwargs`, tested against OllamaLLMClient), plus
the seed where a condition says so. Other users' load on the shared server is not controlled;
each call's time is recorded.

Usage (needs the Spark tunnel):
    .venv/bin/python eval/probe_determinism.py --out eval/results/determinism_probe.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from backend.llm_client import OUTPUT_TOKEN_LIMIT  # noqa: E402

# The cases whose two September runs (p2g_shared60, oracle_ls60_unreviewed) first diverged at
# the attack-vector stage (`eval/list_disagreements.py`).
DEFAULT_CASES = ["20c6ed1c", "36222790", "92389a99", "ad0960eb", "ad7085ac", "32b5db62"]
JSON_SYSTEM = ("You must respond with valid JSON only. Do not include any text, explanation, or "
               "markdown outside the JSON object.")


def request_kwargs(prompt: str, model: str, seed: int = None, json_mode: bool = True,
                   temperature: float = 0.0) -> dict:
    """The request OllamaLLMClient.generate sends, plus a seed when one is given."""
    messages = [{"role": "system", "content": JSON_SYSTEM}] if json_mode else []
    messages.append({"role": "user", "content": prompt})
    kwargs = {"model": model, "messages": messages, "temperature": temperature,
              "max_tokens": OUTPUT_TOKEN_LIMIT}
    if seed is not None:
        kwargs["seed"] = seed
    return kwargs


class _Captured(BaseException):
    """Stops the stage at its model call. A BaseException, so the stage's own
    `except Exception` does not swallow it."""


def capture_prompt(stage, context: dict):
    """(prompt, keyword arguments) of the stage's model call, without making it."""
    had_own = "llm_call" in vars(stage)
    original = stage.llm_call
    seen = {}

    def record(prompt, **kwargs):
        seen.update(prompt=prompt, kwargs=kwargs)
        raise _Captured()

    stage.llm_call = record
    try:
        stage.run(context)
    except _Captured:
        pass
    finally:
        if had_own:
            stage.llm_call = original
        else:
            del stage.llm_call
    if "prompt" not in seen:
        raise RuntimeError(f"{stage.name} made no model call")
    return seen["prompt"], seen["kwargs"]


def run_batch(send, n: int) -> list:
    """Send n requests at the same time; their results in request order."""
    with ThreadPoolExecutor(max_workers=n) as pool:
        return list(pool.map(send, range(n)))


def summarise(rows: list) -> dict:
    """{(case, condition): answers, different answers (text), different telemetry labels, errors}."""
    out = {}
    for row in rows:
        if row.get("kind") == "prompt":
            continue
        key = (row["rule_id"], row["condition"])
        entry = out.setdefault(key, {"outputs": [], "telemetry": [], "errors": 0})
        if row.get("output") is None:
            entry["errors"] += 1
        else:
            entry["outputs"].append(row["output"])
            entry["telemetry"].append(row.get("primary_telemetry"))
    return {key: {"answers": len(e["outputs"]), "different_answers": len(set(e["outputs"])),
                  "different_telemetry": len(set(e["telemetry"])), "errors": e["errors"]}
            for key, e in out.items()}


def order_effects(rows: list) -> dict:
    """Per case, in the order the requests were sent: did the first request's answer never come
    again, and were all later answers identical? (The first probe's conditions ran in a fixed order,
    so a difference between conditions can be a difference between the first request and the rest.)"""
    answers = {}
    for row in sorted((r for r in rows if r.get("kind") == "answer" and r.get("output") is not None),
                      key=lambda r: (r["at"], r["request"])):
        answers.setdefault(row["rule_id"], []).append(row["output"])
    return {rid: {"requests": len(out), "first_differs": out[0] not in out[1:],
                  "later_identical": len(set(out[1:])) <= 1}
            for rid, out in answers.items()}


def served_in_turn(rows: list) -> dict:
    """Requests sent at once that the server answered one after another: sorted by time taken,
    the k-th took about k times the fastest (within 25%)."""
    groups = {}
    for row in rows:
        if row.get("kind") == "answer" and row["condition"].startswith("at once") and row.get("seconds"):
            groups.setdefault((row["rule_id"], row["condition"]), []).append(row["seconds"])
    out = {}
    for key, times in groups.items():
        times = sorted(times)
        out[key] = len(times) > 1 and all(abs(t / (times[0] * k) - 1) <= 0.25 for k, t in enumerate(times, 1))
    return out


# --- the follow-up (user 2026-09-29): is a first-time answer repeatable, and does what came
# before change it? One request at a time, in a fixed and recorded order.

UNRELATED = "Reply with the single word OK."


def follow_up_schedule(ids: list, forward_rounds: int = 4, reverse_rounds: int = 2,
                       unrelated_rounds: int = 2) -> list:
    """The order of requests: a rotation (each question always after the same other one), the
    reversed rotation (after a different one), each after an unrelated question, and each asked
    twice in a row after its rotation neighbour, its reversed neighbour and the unrelated question."""
    steps = []
    for _ in range(forward_rounds):
        steps += [{"phase": "rotation", "prompt": i} for i in ids]
    rev = list(reversed(ids))
    for _ in range(reverse_rounds):
        steps += [{"phase": "reversed", "prompt": i} for i in rev]
    for _ in range(unrelated_rounds):
        for i in ids:
            steps += [{"phase": "after unrelated", "prompt": "unrelated"}, {"phase": "after unrelated", "prompt": i}]
    for k, i in enumerate(ids):
        before = (ids[k - 1], rev[(rev.index(i) - 1) % len(rev)], "unrelated")
        for prev in before:
            steps += [{"phase": "asked twice", "prompt": p} for p in (prev, i, i)]
    return steps


def annotate_order(rows: list, before_first: str) -> None:
    """Mark each answer with the question sent just before it and whether it was a first-time
    ask (the question before was a different one)."""
    previous = before_first
    for row in rows:
        row["after"] = previous
        row["fresh"] = previous != row["prompt"]
        previous = row["prompt"]


def follow_up_analysis(rows: list) -> dict:
    """Per question (the unrelated one left out): first-time answers - how many, how many
    different, and the most different after one and the same preceding question; answers when
    asked again right away; the number of different telemetry labels."""
    out = {}
    for prompt in dict.fromkeys(r["prompt"] for r in rows if r["prompt"] != "unrelated"):
        mine = [r for r in rows if r["prompt"] == prompt and r.get("output") is not None]
        fresh = [r for r in mine if r["fresh"]]
        again = [r for r in mine if not r["fresh"]]
        by_before = {}
        for r in fresh:
            by_before.setdefault(r["after"], set()).add(r["output"])
        out[prompt] = {"fresh": len(fresh), "fresh_different": len({r["output"] for r in fresh}),
                       "most_different_after_one_question": max((len(v) for v in by_before.values()), default=0),
                       "second_asks": len(again), "second_different": len({r["output"] for r in again}),
                       "telemetry_labels": len({r.get("primary_telemetry") for r in mine})}
    return out


def same_as_first_probe(follow_rows: list, earlier_rows: list) -> dict:
    """Per question: are its answers when asked again right away the same as the first probe's
    repeats of the byte-identical prompt? None when the prompt changed between the probes."""
    earlier_sha = {r["rule_id"]: r["sha256"] for r in earlier_rows if r.get("kind") == "prompt"}
    repeats = {}
    for rid, o in order_effects(earlier_rows).items():
        outs = [r["output"] for r in sorted((r for r in earlier_rows if r.get("kind") == "answer"
                                             and r["rule_id"] == rid and r.get("output") is not None),
                                            key=lambda r: (r["at"], r["request"]))]
        repeats[earlier_sha.get(rid)] = set(outs[1:])
    out = {}
    for r in (r for r in follow_rows if r.get("kind") == "prompt"):
        rid, sha = r["rule_id"], r["sha256"]
        again = {x["output"] for x in follow_rows if x.get("kind") == "follow_up" and x["prompt"] == rid
                 and not x["fresh"] and x.get("output") is not None}
        out[rid] = None if sha not in repeats or earlier_sha.get(rid) != sha else again == repeats[sha]
    return out


def todays_labels(rows: list) -> dict:
    """{question: {primary_telemetry label: answers}} over probe rows of both kinds (the unrelated
    question and failed requests left out)."""
    out = {}
    for r in rows:
        if r.get("output") is None or r.get("kind") not in ("answer", "follow_up"):
            continue
        rid = r["rule_id"] if r["kind"] == "answer" else r["prompt"]
        if rid == "unrelated":
            continue
        label = r.get("primary_telemetry")
        out.setdefault(rid, {})
        out[rid][label] = out[rid].get(label, 0) + 1
    return out


def labels_report(probe_files: list, run_files: list) -> None:
    """Per probed question: its label in each earlier run (the recorded attack vector) and today's
    labels over every probe answer."""
    from eval.compare_runs import load
    rows = [json.loads(line) for f in probe_files for line in open(f, encoding="utf-8") if line.strip()]
    runs = [(Path(f).stem, load(Path(f))) for f in run_files]
    print("\nThe label the log source follows (primary_telemetry):")
    for rid, labels in todays_labels(rows).items():
        earlier = "; ".join(f"{name}: {((run.get(rid) or {}).get('pipeline') or {}).get('attack_vector', {}).get('primary_telemetry')}"
                            for name, run in runs)
        print(f"  {rid[:8]}  {earlier} | today: {labels}")


CONDITIONS = [("one at a time", False, None), ("one at a time, seed", False, 42),
              ("at once", True, None), ("at once, seed", True, 42)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cases", nargs="+", default=DEFAULT_CASES, help="rule_id prefixes")
    parser.add_argument("--repeats", type=int, default=5, help="requests per one-at-a-time condition")
    parser.add_argument("--batch", type=int, default=4, help="requests sent at once")
    parser.add_argument("--out")
    parser.add_argument("--report", action="store_true", help="only summarise an existing --out file")
    parser.add_argument("--follow-up", action="store_true",
                        help="the follow-up order (follow_up_schedule) instead of the four conditions")
    parser.add_argument("--earlier", help="the first probe's file, to compare repeats of identical prompts")
    parser.add_argument("--labels", nargs="+", metavar="FILE",
                        help="with --runs: today's labels over these probe files against earlier runs")
    parser.add_argument("--runs", nargs="+", metavar="RUN", default=[])
    args = parser.parse_args()
    if args.labels:
        labels_report(args.labels, args.runs)
        return 0
    if args.report:
        rows = [json.loads(line) for line in open(args.out, encoding="utf-8") if line.strip()]
        if any(r.get("kind") == "follow_up" for r in rows):
            earlier = [json.loads(line) for line in open(args.earlier, encoding="utf-8") if line.strip()] \
                if args.earlier else []
            follow_up_report(rows, earlier)
        else:
            report(rows)
        return 0

    from dotenv import load_dotenv
    from openai import OpenAI

    from eval.run_eval import (load_cases, load_github_manifest, poc_snapshots_instead_of_network,
                               snapshots_instead_of_network)
    load_dotenv(REPO / ".env")
    corpus = load_cases(REPO / "eval/manifest.jsonl", REPO, 2000)
    cases = [next(c for c in corpus if c["rule_id"].startswith(p)) for p in args.cases]
    poc_url_map = load_github_manifest(REPO / "eval/github_manifest.jsonl")
    from backend.agent import SigmaAgent
    orch = SigmaAgent().orchestrator
    model = orch.client.model_name
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    api = OpenAI(base_url=f"{base_url}/v1", api_key="ollama")
    rows, seen_prompts, prompts = [], {}, []
    out = open(args.out, "a", encoding="utf-8")

    def write(row):
        rows.append(row)
        out.write(json.dumps(row) + "\n")
        out.flush()

    def ask(text, temperature=0.0, seed=None, json_mode=True) -> dict:
        started = time.monotonic()
        res = {"at": datetime.now(timezone.utc).isoformat()}
        try:
            resp = api.chat.completions.create(**request_kwargs(text, model, seed=seed, json_mode=json_mode,
                                                                temperature=temperature))
            choice = resp.choices[0]
            res.update(output=choice.message.content, finish_reason=choice.finish_reason,
                       completion_tokens=getattr(resp.usage, "completion_tokens", None))
            if json_mode:
                try:
                    res["primary_telemetry"] = orch.attack_vector.parse_json(res["output"]).get("primary_telemetry")
                except Exception:
                    res["primary_telemetry"] = "(does not parse)"
        except Exception as exc:
            res.update(output=None, error=f"{type(exc).__name__}: {exc}")
        res["seconds"] = round(time.monotonic() - started, 2)
        return res

    for case in cases:
        rid = case["rule_id"]
        ctx = {"original_query": " ".join(case["urls"]), "history": [], "media_file": None}
        with snapshots_instead_of_network(case["url_to_path"]):
            ctx = orch.preprocess.run(ctx)
        with poc_snapshots_instead_of_network(poc_url_map):
            ctx = orch.poc_analysis.run(ctx)
        prompt, kwargs = capture_prompt(orch.attack_vector, ctx)
        digest = hashlib.sha256(prompt.encode()).hexdigest()[:16]
        write({"kind": "prompt", "rule_id": rid, "sha256": digest, "chars": len(prompt), "call": kwargs,
               "same_as": seen_prompts.get(digest)})
        if digest in seen_prompts:
            print(f"{rid[:8]}: same prompt as {seen_prompts[digest][:8]} - not sent again")
            continue
        seen_prompts[digest] = rid
        prompts.append((rid, prompt, kwargs))

    if args.follow_up:
        by_id = {rid: (prompt, kwargs) for rid, prompt, kwargs in prompts}
        previous = "(capture)"
        for n, step in enumerate(follow_up_schedule(list(by_id))):
            if step["prompt"] == "unrelated":
                res = ask(UNRELATED, json_mode=False)
            else:
                prompt, kwargs = by_id[step["prompt"]]
                res = ask(prompt, temperature=kwargs["temperature"])
            write({"kind": "follow_up", "step": n, "phase": step["phase"], "prompt": step["prompt"],
                   "after": previous, "fresh": previous != step["prompt"], **res})
            previous = step["prompt"]
            print(f"[{n + 1}] {step['phase']:<16} {step['prompt'][:9]:<9} {res['seconds']:6.1f}s "
                  f"{res.get('error') or ''}", flush=True)
        out.close()
        earlier = [json.loads(line) for line in open(args.earlier, encoding="utf-8") if line.strip()] \
            if args.earlier else []
        follow_up_report(rows, earlier)
        return 0

    for rid, prompt, kwargs in prompts:
        for condition, at_once, seed in CONDITIONS:
            def send(i, _seed=seed):
                row = {"kind": "answer", "rule_id": rid, "condition": condition, "seed": _seed, "request": i}
                row.update(ask(prompt, temperature=kwargs["temperature"], seed=_seed))
                return row

            results = run_batch(send, args.batch) if at_once else [send(i) for i in range(args.repeats)]
            for row in results:
                write(row)
            s = summarise(rows)[(rid, condition)]
            print(f"{rid[:8]} {condition:<22} answers {s['answers']}  different {s['different_answers']}  "
                  f"telemetry labels {s['different_telemetry']}  errors {s['errors']}", flush=True)
    out.close()
    report(rows)
    return 0


def follow_up_report(rows: list, earlier: list) -> None:
    analysis = follow_up_analysis([r for r in rows if r.get("kind") == "follow_up"])
    same = same_as_first_probe(rows, earlier) if earlier else {}
    print("\nQuestion  first-time: asks  different  most different after one question | asked again: asks  "
          "different | labels | same as first probe")
    for rid, a in analysis.items():
        print(f"{rid[:8]}  {a['fresh']:>21}  {a['fresh_different']:>9}  {a['most_different_after_one_question']:>30} | "
              f"{a['second_asks']:>16}  {a['second_different']:>9} | {a['telemetry_labels']:>6} | {same.get(rid)}")


def report(rows: list) -> None:
    print("\nCase      condition               answers  different  telemetry labels")
    for (rid, condition), s in summarise(rows).items():
        print(f"{rid[:8]}  {condition:<22} {s['answers']:>7}  {s['different_answers']:>9}  {s['different_telemetry']:>16}")
    print("\nIn the order sent (all conditions together):")
    for rid, o in order_effects(rows).items():
        print(f"  {rid[:8]}  {o['requests']} requests: first answer never given again: {o['first_differs']}; "
              f"all later answers identical: {o['later_identical']}")
    turns = served_in_turn(rows)
    print(f"\nRequests sent at once that the server answered one after another: {sum(turns.values())} of "
          f"{len(turns)} batches")


if __name__ == "__main__":
    sys.exit(main())
