#!/usr/bin/env python3
"""Measure candidate defect 15: does the attack-vector stage reproduce the
prompt's own examples instead of the source?

Reruns ONLY the stages that feed the attack-vector prompt (preprocess -> PoC ->
attack vector) on the same cases as a finished harness run, and records the full
attack-vector output, which the harness does not store.

Criteria were fixed before the run was looked at:

  M1  example leak — the output contains a marker string that exists only in the
      ATTACK_VECTOR_EXTRACTION prompt's examples, AND that marker is absent from
      the text the model was actually given (the stage's source window + PoC
      behaviours; the window was 8000 chars for av60.jsonl, SOURCE_TEXT_MAX_CHARS
      after Change 12). Markers are invented, example-specific strings; generic
      patterns the prompt also mentions ("$(", "../../etc/passwd", "rO0AB")
      are excluded because a model may legitimately infer them from the class.
  M2  quote verification — each payload signature's `derived_from` is supposed
      to be a quote from the input. Share found verbatim after lower-casing and
      collapsing whitespace ("..." splits a quote into fragments, all must be
      found). `inferred_from_class` is excluded. A miss means "not verbatim",
      which includes honest paraphrase, so it is an UPPER bound on invention.

Runs the stages exactly as the pipeline does. Since plan 1.3a the PoC stage's
GitHub fetches are served from `eval/github_manifest.jsonl` like the pages; the
two earlier result files (av60.jsonl, av60_window.jsonl) fetched them live.

Usage (needs the Spark tunnel):
    LLM_PROVIDER=ollama ECONOMY_PROVIDER=ollama \\
    .venv/bin/python eval/probe_attack_vector.py \\
        --cases eval/results/baseline60.jsonl --out eval/results/av60.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.run_eval import (  # noqa: E402
    load_cases, load_github_manifest, poc_snapshots_instead_of_network,
    snapshots_instead_of_network,
)

# Invented strings that appear only in the prompt's examples (prompts.py:560-685).
# "saml" was Example A until Change 27 (2026-09-25); kept to count residual copying of it.
EXAMPLE_MARKERS = {
    "saml": ["/saml/login", "samlrequest", "nsc_tass", "patch.nss"],
    "email_iso_lnk": ["remit_8841", "qx7loader", "qxupdate"],
    "websocket_nginx": ["remoteversion", "bt26-02", "thin-scc-wrapper", "sedcp",
                        "bingb0ng", "tw1st3d"],
    "setuid_oopsie": ["oopsie"],
    # Change 30 (defect 15 at its cause): the examples' values become placeholders. Fixed
    # 2026-09-26 before the change was written; a placeholder in an answer is a copy.
    "placeholders": ["<attachment>", "<loader>", "<run-key value>", "<endpoint>", "<parameter>",
                     "<patch file>", "<patch password>", "<patch helper>", "<patch script>",
                     "<vendor binary>", "<setuid binary>"],
}
FAILED_PREFIX = "Extraction failed"


def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def leaked_markers(output: str, model_input: str) -> dict:
    out, src = output.lower(), model_input.lower()
    leaks = {}
    for example, markers in EXAMPLE_MARKERS.items():
        hit = [m for m in markers if m in out and m not in src]
        if hit:
            leaks[example] = hit
    return leaks


def quote_found(quote: str, model_input_norm: str) -> bool:
    fragments = [normalise(f).strip(" \"'`") for f in re.split(r"\.\.\.|…", quote)]
    fragments = [f for f in fragments if f]
    return bool(fragments) and all(f in model_input_norm for f in fragments)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cases", required=True, help="finished harness run whose rule_ids to reuse")
    ap.add_argument("--out", required=True)
    ap.add_argument("--min-chars", type=int, default=2000)
    args = ap.parse_args()

    wanted = [json.loads(l)["rule_id"] for l in open(args.cases)]
    by_id = {c["rule_id"]: c for c in load_cases(REPO / "eval/manifest.jsonl", REPO, args.min_chars)}
    missing = [r for r in wanted if r not in by_id]
    if missing:
        print(f"ERROR: {len(missing)} rule_ids not in the corpus; corpus changed?")
        return 1

    out_path = Path(args.out)
    done = set()
    if out_path.exists():
        done = {json.loads(l)["rule_id"] for l in open(out_path)}

    poc_url_map = load_github_manifest(REPO / "eval/github_manifest.jsonl")
    from backend.agent import SigmaAgent
    orch = SigmaAgent().orchestrator
    print(f"Model: {orch.client.model_name} | {len(wanted)} cases, {len(done)} already done")

    with open(out_path, "a") as fh:
        for n, rid in enumerate(wanted, 1):
            if rid in done:
                continue
            case = by_id[rid]
            started = time.monotonic()
            ctx = {"original_query": " ".join(case["urls"]), "history": [], "media_file": None}
            with snapshots_instead_of_network(case["url_to_path"]) as shim:
                ctx = orch.preprocess.run(ctx)
            with poc_snapshots_instead_of_network(poc_url_map) as poc_shim:
                ctx = orch.poc_analysis.run(ctx)
            ctx = orch.attack_vector.run(ctx)

            # Rebuilt as stage_attack_vector.py:62-72 builds the prompt input,
            # using the stage's own window so the check follows any change to it.
            behaviours = ctx.get("poc_analysis", {}).get("behavioral_indicators", [])
            poc_text = json.dumps(behaviours[:15], indent=2) if behaviours else "No PoC behaviors extracted."
            source = orch.attack_vector.source_text(ctx["preprocessed"]["combined_text"])
            model_input = source + "\n" + poc_text
            av = ctx["attack_vector"]
            output = json.dumps(av)
            input_norm = normalise(model_input)

            quotes = [s.get("derived_from", "") for s in av.get("payload_signatures", [])
                      if isinstance(s, dict)]
            quotes = [q for q in quotes if q and q.strip() != "inferred_from_class"]

            row = {
                "rule_id": rid,
                "title": case["title"],
                "gold_category": case.get("category"),
                "gold_product": case.get("product"),
                "snapshots_missed": shim.missed,
                "poc_snapshots_missed": poc_shim.missed,
                "poc_snippets": ctx.get("poc_analysis", {}).get("snippets_found", 0),
                "failed": str(av.get("reasoning", "")).startswith(FAILED_PREFIX),
                "model_input_chars": len(model_input),
                "leaks": leaked_markers(output, model_input),
                "quotes_total": len(quotes),
                "quotes_found": sum(quote_found(q, input_norm) for q in quotes),
                "attack_vector": av,
                "elapsed_s": round(time.monotonic() - started, 2),
            }
            fh.write(json.dumps(row) + "\n")
            fh.flush()
            flag = f"LEAK {row['leaks']}" if row["leaks"] else ""
            print(f"[{n:2d}/{len(wanted)}] {rid[:8]} {row['elapsed_s']:5.1f}s "
                  f"quotes {row['quotes_found']}/{row['quotes_total']} "
                  f"telemetry={av.get('primary_telemetry')!r} {flag}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
