#!/usr/bin/env python3
"""Diagnose the analysis stage's ATT&CK retrieval (#1 of the pipeline-quality order, 2026-10-05). Offline: the local
ChromaDB index and the saved pages; no LLM call.

The analysis stage searches the ATT&CK collection with `combined_text[:500]` (5 results), the text it then gives the
model as "MITRE context". On many pages those first 500 characters are the input URLs and a site menu. For each case
of a saved run, the probe runs that search and the candidates fixed before looking - the attack-vector summary the
stage already has (`format_vector_summary`, from the row's saved attack vector), and the summary followed by the
current text - and reports whether the gold rule's techniques are among the results (exact, and by parent technique
as S4). The embedding model reads at most 256 word pieces (~1,000 characters); longer queries are cut by it.

Usage:
    .venv/bin/python eval/probe_mitre_query.py eval/results/c41A_tuning60.jsonl [--show 3]
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))


def _summary(ctx: dict) -> str:
    from backend.pipeline.stage_attack_vector import AttackVectorStage
    return AttackVectorStage.format_vector_summary(ctx.get("attack_vector") or {})


QUERIES = {
    "current": lambda ctx: ctx["text"][:500],
    "vector_summary": _summary,
    "both": lambda ctx: _summary(ctx) + "\n" + ctx["text"][:500],
}


def gold_techniques(rule: dict) -> set:
    from eval.scorers import extract_techniques
    return extract_techniques((rule or {}).get("tags"))


def retrieved_ids(result: dict) -> list:
    metas = ((result.get("mitre") or {}).get("metadatas") or [[]])[0]
    return [str(m["external_id"]).lower() for m in metas if isinstance(m, dict) and m.get("external_id")]


def recall(gold: set, got, parent: bool = False):
    if not gold:
        return None
    norm = (lambda ids: {i.split(".")[0] for i in ids}) if parent else set
    return len(norm(gold) & norm(set(got))) / len(norm(gold))


def run_queries(store, ctx: dict, gold: set) -> dict:
    out = {}
    for name, build in QUERIES.items():
        got = retrieved_ids(store.search(build(ctx), collections=["mitre"], n_results=5))
        out[name] = {"retrieved": got, "recall": recall(gold, got), "recall_parent": recall(gold, got, parent=True)}
    return out


def main() -> int:
    import yaml
    from backend.pipeline.stage_preprocess import PreprocessStage
    from backend.vector_store import VectorStore
    from eval.run_eval import load_cases, snapshots_instead_of_network
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run")
    parser.add_argument("--show", type=int, default=3, help="print the first N cases' current query")
    args = parser.parse_args()
    rows = [json.loads(l) for l in open(args.run, encoding="utf-8") if l.strip()]
    cases = {c["rule_id"]: c for c in load_cases(REPO / "eval/manifest.jsonl", REPO, 2000)}
    with contextlib.redirect_stdout(io.StringIO()):
        store = VectorStore()
    results = []
    for row in rows:
        case = cases.get(row["rule_id"])
        if not case:
            continue
        with snapshots_instead_of_network(case["url_to_path"]), contextlib.redirect_stdout(io.StringIO()):
            pre = PreprocessStage(None, "").run({"original_query": " ".join(case["urls"]), "history": [],
                                                 "media_file": None})
        ctx = {"text": pre["preprocessed"]["combined_text"], "attack_vector": (row.get("pipeline") or {}).get("attack_vector")}
        gold = gold_techniques(yaml.safe_load((REPO / row["rule_path"]).read_text(encoding="utf-8")))
        if not gold:
            continue
        with contextlib.redirect_stdout(io.StringIO()):
            res = run_queries(store, ctx, gold)
        results.append({"rule_id": row["rule_id"], "gold": sorted(gold), **res})
        if len(results) <= args.show:
            print(f"--- {row['rule_id'][:8]} current query: {ctx['text'][:500]!r}"[:420])
    n = len(results)
    print(f"\n{Path(args.run).stem}: {n} cases whose gold rule names techniques")
    for name in QUERIES:
        hit = sum(1 for r in results if r[name]["recall"])
        hit_p = sum(1 for r in results if r[name]["recall_parent"])
        mean = sum(r[name]["recall"] for r in results) / n
        mean_p = sum(r[name]["recall_parent"] for r in results) / n
        print(f"  {name:15} a gold technique in the top 5: {hit:>2} of {n} (parent {hit_p:>2})   "
              f"mean recall {mean:.3f} (parent {mean_p:.3f})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
