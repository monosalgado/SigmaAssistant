#!/usr/bin/env python3
"""Count the attack-vector prompt's example text copied into a run's attack vectors.

Plan 2.3 (step d): measured on the reference run BEFORE Change 27's run, so both sides
use the same code. Offline, no LLM: reads a finished result file's recorded attack
vectors (`row["pipeline"]["attack_vector"]`, baseline v2 onward).

Criterion — the defect-15 one, `probe_attack_vector.leaked_markers`: an invented marker
string from the prompt's examples appears in the output AND is absent from the input.
The input here is the case's extracted text (preprocessed offline from the snapshots)
plus the bodies of the GitHub files the PoC stage fetched: a superset of what the
attack-vector stage saw (it gets the PoC stage's summary of that code), so the count is
a LOWER bound, like the probe's.

- anywhere:  a marker anywhere in the recorded attack vector
- in_vector: a marker in the vector itself — initial access vector, entry point,
             attacker-controlled input, payload signatures (not the incidental list)
- in_rules:  a marker in the generated rules (added 2026-09-26, before the defect-15 run).
             Generation also reads retrieved documents; none of the markers occurs in any
             retrieval collection (`--check-retrieval`), so a marker absent from the input
             can only have come from the prompt's examples.

Usage:
    .venv/bin/python eval/count_example_copies.py eval/results/p2c_first_rule60.jsonl
    .venv/bin/python eval/count_example_copies.py --check-retrieval
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from backend.pipeline.stage_poc_analysis import github_fetch_targets  # noqa: E402
from eval.probe_attack_vector import EXAMPLE_MARKERS, leaked_markers  # noqa: E402

VECTOR_FIELDS = ("initial_access_vector", "entry_point", "attacker_controlled_input",
                 "payload_signatures")


def copies(attack_vector: dict, model_input_text: str, rules_text: str = "") -> dict:
    vector_part = {k: attack_vector.get(k) for k in VECTOR_FIELDS}
    return {"anywhere": leaked_markers(json.dumps(attack_vector), model_input_text),
            "in_vector": leaked_markers(json.dumps(vector_part), model_input_text),
            "in_rules": leaked_markers(rules_text, model_input_text)}


def rules_text(row: dict) -> str:
    rules = row.get("rules_yaml") or []
    return rules if isinstance(rules, str) else "\n".join(str(r) for r in rules)


def corpus_hits(texts) -> dict:
    """How many reference texts contain each marker (case-insensitive)."""
    hits = Counter()
    for text in texts:
        low = (text or "").lower()
        hits.update(m for markers in EXAMPLE_MARKERS.values() for m in markers if m in low)
    return dict(hits)


def github_bodies(text: str, url_map: dict, read=None) -> list:
    """Stored bodies of the GitHub files and gists the PoC stage fetches for `text`."""
    read = read or (lambda path: Path(path).read_text(encoding="utf-8", errors="replace"))
    files, gists = github_fetch_targets(text)
    bodies = []
    for target in files + gists:
        entry = url_map.get(target["fetch_url"]) or {}
        if entry.get("path"):
            bodies.append(read(entry["path"]))
    return bodies


def model_input(text: str, bodies: list) -> str:
    return "\n".join([text] + list(bodies))


def summarise(results: list) -> dict:
    return {
        "n": len(results),
        "anywhere": sum(1 for r in results if r["anywhere"]),
        "in_vector": sum(1 for r in results if r["in_vector"]),
        "by_example_anywhere": dict(Counter(g for r in results for g in r["anywhere"])),
        "by_example_in_vector": dict(Counter(g for r in results for g in r["in_vector"])),
        "in_rules": sum(1 for r in results if r.get("in_rules")),
        "by_example_in_rules": dict(Counter(g for r in results for g in r.get("in_rules", {}))),
    }


def check_retrieval(path: Path = REPO / "data/chroma_db") -> int:
    """Markers in the local retrieval collections: none means a marker in a rule cannot
    have come from a retrieved document."""
    import chromadb

    client = chromadb.PersistentClient(path=str(path))
    for listed in client.list_collections():
        collection = client.get_collection(getattr(listed, "name", listed))
        n, texts = collection.count(), []
        for offset in range(0, n, 2000):
            texts += collection.get(limit=2000, offset=offset, include=["documents"])["documents"]
        print(f"  {collection.name:20} {n:6} documents, markers found: {corpus_hits(texts) or 'none'}")
    return 0


def main(argv: list) -> int:
    if argv[1:] == ["--check-retrieval"]:
        return check_retrieval()
    if len(argv) != 2:
        print(__doc__)
        return 1
    from backend.pipeline.stage_preprocess import PreprocessStage
    from eval.run_eval import load_cases, load_github_manifest, snapshots_instead_of_network

    rows = [json.loads(l) for l in Path(argv[1]).read_text(encoding="utf-8").splitlines() if l.strip()]
    cases = {c["rule_id"]: c for c in load_cases(REPO / "eval/manifest.jsonl", REPO, 2000)}
    url_map = load_github_manifest(REPO / "eval/github_manifest.jsonl")

    results = []
    for row in rows:
        av = (row.get("pipeline") or {}).get("attack_vector")
        case = cases.get(row["rule_id"])
        if not av or not case:
            continue
        with snapshots_instead_of_network(case["url_to_path"]), \
                contextlib.redirect_stdout(io.StringIO()):
            ctx = PreprocessStage(None, "").run(
                {"original_query": " ".join(case["urls"]), "history": [], "media_file": None})
        text = ctx["preprocessed"]["combined_text"]
        found = copies(av, model_input(text, github_bodies(text, url_map)), rules_text(row))
        results.append({"rule_id": row["rule_id"], **found})

    s = summarise(results)
    print(f"{argv[1]}: {s['n']} recorded attack vectors")
    print(f"  example text copied anywhere      : {s['anywhere']} cases {s['by_example_anywhere']}")
    print(f"  ... in the vector itself          : {s['in_vector']} cases {s['by_example_in_vector']}")
    for r in results:
        if r["in_vector"]:
            print(f"    {r['rule_id'][:8]}  {r['in_vector']}")
    print(f"  ... in the generated rules        : {s['in_rules']} cases {s['by_example_in_rules']}")
    for r in results:
        if r["in_rules"]:
            print(f"    {r['rule_id'][:8]}  {r['in_rules']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
