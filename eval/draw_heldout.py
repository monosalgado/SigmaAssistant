#!/usr/bin/env python3
"""Draw the held-out cases for plan 2.9, once.

Every Phase 2 change was found by reading failures in the 60 seed-0 cases and measured on
the same cases. The confirmation uses cases that no run has touched: the corpus cases
(`load_cases`, the harness's own filter) whose rule id appears in NO result file under
eval/results — the tuning runs, pilots, probes and preflight smoke runs alike. From those,
the harness's stratified sampler (`stratified_sample`, seed 0) draws 60, and their manifest
lines are written verbatim to eval/manifest_heldout.jsonl, which both the final pipeline
and baseline v2's code run with `--manifest`.

The file is written once and committed before any run on it; the script refuses to
overwrite it.

Usage:
    .venv/bin/python eval/draw_heldout.py
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

HELDOUT_PATH = REPO / "eval/manifest_heldout.jsonl"
N_CASES = 60
SEED = 0


def used_rule_ids(results_dir: Path) -> set:
    """Rule ids in every result file (*.jsonl*, backups included), recursively."""
    used = set()
    for path in Path(results_dir).rglob("*.jsonl*"):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and row.get("rule_id"):
                used.add(row["rule_id"])
    return used


def select_heldout(cases: list, used: set, n: int, seed: int) -> list:
    from eval.run_eval import stratified_sample

    return stratified_sample([c for c in cases if c["rule_id"] not in used], n, seed)


def subset_manifest_lines(manifest: Path, rule_ids: set) -> list:
    lines = []
    for line in Path(manifest).read_text(encoding="utf-8").splitlines():
        if line.strip() and json.loads(line)["rule_id"] in rule_ids:
            lines.append(line)
    return lines


def write_once(path: Path, lines: list) -> None:
    path = Path(path)
    if path.exists():
        raise FileExistsError(f"{path} exists: the held-out cases are drawn once")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    from eval.run_eval import load_cases

    manifest = REPO / "eval/manifest.jsonl"
    with contextlib.redirect_stdout(io.StringIO()):
        cases = load_cases(manifest, REPO, 2000)
    used = used_rule_ids(REPO / "eval/results")
    pool = [c for c in cases if c["rule_id"] not in used]
    drawn = select_heldout(cases, used, N_CASES, SEED)
    lines = subset_manifest_lines(manifest, {c["rule_id"] for c in drawn})
    write_once(HELDOUT_PATH, lines)
    print(f"corpus {len(cases)} cases; ever run {len(used & {c['rule_id'] for c in cases})}; "
          f"never run {len(pool)}; drawn {len(lines)} (seed {SEED}) -> {HELDOUT_PATH.relative_to(REPO)}")
    print("categories:", dict(Counter(c.get("category") or "none" for c in drawn).most_common()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
