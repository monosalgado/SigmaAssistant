#!/usr/bin/env python3
"""Write backend/pipeline/sigma_logsource_table.json from the local SigmaHQ rules.

The analysis prompt's log-source reference table (Change 28, plan 2.6): every category
with the products its rules use, and every product/service pair used without a category,
each with its most-used detection fields. Built from data/sigma/rules — the directory the
retrieval index is built from — and never from rules-emerging-threats, which holds the
evaluation's answers.

Usage:
    .venv/bin/python scripts/build_sigma_logsource_table.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from backend.pipeline.sigma_logsource import LOGSOURCE_TABLE_PATH, build_logsource_table  # noqa: E402


def sigmahq_commit(sigma_dir: Path) -> str:
    try:
        return subprocess.run(["git", "-C", str(sigma_dir), "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main() -> int:
    rules = REPO / "data/sigma/rules"
    if not rules.is_dir():
        print(f"{rules} not found: clone SigmaHQ into data/sigma first.")
        return 1
    table = build_logsource_table(rules)
    rows = lambda key: ",\n".join("    " + json.dumps(r) for r in table[key])  # one row per line
    LOGSOURCE_TABLE_PATH.write_text(
        "{\n"
        f'  "source": "data/sigma/rules",\n'
        f'  "sigmahq_commit": {json.dumps(sigmahq_commit(REPO / "data/sigma"))},\n'
        f'  "with_category": [\n{rows("with_category")}\n  ],\n'
        f'  "without_category": [\n{rows("without_category")}\n  ]\n'
        "}\n", encoding="utf-8")
    print(f"{len(table['with_category'])} categories and {len(table['without_category'])} "
          f"sources without a category written to {LOGSOURCE_TABLE_PATH.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
