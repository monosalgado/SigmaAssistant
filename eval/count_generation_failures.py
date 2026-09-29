#!/usr/bin/env python3
"""Generation answers that could not be read - the measure for Change 36 (defect 5), fixed
before its run. Offline: reads finished result files.

- cases_without_rules_unreadable  cases with no rule whose kept response carries
                                  "Generation error" (the answer could not be read on every
                                  attempt). Computable for every run, old and new.
- calls_unreadable                generation calls whose answer could not be read, retried
                                  or not: `parse_error` in the row's generation log. Recorded
                                  from Change 36 on; None (not recorded) for older runs.
- cases_with_an_unreadable_call   the cases with at least one such call (None if not recorded).
Rows of crashed cases (error set) are left out.

Usage:
    .venv/bin/python eval/count_generation_failures.py eval/results/<run>.jsonl [<run2>.jsonl ...]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def count_failures(rows: list) -> dict:
    rows = [r for r in rows if not r.get("error")]
    lost, calls, recorded, unreadable, cases_unreadable = [], 0, False, 0, []
    for row in rows:
        if row.get("n_rules", 0) == 0 and "Generation error" in (row.get("response_text") or ""):
            lost.append(row["rule_id"])
        generations = (row.get("pipeline") or {}).get("generations") or []
        calls += len(generations)
        failed = [g for g in generations if "parse_error" in g and g["parse_error"]]
        recorded = recorded or any("parse_error" in g for g in generations)
        unreadable += len(failed)
        if failed:
            cases_unreadable.append(row["rule_id"])
    return {
        "cases": len(rows),
        "cases_without_rules_unreadable": lost,
        "calls": calls,
        "calls_unreadable": unreadable if recorded else None,
        "cases_with_an_unreadable_call": cases_unreadable if recorded else None,
    }


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    for path in sys.argv[1:]:
        rows = [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]
        out = count_failures(rows)
        print(f"{path}")
        print(f"  cases scored: {out['cases']}")
        print(f"  cases with no rule, answer unreadable: {len(out['cases_without_rules_unreadable'])} "
              f"{out['cases_without_rules_unreadable']}")
        if out["calls_unreadable"] is None:
            print(f"  generation calls: {out['calls']} (unreadable answers not recorded in this run)")
        else:
            print(f"  generation calls: {out['calls']}, unreadable: {out['calls_unreadable']} "
                  f"in {len(out['cases_with_an_unreadable_call'])} cases")


if __name__ == "__main__":
    main()
