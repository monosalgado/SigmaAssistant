#!/usr/bin/env python3
"""Change 53's measure: how many indicators the analysis lists, and how many a rule uses (offline; saved rows).

Per run: reports; indicators listed (total, median per report); used by any rule - from the pipeline's own
`indicator_use` record (Change 40: an indicator is used when a rule's detection value contains it or is contained in
it); the used share; hashes and IPs listed; and per type, listed -> used.

Usage:
    .venv/bin/python eval/indicator_counts.py eval/results/<run>.jsonl [...]
"""

from __future__ import annotations

import json
import statistics
import sys
from collections import Counter
from pathlib import Path


def run_counts(rows: list) -> dict:
    listed, used, per_report = 0, 0, []
    types_listed, types_used = Counter(), Counter()
    for row in rows:
        p = row.get("pipeline") or {}
        indicators = [i for i in p.get("indicators") or [] if isinstance(i, dict)]
        used_values = {str(v).lower() for v in ((p.get("indicator_use") or {}).get("used") or [])}
        per_report.append(len(indicators))
        listed += len(indicators)
        for ind in indicators:
            kind = ind.get("type") or "?"
            types_listed[kind] += 1
            if str(ind.get("value", "")).lower() in used_values:
                types_used[kind] += 1
                used += 1
    return {"reports": len(rows), "listed": listed, "used": used,
            "median_listed": statistics.median(per_report) if per_report else 0,
            "used_share": round(used / listed, 3) if listed else 0.0,
            "hashes_and_ips": types_listed["hash"] + types_listed["ip_address"],
            "by_type": {k: {"listed": types_listed[k], "used": types_used[k]} for k, _ in types_listed.most_common()}}


def main(argv: list) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1
    for path in argv[1:]:
        rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
        c = run_counts(rows)
        print(f"{Path(path).stem:22} {c['reports']} reports: listed {c['listed']} (median {c['median_listed']} per "
              f"report), used by a rule {c['used']} ({c['used_share']:.0%}); hashes + IPs listed {c['hashes_and_ips']}")
        print("   by type (listed -> used): " + ", ".join(f"{k} {v['listed']}->{v['used']}"
                                                         for k, v in c["by_type"].items()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
