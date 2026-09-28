#!/usr/bin/env python3
"""S5 (detection-field F1) between two runs, split by what happened to S3 in each case:
became right, right in both, wrong in both, became wrong. Offline; paired by rule_id with
`compare_runs.metric_value`, so the cases are those the paired comparison scores.

Written for the simulated-analyst result (plan 5.3), post-hoc: is the S5 gain only the
cases whose log source became right?

Usage:
    .venv/bin/python eval/s5_by_logsource.py <run A>.jsonl <run B>.jsonl
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.compare_runs import load, metric_value  # noqa: E402

GROUPS = {(False, True): "became right", (True, True): "right in both",
          (False, False): "wrong in both", (True, False): "became wrong"}


def split_s5(a: dict, b: dict) -> dict:
    out = {name: {"cases": [], "a": [], "b": []} for name in GROUPS.values()}
    for rid in a:
        if rid not in b:
            continue
        s3 = (metric_value(a[rid], "S3"), metric_value(b[rid], "S3"))
        s5 = (metric_value(a[rid], "S5"), metric_value(b[rid], "S5"))
        if None in s3 or None in s5:
            continue
        group = out[GROUPS[s3]]
        group["cases"].append(rid)
        group["a"].append(s5[0])
        group["b"].append(s5[1])
    for group in out.values():
        n = len(group["cases"])
        group["mean_a"] = round(sum(group.pop("a")) / n, 3) if n else None
        group["mean_b"] = round(sum(group.pop("b")) / n, 3) if n else None
    return out


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    groups = split_s5(load(Path(sys.argv[1])), load(Path(sys.argv[2])))
    print(f"A: {sys.argv[1]}\nB: {sys.argv[2]}")
    print(f"{'S3 (A -> B)':<16}{'n':>4}{'S5 A':>9}{'S5 B':>9}{'B - A':>9}")
    for name, g in groups.items():
        n = len(g["cases"])
        diff = "" if not n else f"{g['mean_b'] - g['mean_a']:+.3f}"
        print(f"{name:<16}{n:>4}{g['mean_a'] if n else '-':>9}{g['mean_b'] if n else '-':>9}{diff:>9}")


if __name__ == "__main__":
    main()
