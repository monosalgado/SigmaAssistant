#!/usr/bin/env python3
"""Compare two runs on the same cases, case by case (paired). Standard library only.

Why paired: S2-S5 are computed only on cases whose first rule parses, so the unpaired
means of two runs average different cases. Baseline v1 -> v2: the unpaired S4 rose
0.123 -> 0.175; on the same 35 cases the difference was +0.014, interval spanning zero.

Method (the same as the scratch analysis logged for baseline v2):
- Cases are matched by `rule_id`; each metric uses only the cases scored in BOTH runs.
- S1 (first rule parses) and S3 (logsource exact match): exact McNemar test — a
  two-sided binomial test on the discordant cases.
- S4, S5, tokens, seconds and rules per case: mean difference (B - A) with a paired
  bootstrap 95% interval (10,000 resamples, seed 0, percentile method with linear
  interpolation). Python's random generator, not numpy's, so the intervals differ from
  the scratch script's in the last digits; the method is the same.

Usage:
    .venv/bin/python eval/compare_runs.py <run A>.jsonl <run B>.jsonl
"""

from __future__ import annotations

import json
import random
import sys
from math import comb
from pathlib import Path
from typing import Optional

BINARY = ("S1", "S3")
CONTINUOUS = ("S4", "S5", "tokens", "seconds", "rules")
LABELS = {
    "S1": "S1 valid Sigma", "S3": "S3 logsource exact", "S4": "S4 ATT&CK F1",
    "S5": "S5 detection F1", "tokens": "tokens per case", "seconds": "seconds per case",
    "rules": "rules per case",
}


def load(path: Path) -> dict:
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip()]
    return {r["rule_id"]: r for r in rows}


def metric_value(row: dict, metric: str):
    scores = row.get("scores") or {}
    parses = bool((scores.get("validity") or {}).get("parses"))
    if metric == "S1":
        return parses if scores else None
    if metric in ("S3", "S4", "S5"):
        if not parses:
            return None
        if metric == "S3":
            logsource = scores.get("logsource")
            return None if not logsource else bool(logsource["exact_match"])
        if metric == "S4":
            return ((scores.get("attack") or {}).get("exact") or {}).get("f1")
        return (scores.get("detection_fields") or {}).get("f1")
    if metric == "tokens":
        return (row.get("telemetry") or {}).get("total_tokens")
    if metric == "seconds":
        return row.get("elapsed_s")
    if metric == "rules":
        return row.get("n_rules")
    raise ValueError(metric)


def paired(a: dict, b: dict, metric: str) -> list:
    out = []
    for rid in a:
        if rid not in b:
            continue
        x, y = metric_value(a[rid], metric), metric_value(b[rid], metric)
        if x is not None and y is not None:
            out.append((x, y))
    return out


def mcnemar(pairs: list) -> dict:
    only_a = sum(1 for x, y in pairs if x and not y)
    only_b = sum(1 for x, y in pairs if y and not x)
    n = only_a + only_b
    if n == 0:
        p = 1.0
    else:
        tail = sum(comb(n, k) for k in range(min(only_a, only_b) + 1)) / 2 ** n
        p = min(1.0, 2 * tail)
    return {"n": len(pairs), "a_true": sum(1 for x, _ in pairs if x),
            "b_true": sum(1 for _, y in pairs if y), "only_a": only_a, "only_b": only_b, "p": p}


def percentile(values: list, q: float) -> float:
    """Linear interpolation between closest ranks (numpy's default)."""
    s = sorted(values)
    pos = (len(s) - 1) * q / 100
    lo = int(pos)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def bootstrap_ci(diffs: list, resamples: int = 10_000, seed: int = 0) -> tuple:
    rng = random.Random(seed)
    n = len(diffs)
    means = [sum(rng.choices(diffs, k=n)) / n for _ in range(resamples)]
    return percentile(means, 2.5), percentile(means, 97.5)


def continuous(pairs: list) -> dict:
    diffs = [y - x for x, y in pairs]
    n = len(pairs)
    return {
        "n": n,
        "mean_a": sum(x for x, _ in pairs) / n if n else None,
        "mean_b": sum(y for _, y in pairs) / n if n else None,
        "diff": sum(diffs) / n if n else None,
        "ci": bootstrap_ci(diffs) if n else (None, None),
        "better": sum(1 for d in diffs if d > 0),
        "worse": sum(1 for d in diffs if d < 0),
        "same": sum(1 for d in diffs if d == 0),
    }


def compare(a: dict, b: dict) -> dict:
    result = {"matched": len(set(a) & set(b)), "only_in_a": len(set(a) - set(b)),
              "only_in_b": len(set(b) - set(a))}
    for m in BINARY:
        result[m] = mcnemar(paired(a, b, m))
    for m in CONTINUOUS:
        result[m] = continuous(paired(a, b, m))
    return result


def _fmt(x: Optional[float], digits: int) -> str:
    return "n/a" if x is None else f"{x:.{digits}f}"


def main(argv: list) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 1
    a, b = load(Path(argv[1])), load(Path(argv[2]))
    r = compare(a, b)
    print(f"A: {argv[1]} ({len(a)} rows)\nB: {argv[2]} ({len(b)} rows)")
    print(f"matched cases: {r['matched']}"
          + (f"  (only in A: {r['only_in_a']}, only in B: {r['only_in_b']})"
             if r["only_in_a"] or r["only_in_b"] else ""))
    print("Each metric uses only the cases scored in both runs.\n")
    print(f"{'metric':22} {'n':>3}  {'A':>9} {'B':>9}  difference / test")
    for m in BINARY:
        s = r[m]
        print(f"{LABELS[m]:22} {s['n']:>3}  {s['a_true']:>9} {s['b_true']:>9}  "
              f"{s['only_a']} only A, {s['only_b']} only B; exact McNemar p = {s['p']:.3f}")
    for m in CONTINUOUS:
        s = r[m]
        d = 0 if m == "tokens" else (1 if m == "seconds" else 3)
        print(f"{LABELS[m]:22} {s['n']:>3}  {_fmt(s['mean_a'], d):>9} {_fmt(s['mean_b'], d):>9}  "
              f"{'+' if (s['diff'] or 0) >= 0 else ''}{_fmt(s['diff'], d)}, 95% CI "
              f"[{_fmt(s['ci'][0], d)}, {_fmt(s['ci'][1], d)}]; "
              f"B higher/lower/same: {s['better']}/{s['worse']}/{s['same']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
