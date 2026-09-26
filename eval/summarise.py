"""Summarise evaluation runs and compare two arms.

Reports each metric with the number of cases it was computed over, because the
metrics have different denominators: content scores exist only for rules that
parsed, and S4/S5 are undefined for some cases (no ATT&CK tags, keyword-only
detections). A mean without its n is not interpretable.

Every agreement metric is printed next to the null baseline measured in Change 4 —
the score obtained by pairing unrelated gold rules. A result near the baseline means
the system is doing no better than chance, which is easy to miss when looking at an
unanchored number.

Usage
-----
    .venv/bin/python eval/summarise.py eval/results/run.jsonl
    .venv/bin/python eval/summarise.py eval/results/a.jsonl eval/results/b.jsonl
"""

from __future__ import annotations

import argparse
import json
import statistics
from math import comb, sqrt
from pathlib import Path

# Measured in Change 4: score of a gold rule against a *different* gold rule.
NULL_BASELINES = {
    "logsource_exact": 0.173,
    "attack_f1": 0.092,
    "detection_f1": 0.133,
}


def load(path: Path) -> list:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def binom_p_above(k: int, n: int, p0: float) -> float:
    """Exact one-sided binomial p-value: P(X >= k) for X ~ Binomial(n, p0).

    S3 against chance (pre-registered 2026-09-26): one-sided, alpha 0.05, applied once
    to the final Phase 2 run; values on earlier runs are descriptive. The null p0 is
    treated as fixed (it is measured over many mismatched gold pairs, Change 4).
    """
    return min(1.0, sum(comb(n, i) * p0 ** i * (1 - p0) ** (n - i) for i in range(k, n + 1)))


def min_k_above(n: int, p0: float, alpha: float = 0.05) -> int:
    """Smallest count of n that binom_p_above would call above chance at alpha."""
    return next(k for k in range(n + 2) if k > n or binom_p_above(k, n, p0) < alpha)


def wilson_ci(k: int, n: int, z: float = 1.959963984540054) -> tuple:
    """95% Wilson score interval for a proportion k/n."""
    if n == 0:
        return (None, None)
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (centre - half, centre + half)


def _mean(values: list):
    # float() because statistics.mean returns an int for all-int input, which
    # would then bypass the float branch in _fmt and print as "0" not "0.00".
    return float(statistics.mean(values)) if values else None


def summarise(rows: list) -> dict:
    scored = [r for r in rows if r.get("scores")]
    parsed = [r for r in scored if (r["scores"].get("validity") or {}).get("parses")]

    logsource, attack, detection, issues = [], [], [], []
    for row in parsed:
        s = row["scores"]
        if s.get("logsource"):
            logsource.append(1.0 if s["logsource"]["exact_match"] else 0.0)
        if s.get("attack") and s["attack"]["exact"]["f1"] is not None:
            attack.append(s["attack"]["exact"]["f1"])
        if s.get("detection_fields") and s["detection_fields"]["f1"] is not None:
            detection.append(s["detection_fields"]["f1"])
        issues.append((s.get("validity") or {}).get("issue_count", 0))

    tokens, thinking, latency, missing = [], [], [], 0
    limited_calls = limited_cases = 0
    for row in rows:
        tel = row.get("telemetry") or {}
        if tel.get("total_tokens") is not None:
            tokens.append(tel["total_tokens"])
        if tel.get("thinking_tokens"):
            thinking.append(tel["thinking_tokens"])
        missing += tel.get("calls_without_token_data", 0)
        # Answers cut at the output limit (Change 24): a model failure, measured
        # with the case rather than stopping the run, so it is reported here.
        limited_calls += tel.get("calls_output_limited", 0)
        limited_cases += bool(tel.get("calls_output_limited", 0))
        if row.get("elapsed_s") is not None:
            latency.append(row["elapsed_s"])

    return {
        "n_cases": len(rows),
        "n_errors": sum(1 for r in rows if r.get("error")),
        "n_scored": len(scored),
        "validity_rate": _mean([1.0 if (r["scores"].get("validity") or {}).get("parses")
                                else 0.0 for r in scored]),
        "n_parsed": len(parsed),
        "mean_issues": _mean(issues),
        "logsource_exact": _mean(logsource),
        "n_logsource": len(logsource),
        "logsource_k": int(sum(logsource)),
        "logsource_p_above_chance": (binom_p_above(int(sum(logsource)), len(logsource),
                                                   NULL_BASELINES["logsource_exact"])
                                     if logsource else None),
        "logsource_ci": wilson_ci(int(sum(logsource)), len(logsource)),
        "attack_f1": _mean(attack),
        "n_attack": len(attack),
        "detection_f1": _mean(detection),
        "n_detection": len(detection),
        "mean_tokens": _mean(tokens),
        "total_tokens": sum(tokens) if tokens else None,
        "mean_thinking_tokens": _mean(thinking),
        "calls_without_token_data": missing,
        "calls_output_limited": limited_calls,
        "cases_output_limited": limited_cases,
        "mean_latency_s": _mean(latency),
        "mean_rules": _mean([r.get("n_rules", 0) for r in rows]),
    }


def _gate(name: str, rows: list, key: str, bad):
    """One check. `bad(row)` says whether a row fails it; rows without `key` did
    not record it. NOT RECORDED only when no row has the field at all."""
    present = [r for r in rows if key in r]
    if not present:
        return {"name": name, "status": "NOT RECORDED", "detail": f"no row has `{key}`"}
    failing = [r for r in present if bad(r)]
    return {"name": name, "status": "FAIL" if failing else "PASS",
            "detail": f"{len(failing)} of {len(present)} rows fail"}


def check_gates(rows: list) -> dict:
    """Is a result file citable? (plan 1.4a)

    The checks every run has had to pass, computed by hand until now. Gate 1
    covers both the page snapshots and, since Change 17, the PoC stage's GitHub
    fetches. A file written before a check existed says NOT RECORDED for it rather
    than passing it: the PoC counters arrived with Change 17, and case-level
    errors were invisible to the harness before Change 14 (defect 17), which is
    detected by the absence of the `pipeline` field added right after it.
    """
    if not rows:
        return {"checks": [], "verdict": "NOT CITABLE"}
    tel = lambda r: r.get("telemetry") or {}
    checks = [
        _gate("page snapshots all served", rows, "snapshots_missed",
              lambda r: r["snapshots_missed"]),
        _gate("PoC GitHub snapshots all served", rows, "poc_snapshots_missed",
              lambda r: r["poc_snapshots_missed"]),
        _gate("token data on every call", rows, "telemetry",
              lambda r: tel(r).get("calls_without_token_data", 0)),
        _gate("no failed LLM calls", rows, "telemetry",
              lambda r: tel(r).get("n_errors", 0)),
    ]
    if any("pipeline" in r for r in rows):
        checks.append(_gate("no case-level errors", rows, "error", lambda r: r["error"]))
    else:
        checks.append({"name": "no case-level errors", "status": "NOT RECORDED",
                       "detail": "file predates Change 14; crashes were not visible"})
    checks.append(_gate("no suspiciously fast cases (< 30 s)", rows, "elapsed_s",
                        lambda r: r["elapsed_s"] < 30))
    ids = [r.get("rule_id") for r in rows]
    dupes = len(ids) - len(set(ids))
    checks.append({"name": "no duplicate cases", "status": "FAIL" if dupes else "PASS",
                   "detail": f"{len(rows)} rows, {len(set(ids))} unique"})

    statuses = [c["status"] for c in checks]
    if "FAIL" in statuses:
        verdict = "NOT CITABLE"
    elif "NOT RECORDED" in statuses:
        verdict = f"CITABLE WITH CAVEATS ({statuses.count('NOT RECORDED')} not recorded)"
    else:
        verdict = "CITABLE"
    return {"checks": checks, "verdict": verdict}


def report_gates(result: dict) -> None:
    print("  gates:")
    for c in result["checks"]:
        print(f"    {c['status']:<13} {c['name']}  ({c['detail']})")
    print(f"  verdict: {result['verdict']}")


def split_by_contamination(rows: list, flags: dict = None) -> dict:
    """Split rows into clean / flagged / unknown (plan 1.3b).

    A row's own `contamination` field wins; rows written before the flag existed
    are looked up in `flags` (rule_id -> bool, from eval/contamination.jsonl). A
    case found in neither is `unknown`, never assumed clean.
    """
    flags = flags or {}
    split = {"clean": [], "flagged": [], "unknown": []}
    for row in rows:
        flagged = (row.get("contamination") or {}).get("flagged")
        if flagged is None:
            flagged = flags.get(row.get("rule_id"))
        key = "unknown" if flagged is None else ("flagged" if flagged else "clean")
        split[key].append(row)
    return split


def load_flags(path: Path) -> dict:
    """rule_id -> flagged, from the committed contamination list."""
    if not path.exists():
        return {}
    return {e["rule_id"]: e["flagged"] for e in
            (json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip())}


def _fmt(value, digits: int = 3) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def report(name: str, s: dict) -> None:
    print(f"\n=== {name} ===")
    print(f"  cases                : {s['n_cases']}  (errors: {s['n_errors']})")
    print(f"  S1 valid Sigma       : {_fmt(s['validity_rate'])}  (n={s['n_scored']})")
    print(f"  S2 mean issues/rule  : {_fmt(s['mean_issues'], 2)}  (n={s['n_parsed']})")

    for label, key, baseline_key in [
        ("S3 logsource exact  ", "logsource_exact", "logsource_exact"),
        ("S4 ATT&CK F1        ", "attack_f1", "attack_f1"),
        ("S5 detection F1     ", "detection_f1", "detection_f1"),
    ]:
        value = s[key]
        baseline = NULL_BASELINES[baseline_key]
        n = s["n_" + key.split("_")[0]] if ("n_" + key.split("_")[0]) in s else None
        marker = ""
        if value is not None:
            marker = "  <-- at/below chance" if value <= baseline else ""
        print(f"  {label} : {_fmt(value)}  (n={n}, chance={baseline}){marker}")
        if key == "logsource_exact" and s.get("n_logsource"):
            lo, hi = s["logsource_ci"]
            need = min_k_above(s["n_logsource"], baseline)
            print(f"    vs chance          : {s['logsource_k']}/{s['n_logsource']}, 95% Wilson CI "
                  f"[{lo:.3f}, {hi:.3f}], one-sided exact binomial p = "
                  f"{s['logsource_p_above_chance']:.3f} (p < 0.05 needs >= {need}/{s['n_logsource']})")

    print(f"  rules per case       : {_fmt(s['mean_rules'], 2)}")
    print(f"  mean tokens/case     : {_fmt(s['mean_tokens'], 0)}")
    print(f"  total tokens         : {_fmt(s['total_tokens'], 0)}")
    print(f"  mean thinking tokens : {_fmt(s['mean_thinking_tokens'], 0)}")
    print(f"  mean latency (s)     : {_fmt(s['mean_latency_s'], 1)}")
    print(f"  answers cut at limit : {s['calls_output_limited']} calls in "
          f"{s['cases_output_limited']} cases")
    if s["calls_without_token_data"]:
        print(f"  WARNING: {s['calls_without_token_data']} LLM calls reported no token "
              f"data — cost figures are incomplete")


def compare(a: dict, b: dict, name_a: str, name_b: str) -> None:
    print(f"\n=== {name_a} vs {name_b} ===")
    print(f"  {'metric':<22} {'A':>10} {'B':>10} {'delta':>10}")
    for label, key, digits in [
        ("S1 valid Sigma", "validity_rate", 3),
        ("S3 logsource exact", "logsource_exact", 3),
        ("S4 ATT&CK F1", "attack_f1", 3),
        ("S5 detection F1", "detection_f1", 3),
        ("S2 mean issues", "mean_issues", 2),
        ("mean tokens/case", "mean_tokens", 0),
        ("mean latency (s)", "mean_latency_s", 1),
    ]:
        va, vb = a[key], b[key]
        delta = "n/a" if (va is None or vb is None) else f"{vb - va:+.{digits}f}"
        print(f"  {label:<22} {_fmt(va, digits):>10} {_fmt(vb, digits):>10} {delta:>10}")
    print("\n  Deltas are descriptive only. Significance requires a paired test over "
          "the per-case scores (McNemar for S1/S3, bootstrap CI for S4/S5).")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", nargs="+", help="One or two JSONL result files.")
    parser.add_argument("--contamination", default="eval/contamination.jsonl",
                        help="Flag list applied to rows that carry no flag of their own.")
    args = parser.parse_args()
    flags = load_flags(Path(args.contamination))

    paths = [Path(p) for p in args.results]
    for path in paths:
        if not path.exists():
            raise SystemExit(f"Not found: {path}")

    summaries = [summarise(load(p)) for p in paths]
    for path, summary in zip(paths, summaries):
        report(path.name, summary)
        report_gates(check_gates(load(path)))
        split = split_by_contamination(load(path), flags)
        # Headline on the clean cases; flagged cases on their own line (plan 1.3b).
        if split["flagged"] or split["clean"]:
            report(f"{path.name} - clean cases (no detection rule in the input)",
                   summarise(split["clean"]))
            report(f"{path.name} - flagged cases (a detection rule reaches the pipeline)",
                   summarise(split["flagged"]))
        if split["unknown"]:
            print(f"\n  NOTE: {len(split['unknown'])} case(s) have no contamination flag "
                  "(not in the flag list) and appear in neither subset.")

    if len(summaries) == 2:
        compare(summaries[0], summaries[1], paths[0].name, paths[1].name)


if __name__ == "__main__":
    main()
