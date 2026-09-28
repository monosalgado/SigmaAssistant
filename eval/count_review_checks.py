#!/usr/bin/env python3
"""Adherence to the analyst's review - the counts fixed in the simulated-analyst plan (5.3).
Offline: reads a finished result file (the oracle arm's rows keep `analyst_check`).

- checked                 cases whose review asked something of the rules
- followed_first_time     no departure after the first generation
- rewritten               a departure (the analyst's log source, a rejected technique) got the
                          one rewrite
- followed_after_rewrite  none remained after it
- still_departing         some remained (shown, the rules not edited)
- rewrite_failed          the rewrite gave no rules; the earlier rules were kept
- flagged                 a rejected string used in a detection (shown, never rewritten)
- choice_in_a_later_rule  still departing, but a later rule uses the analyst's log source (the
                          model changed the order); post-hoc, added after the 5.3 run
Rows of crashed cases (error set) are left out.

Usage:
    .venv/bin/python eval/count_review_checks.py eval/results/<run>_oracle.jsonl
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.pipeline.sigma_logsource import _clean  # noqa: E402


def _later_rule_follows(row: dict) -> bool:
    choice = ((row.get("oracle_review") or {}).get("logsource")) or None
    if not choice:
        return False
    for rule in (row.get("rules_yaml") or [])[1:]:
        try:
            logsource = (yaml.safe_load(rule) or {}).get("logsource") or {}
        except yaml.YAMLError:
            continue
        if isinstance(logsource, dict) and \
                {f: _clean(logsource.get(f)) for f in ("category", "product", "service")} == choice:
            return True
    return False


def count_checks(rows: list) -> dict:
    rows = [r for r in rows if not r.get("error")]
    out = {k: [] for k in ("followed_first_time", "rewritten", "followed_after_rewrite",
                           "still_departing", "rewrite_failed", "flagged", "choice_in_a_later_rule")}
    kinds = Counter()
    checked = 0
    for row in rows:
        check = (row.get("pipeline") or {}).get("analyst_check")
        if not check:
            continue
        checked += 1
        rid = row["rule_id"]
        before, after = check.get("departures_before") or [], check.get("departures") or []
        kinds.update(d.get("kind") for d in before)
        if not before:
            out["followed_first_time"].append(rid)
        if check.get("rewritten"):
            out["rewritten"].append(rid)
            (out["still_departing"] if after else out["followed_after_rewrite"]).append(rid)
            if after and _later_rule_follows(row):
                out["choice_in_a_later_rule"].append(rid)
        if check.get("rewrite_failed"):
            out["rewrite_failed"].append(rid)
        if check.get("flagged"):
            out["flagged"].append(rid)
    return dict(out, cases=len(rows), checked=checked, departures_by_kind=dict(kinds))


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    rows = [json.loads(l) for l in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines() if l.strip()]
    out = count_checks(rows)
    print(sys.argv[1])
    print(f"  cases: {out['cases']}, checked against the review: {out['checked']}")
    for key in ("followed_first_time", "rewritten", "followed_after_rewrite", "still_departing",
                "choice_in_a_later_rule", "rewrite_failed", "flagged"):
        ids = out[key]
        print(f"  {key.replace('_', ' '):<24} {len(ids):>3}  {' '.join(i[:8] for i in ids) if 0 < len(ids) <= 12 else ''}")
    print(f"  departures by kind (first generation): {out['departures_by_kind']}")


if __name__ == "__main__":
    main()
