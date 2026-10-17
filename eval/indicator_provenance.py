#!/usr/bin/env python3
"""Do the analysis's indicators that are NOT in the report carry the expert's outside knowledge? (offline, post-hoc;
user 2026-10-17, before Change 53's run)

An indicator is "in the report" when its value - defanging (`[.]`, `hxxp`), case, whitespace and doubled backslashes
ignored (`signature_grounding._norm`) - appears in the text the pipeline read (`diagnose_detection._case_text`). Per
group: listed, used by a rule (the pipeline's `indicator_use` record), and used AND matching one of the gold rule's
detection values (`scorers.value_matches`, as S5v). Values under 3 characters are skipped.

Usage:
    .venv/bin/python eval/indicator_provenance.py eval/results/<run>.jsonl [...]
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.scorers import normalise_value, value_matches  # noqa: E402
from eval.signature_grounding import _norm  # noqa: E402

GROUPS = ("in the report", "not in the report")


def _flat(text: str) -> str:
    return " ".join(_norm(text).split())


def in_report(value: str, text: str) -> bool:
    return _flat(value) in _flat(text)


def group_counts(indicators: list, used: set, text: str, gold_values: list) -> dict:
    out = {g: {"listed": 0, "used": 0, "used_matching_expert": 0} for g in GROUPS}
    used = {str(u).lower() for u in used}
    flat_text = _flat(text)
    for ind in indicators:
        value = str((ind or {}).get("value", ""))
        if len(value) < 3:
            continue
        g = out[GROUPS[0] if _flat(value) in flat_text else GROUPS[1]]
        g["listed"] += 1
        if value.lower() in used:
            g["used"] += 1
            g["used_matching_expert"] += any(value_matches(gv, normalise_value(value)) for gv in gold_values)
    return out


def main(argv: list) -> int:
    import yaml
    from eval.diagnose_detection import _case_text
    from eval.run_eval import load_cases, load_github_manifest
    from eval.scorers import extract_detection_values
    if len(argv) < 2:
        print(__doc__)
        return 1
    with contextlib.redirect_stdout(io.StringIO()):
        cases = {c["rule_id"]: c for c in load_cases(REPO / "eval/manifest.jsonl", REPO, 2000)}
    url_map = load_github_manifest(REPO / "eval/github_manifest.jsonl")
    for path in argv[1:]:
        total = {g: {"listed": 0, "used": 0, "used_matching_expert": 0} for g in GROUPS}
        for line in open(path, encoding="utf-8"):
            if not line.strip():
                continue
            row = json.loads(line)
            case = cases.get(row.get("rule_id"))
            if not case:
                continue
            p = row.get("pipeline") or {}
            gold = yaml.safe_load(open(REPO / case["rule_path"], encoding="utf-8"))
            gold_values = [v for _, v in extract_detection_values((gold or {}).get("detection"))]
            c = group_counts(p.get("indicators") or [], set((p.get("indicator_use") or {}).get("used") or []),
                             _case_text(case, url_map), gold_values)
            for g in GROUPS:
                for k in total[g]:
                    total[g][k] += c[g][k]
        print(Path(path).stem)
        for g in GROUPS:
            t = total[g]
            print(f"  {g:18} listed {t['listed']:5}, used by a rule {t['used']:4}, used and matching an expert value "
                  f"{t['used_matching_expert']:3}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
