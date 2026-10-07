#!/usr/bin/env python3
"""Are the payload signatures in the report, and do the ones that are not reach the rules anyway? (#6, pipeline
quality, the prompt review's P2; user 2026-10-07; offline, from saved rows - post-hoc, to motivate a change)

The rule writer is told the attack-vector stage's payload signatures are "strings/patterns a real attacker MUST produce",
and the coverage retry that each missed one "MUST literally" appear in a rule. Per signature:
- **in the report** - its literal text (regex escapes of punctuation undone; defanging `[.]`, `hxxp`, case and doubled
  backslashes ignored)
  appears in the text the pipeline read (`diagnose_detection._case_text`);
- **in parts** - a regex whose literal fragments of >= 4 characters all appear;
- **not in the report**;
and whether the stage marked it `inferred_from_class` (the prompt allows it); then whether the final rules use it - the
pipeline's own coverage record (`coverage_check.payload_signatures_covered`).

Usage:
    .venv/bin/python eval/signature_grounding.py eval/results/<run>.jsonl [...]
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

STATUSES = ("in the report", "in parts", "not in the report")
_ESCAPED = re.compile(r"\\([.\-/?()\[\]+*$^|{}])")
_META = re.compile(r"\.\*|\.\+|\[[^\]]*\][*+?]?|\{\d+(?:,\d*)?\}|[()|+?*^$]")


def _norm(text: str) -> str:
    # A run of backslashes read as one: rules and JSON double them (`C:\\Users`), reports do not.
    t = re.sub(r"\\+", r"\\", text or "").lower()
    for fanged, plain in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[:]", ":"), ("hxxp", "http")):
        t = t.replace(fanged, plain)
    return t


def literal(pattern: str) -> str:
    """The pattern's text with regex escapes of punctuation undone, defanging removed, lower case."""
    return _norm(_ESCAPED.sub(r"\1", pattern or ""))


def _fragments(pattern: str) -> list:
    masked = _ESCAPED.sub(lambda m: "\x00" + m.group(1), pattern or "")
    return [_norm(p.replace("\x00", "")).strip() for p in _META.split(masked)]


def signature_status(pattern: str, report_text: str) -> str:
    text = _norm(report_text)
    parts = _fragments(pattern)
    if len(parts) == 1:
        return "in the report" if literal(pattern).strip() and literal(pattern).strip() in text else "not in the report"
    long_parts = [p for p in parts if len(p) >= 4]
    return "in parts" if long_parts and all(p in text for p in long_parts) else "not in the report"


def run_counts(rows: list, texts: dict) -> dict:
    out = {"cases": 0, "signatures": 0, "status": dict.fromkeys(STATUSES, 0), "used": dict.fromkeys(STATUSES, 0),
           "inferred_from_class": 0, "not_in_report_not_inferred": 0, "not_in_report_not_inferred_used": 0}
    for row in rows:
        if row.get("rule_id") not in texts:
            continue
        out["cases"] += 1
        pipeline = row.get("pipeline") or {}
        covered = set((pipeline.get("coverage_check") or {}).get("payload_signatures_covered") or [])
        for sig in (pipeline.get("attack_vector") or {}).get("payload_signatures") or []:
            if not isinstance(sig, dict) or not sig.get("pattern"):
                continue
            status = signature_status(sig["pattern"], texts[row["rule_id"]])
            used = sig["pattern"] in covered
            inferred = sig.get("derived_from") == "inferred_from_class"
            out["signatures"] += 1
            out["status"][status] += 1
            out["used"][status] += used
            out["inferred_from_class"] += inferred
            if status == "not in the report" and not inferred:
                out["not_in_report_not_inferred"] += 1
                out["not_in_report_not_inferred_used"] += used
    return out


def main(argv: list) -> int:
    import contextlib
    import io

    from eval.diagnose_detection import _case_text
    from eval.run_eval import load_cases, load_github_manifest
    if len(argv) < 2:
        print(__doc__)
        return 1
    with contextlib.redirect_stdout(io.StringIO()):
        cases = {c["rule_id"]: c for c in load_cases(REPO / "eval/manifest.jsonl", REPO, 2000)}
    url_map = load_github_manifest(REPO / "eval/github_manifest.jsonl")
    texts = {}
    for path in argv[1:]:
        rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
        for row in rows:
            rid = row.get("rule_id")
            if rid in cases and rid not in texts:
                texts[rid] = _case_text(cases[rid], url_map)
        c = run_counts(rows, texts)
        n = c["signatures"] or 1
        parts = ", ".join(f"{s} {c['status'][s]} ({c['status'][s] / n:.0%}; used by a rule {c['used'][s]})"
                          for s in STATUSES)
        print(f"{Path(path).stem:22} {c['cases']} cases, {c['signatures']} signatures: {parts}; inferred_from_class "
              f"{c['inferred_from_class']}; not in the report and not marked inferred {c['not_in_report_not_inferred']} "
              f"(used {c['not_in_report_not_inferred_used']})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
