#!/usr/bin/env python3
"""The mechanisms of Changes 57, 59, 60 and 61, read from two arms' rows (plan in the log, 2026-11-10: "towards one";
built before the session's rows were read).

B is the arm with the changes, A the arm without; paired measures are B minus A on the cases both arms have, with a
bootstrap 95% CI (`compare_runs.continuous`: 10,000 resamples, seed 0). Counts are over those paired cases.

  Change 57  cases regenerated (the rule writer ran more than once) and, where the row records it, why; patterns
             holding a backslash that the coverage check checked, those it found, and those it reported missed
             although a final rule's detection holds them (compared with backslashes removed on both sides, as
             `rule_health` compares); attack-vector answers: ok, salvaged (Change 57's part c), failed (empty vector)
  Change 59  rules per case, paired
  Change 60  review's answer tokens per case, paired (every review call of the case); rules put back by Change 55's
             check; rules review returned against the rules it was given (where the row records it)
  Change 61  attack-vector and analysis prompt tokens per case, paired (reported, not gated)
  Also       seconds per case, paired

Read elsewhere: Change 57's "do not use" hits outside a detection and Change 59's patterns from the four places with
no Windows/Linux field come from `eval/rule_health.py`; the gate from `eval/compare_arms.py` and
`eval/footprint_measures.py`. A case regenerated holds the coverage check of its last answer, so "missed although a
final rule holds them" compares that check with the final rules (after review).

Usage:
    .venv/bin/python eval/change_measures.py --a A.jsonl --b B.jsonl --scope windows-linux [--out summary.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Callable, Optional

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.compare_runs import continuous, load  # noqa: E402
from eval.rule_health import _pairs, _simplified, read_rule  # noqa: E402
from eval.scope import SCOPES, in_scope  # noqa: E402


# --- per case -------------------------------------------------------------------------------------------------------

def stage_tokens(row: dict, stage: str, kind: str) -> Optional[int]:
    """The `kind` tokens (`prompt_tokens` or `completion_tokens`) of every call of `stage` in the case; 0 when the
    step was not called, None when a call of it has no token count."""
    total = 0
    for call in row.get("llm_calls") or []:
        if call.get("stage") != stage:
            continue
        if call.get(kind) is None:
            return None
        total += call[kind]
    return total


def rules_put_back(row: dict) -> int:
    return len((row.get("pipeline") or {}).get("review_reverted") or [])


def regeneration(row: dict) -> dict:
    calls = sum(1 for c in row.get("llm_calls") or [] if c.get("stage") == "generation")
    if calls <= 1:
        return {"regenerated": False, "reason": None}
    reason = (row.get("pipeline") or {}).get("regeneration_reason")
    if not reason:
        return {"regenerated": True, "reason": "not recorded"}
    triggers = reason.get("triggers") or []
    return {"regenerated": True, "reason": reason.get("kind", "?") + (f": {', '.join(triggers)}" if triggers else "")}


def backslash_patterns(row: dict) -> dict:
    pipeline = row.get("pipeline") or {}
    check = pipeline.get("coverage_check") or {}
    covered = [p for p in check.get("payload_signatures_covered") or [] if "\\" in str(p)]
    missed = [p for p in check.get("payload_signatures_missed") or [] if "\\" in str(p)]
    values = [value.lower().replace("\\", "") for text in row.get("rules_yaml") or []
              for rule in [read_rule(text)] if rule for _, value in _pairs(rule)]
    in_a_rule = sum(1 for p in missed if _simplified(p) and any(_simplified(p) in v for v in values))
    return {"checked": len(covered) + len(missed), "found": len(covered), "missed_but_in_a_rule": in_a_rule}


def attack_vector_answer(row: dict) -> str:
    vector = (row.get("pipeline") or {}).get("attack_vector") or {}
    if str(vector.get("reasoning") or "").startswith("Extraction failed"):
        return "failed"
    return "salvaged" if vector.get("salvaged") else "ok"


def review_returned(row: dict) -> Optional[dict]:
    pipeline = row.get("pipeline") or {}
    returned = pipeline.get("review_returned")
    if returned is None:
        return None
    return {"returned": len(returned.get("rules") or []), "reviewed": len(pipeline.get("pre_review_rules") or []),
            "readable": bool(returned.get("readable"))}


# --- two arms -------------------------------------------------------------------------------------------------------

def paired(a: dict, b: dict, value: Callable[[dict], Optional[float]]) -> dict:
    """B minus A on the cases both arms have; a case whose value is unknown in either arm is left out and counted."""
    pairs, unknown = [], 0
    for rid in sorted(set(a) & set(b)):
        x, y = value(a[rid]), value(b[rid])
        if x is None or y is None:
            unknown += 1
            continue
        pairs.append((x, y))
    out = continuous(pairs)
    out.update({"unknown": unknown, "only_in_a": len(set(a) - set(b)), "only_in_b": len(set(b) - set(a))})
    return out


def measures(a: dict, b: dict, scope: Optional[str] = None) -> dict:
    if scope:
        a = {rid: r for rid, r in a.items() if in_scope(r, scope)}
        b = {rid: r for rid, r in b.items() if in_scope(r, scope)}
    common = sorted(set(a) & set(b))
    arms = {"a": [a[rid] for rid in common], "b": [b[rid] for rid in common]}

    def each(count):
        return {name: count(rows) for name, rows in arms.items()}

    def regenerated(rows):
        found = [regeneration(r) for r in rows]
        return {"cases": sum(f["regenerated"] for f in found),
                "reasons": dict(Counter(f["reason"] for f in found if f["regenerated"]))}

    def backslashes(rows):
        found = [backslash_patterns(r) for r in rows]
        return {key: sum(f[key] for f in found) for key in ("checked", "found", "missed_but_in_a_rule")}

    def answers(rows):
        found = Counter(attack_vector_answer(r) for r in rows)
        return {key: found.get(key, 0) for key in ("ok", "salvaged", "failed")}

    def put_back(rows):
        counts = [rules_put_back(r) for r in rows]
        return {"rules": sum(counts), "cases": sum(1 for c in counts if c)}

    def returned(rows):
        found = [f for f in (review_returned(r) for r in rows) if f is not None]
        return {"returned": sum(f["returned"] for f in found), "reviewed": sum(f["reviewed"] for f in found),
                "cases": len(found), "unreadable": sum(1 for f in found if not f["readable"])}

    return {
        "cases": {"a": len(a), "b": len(b), "paired": len(common)},
        "change57": {"regenerated": each(regenerated), "backslash_patterns": each(backslashes),
                     "attack_vector_answers": each(answers)},
        "change59": {"rules_per_case": paired(a, b, lambda r: r.get("n_rules"))},
        "change60": {"review_answer_tokens": paired(a, b, lambda r: stage_tokens(r, "review", "completion_tokens")),
                     "rules_put_back": each(put_back), "review_returned": each(returned)},
        "change61": {
            "attack_vector_prompt_tokens": paired(a, b, lambda r: stage_tokens(r, "attack_vector", "prompt_tokens")),
            "analysis_prompt_tokens": paired(a, b, lambda r: stage_tokens(r, "analysis", "prompt_tokens"))},
        "seconds_per_case": paired(a, b, lambda r: r.get("elapsed_s")),
    }


# --- report ---------------------------------------------------------------------------------------------------------

def _paired_line(name: str, p: dict) -> str:
    if not p["n"]:
        return f"  {name}: no paired case"
    lo, hi = p["ci"]
    return (f"  {name}: A {p['mean_a']:,.1f}  B {p['mean_b']:,.1f}  B-A {p['diff']:+,.1f}  CI [{lo:+,.1f}, {hi:+,.1f}]"
            f"  (n {p['n']}; B higher {p['better']}, lower {p['worse']}, same {p['same']}"
            + (f"; unknown {p['unknown']}" if p["unknown"] else "") + ")")


def print_report(m: dict) -> None:
    c = m["cases"]
    print(f"cases: A {c['a']}, B {c['b']}, paired {c['paired']}")
    print("Change 57")
    for arm in ("a", "b"):
        r, s, v = (m["change57"][k][arm] for k in ("regenerated", "backslash_patterns", "attack_vector_answers"))
        print(f"  {arm.upper()}: regenerated {r['cases']} {r['reasons'] or ''}; backslash patterns checked "
              f"{s['checked']}, found {s['found']}, missed although a final rule holds them "
              f"{s['missed_but_in_a_rule']}; attack-vector answers {v}")
    print("Change 59")
    print(_paired_line("rules per case", m["change59"]["rules_per_case"]))
    print("Change 60")
    print(_paired_line("review answer tokens per case", m["change60"]["review_answer_tokens"]))
    for arm in ("a", "b"):
        pb, rr = m["change60"]["rules_put_back"][arm], m["change60"]["review_returned"][arm]
        print(f"  {arm.upper()}: rules put back {pb['rules']} in {pb['cases']} cases; review returned "
              f"{rr['returned']} of {rr['reviewed']} rules ({rr['cases']} cases recorded, {rr['unreadable']} "
              f"unreadable)")
    print("Change 61 (reported)")
    print(_paired_line("attack-vector prompt tokens", m["change61"]["attack_vector_prompt_tokens"]))
    print(_paired_line("analysis prompt tokens", m["change61"]["analysis_prompt_tokens"]))
    print("Also")
    print(_paired_line("seconds per case", m["seconds_per_case"]))


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--a", required=True, type=Path, help="the arm without the changes")
    parser.add_argument("--b", required=True, type=Path, help="the arm with the changes")
    parser.add_argument("--scope", choices=sorted(SCOPES), default=None)
    parser.add_argument("--out", type=Path, default=None, help="write the reading as JSON")
    args = parser.parse_args(argv)
    m = measures(load(args.a), load(args.b), scope=args.scope)
    print_report(m)
    if args.out:
        args.out.write_text(json.dumps(m, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
