#!/usr/bin/env python3
"""The evaluation's scope: Windows and Linux attacks only (user decision, log 2026-10-19).

A case is **in scope** when its expert (gold) rule's log source names `product: windows` or `product: linux` - the
manifest's log source, which `load_cases` copies into every case and every result row. Out: web (`category:
webserver` / `proxy`, no product) and every other source (network, firewall, cloud, identity, macOS, ...). The
assistant itself is unchanged; only what is scored changes. Earlier results stay as reported; re-scoring a run made
before this decision on the scope is post-hoc and is labelled so.

`null_baselines` measures chance on a set of gold rules: every rule scored against every *other* rule of the set
(all ordered pairs - the exact mean of Change 4's "a different random gold rule" control, with no seed). This module's
summary prints the counts by set and the baselines for the whole corpus and for the scope; the scope's baselines are
copied into `summarise.py` (`SCOPE_NULL_BASELINES`) from this output.

Usage:
    .venv/bin/python eval/scope.py
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.scorers import score_attack_tags, score_detection_fields, score_logsource  # noqa: E402

SCOPES = {"windows-linux": frozenset({"windows", "linux"})}


def in_scope(row: dict, scope: str) -> bool:
    products = SCOPES[scope]
    return str(row.get("product") or "").strip().lower() in products


def keep(rows, scope):
    """The rows in scope: a list of rows, or {rule_id: row}. No scope -> the rows unchanged."""
    if scope is None:
        return rows
    if isinstance(rows, dict):
        return {rid: row for rid, row in rows.items() if in_scope(row, scope)}
    return [row for row in rows if in_scope(row, scope)]


def _mean(values: list):
    return sum(values) / len(values) if values else None


def null_baselines(golds: list) -> dict:
    """Chance on these gold rules: each scored against every other one (ordered pairs i != j). An F1 that is
    undefined for a pair (a rule with no technique, no detection field) is left out, as the scorers' summaries do."""
    if len(golds) < 2:
        raise ValueError("null baselines need at least two gold rules")
    logsource, attack, detection = [], [], []
    for i, gold in enumerate(golds):
        for j, other in enumerate(golds):
            if i == j:
                continue
            logsource.append(1.0 if score_logsource(other.get("logsource"), gold.get("logsource"))["exact_match"]
                             else 0.0)
            f1 = score_attack_tags(other.get("tags"), gold.get("tags"))["exact"]["f1"]
            if f1 is not None:
                attack.append(f1)
            f1 = score_detection_fields(other.get("detection"), gold.get("detection"))["f1"]
            if f1 is not None:
                detection.append(f1)
    return {"logsource_exact": _mean(logsource), "n_pairs": len(logsource),
            "attack_f1": _mean(attack), "n_attack": len(attack),
            "detection_f1": _mean(detection), "n_detection": len(detection)}


def _group(case: dict) -> str:
    if in_scope(case, "windows-linux"):
        return str(case["product"]).lower()
    return "web" if str(case.get("category") or "").lower() in ("webserver", "proxy") else "other"


def main() -> int:
    from eval.draw_heldout import used_rule_ids
    from eval.run_eval import load_cases, stratified_sample

    with contextlib.redirect_stdout(io.StringIO()):
        cases = load_cases(REPO / "eval/manifest.jsonl", REPO, 2000)
        tuning = {c["rule_id"] for c in stratified_sample(cases, 60, 0)}
    sets = {"tuning (seed 0)": tuning}
    for name in ("manifest_heldout", "manifest_confirm2", "manifest_confirm3"):
        path = REPO / f"eval/{name}.jsonl"
        sets[name] = {json.loads(line)["rule_id"] for line in path.read_text(encoding="utf-8").splitlines()
                      if line.strip()}
    used = used_rule_ids(REPO / "eval/results")
    sets["never run (in no result file)"] = {c["rule_id"] for c in cases} - used

    group = {c["rule_id"]: _group(c) for c in cases}
    print(f"corpus: {len(cases)} cases; {dict(Counter(group.values()).most_common())}")
    for name, ids in sets.items():
        counts = Counter(group[i] for i in ids if i in group)
        n_in = counts["windows"] + counts["linux"]
        print(f"  {name}: {len(ids & set(group))} -> in scope {n_in} (windows {counts['windows']}, linux "
              f"{counts['linux']}); out: web {counts['web']}, other {counts['other']}")
    scoped = keep(cases, "windows-linux")
    for label, subset in (("whole corpus", cases), ("scope windows-linux", scoped)):
        b = null_baselines([c["gold"] for c in subset])
        print(f"null baselines, {label} ({len(subset)} gold rules, {b['n_pairs']} ordered pairs): "
              f"logsource_exact {b['logsource_exact']:.3f}; attack_f1 {b['attack_f1']:.3f} (n {b['n_attack']}); "
              f"detection_f1 {b['detection_f1']:.3f} (n {b['n_detection']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
