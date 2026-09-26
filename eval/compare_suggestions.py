#!/usr/bin/env python3
"""Plan 2.6's measures (Change 28), fixed before its run: the analysis stage's top
log-source suggestion against the gold rule, paired between two runs, over ALL rows.

The gold log source comes from eval/manifest.jsonl, so a case counts whether or not its
first rule parses. (The diagnosis tool's web-label counts are taken over parsed first
rules only, so their denominators differ between runs — log, 2026-09-26 correction.)
A case whose analysis gave no suggestion counts as a miss and as off the table.

- exact        top suggestion = gold log source: category, product and service, absent
               matching absent (S3's rule, `eval.scorers.score_logsource`); placeholders
               such as '-' count as absent. PRIMARY — exact McNemar, paired.
- on_table     top suggestion is a log source SigmaHQ's main rule set uses, in one of
               Sigma's two forms (`sigma_logsource.on_table`, the committed table).
- no_category  top suggestion has no category (the product + service form).
- by gold form exact on gold rules defined by a service (no category), on web gold
               (webserver/proxy), and on the other category gold.

Usage:
    .venv/bin/python eval/compare_suggestions.py A.jsonl B.jsonl
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from backend.pipeline.sigma_logsource import _clean, load_logsource_table, on_table  # noqa: E402
from eval.compare_runs import mcnemar  # noqa: E402
from eval.scorers import score_logsource  # noqa: E402

FIELDS = ("category", "product", "service")
WEB = {"webserver", "proxy"}
FORMS = ("service", "web", "category")


def load_gold(manifest: Path) -> dict:
    rows = (json.loads(l) for l in Path(manifest).read_text(encoding="utf-8").splitlines() if l.strip())
    return {r["rule_id"]: r.get("logsource") or {} for r in rows}


def top_suggestion(row: dict) -> Optional[dict]:
    suggestions = (row.get("pipeline") or {}).get("logsource_suggestions") or []
    return next((s for s in suggestions if isinstance(s, dict)), None)


def gold_form(gold: dict) -> str:
    category = _clean(gold.get("category"))
    if category is None:
        return "service"
    return "web" if category in WEB else "category"


def suggestion_measures(row: dict, gold: dict, table: dict) -> dict:
    top = top_suggestion(row)
    if top is None:
        return {"has_suggestion": False, "exact": False, "on_table": False, "no_category": False}
    cleaned = {f: _clean(top.get(f)) for f in FIELDS}
    return {
        "has_suggestion": True,
        "exact": score_logsource(cleaned, gold)["exact_match"],
        "on_table": on_table(top, table),
        "no_category": cleaned["category"] is None,
    }


def compare(rows_a: list, rows_b: list, gold: dict, table: dict) -> dict:
    a = {r["rule_id"]: r for r in rows_a}
    b = {r["rule_id"]: r for r in rows_b}
    ids = sorted(set(a) & set(b) & set(gold))
    ma = {i: suggestion_measures(a[i], gold[i], table) for i in ids}
    mb = {i: suggestion_measures(b[i], gold[i], table) for i in ids}
    count = lambda m, key, sub=ids: sum(1 for i in sub if m[i][key])
    by_form = {}
    for form in FORMS:
        sub = [i for i in ids if gold_form(gold[i]) == form]
        by_form[form] = {"n": len(sub), "a": count(ma, "exact", sub), "b": count(mb, "exact", sub)}
    return {
        "n": len(ids),
        "exact": mcnemar([(ma[i]["exact"], mb[i]["exact"]) for i in ids]),
        "on_table": mcnemar([(ma[i]["on_table"], mb[i]["on_table"]) for i in ids]),
        "no_category": {"a": count(ma, "no_category"), "b": count(mb, "no_category")},
        "no_suggestion": {"a": len(ids) - count(ma, "has_suggestion"),
                          "b": len(ids) - count(mb, "has_suggestion")},
        "by_gold_form": by_form,
        "changed": [(i, ma[i]["exact"], mb[i]["exact"]) for i in ids if ma[i]["exact"] != mb[i]["exact"]],
    }


def _load(path: str) -> list:
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]


def main(argv: list) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 1
    rows_a, rows_b = _load(argv[1]), _load(argv[2])
    r = compare(rows_a, rows_b, load_gold(REPO / "eval/manifest.jsonl"), load_logsource_table())
    print(f"A: {argv[1]} ({len(rows_a)} rows)\nB: {argv[2]} ({len(rows_b)} rows)")
    print(f"matched cases: {r['n']} (every row counts, whether or not its first rule parses)\n")
    print(f"{'top suggestion (analysis stage)':34} {'A':>5} {'B':>5}  test")
    for key, label in (("exact", "= gold log source  [PRIMARY]"), ("on_table", "on the table")):
        m = r[key]
        print(f"  {label:32} {m['a_true']:5} {m['b_true']:5}  {m['only_a']} only A, "
              f"{m['only_b']} only B; exact McNemar p = {m['p']:.3f}")
    print(f"  {'without a category':32} {r['no_category']['a']:5} {r['no_category']['b']:5}")
    print(f"  {'no suggestion at all':32} {r['no_suggestion']['a']:5} {r['no_suggestion']['b']:5}")
    print("  = gold, by the gold rule's form:")
    for form, label in (("service", "defined by a service"), ("web", "web (webserver/proxy)"),
                        ("category", "other category")):
        f = r["by_gold_form"][form]
        name = f"{label} (n={f['n']})"
        print(f"    {name:30} {f['a']:5} {f['b']:5}")
    if r["changed"]:
        print("  changed cases (A -> B): " + ", ".join(f"{i[:8]} {x}->{y}" for i, x, y in r["changed"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
