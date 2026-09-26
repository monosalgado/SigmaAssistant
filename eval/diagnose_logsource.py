#!/usr/bin/env python3
"""Where does the log source go wrong? (plan task 2.1; offline, no LLM)

Follows the log-source *category* of every case through the pipeline, from a
result file whose rows carry the stages' intermediate results (`row["pipeline"]`,
baseline v2 onward):

    attack-vector telemetry  ->  analysis suggestions  ->  generated rule   vs   gold

Definitions — fixed on 2026-09-24 before any bucket count was computed. Seen
first, and the reason `category` is the compared field: in baseline v2 the rule's
category matches gold in 16 of 57 scored cases, the product in 26, and a wrong
`service` alone explains 1.

- Population: the rows S3 scores (a logsource score exists; the first rule parses).
- Rule and gold category: read from the row's S3 score, so this diagnosis and S3
  cannot disagree. Compared with the scorer's normalisation (`eval.scorers._norm`):
  case and surrounding space ignored; an absent category matches only an absent one.
- Top suggestion: the FIRST entry of the analysis stage's `logsource_suggestions`
  (the order the generation prompt lists them). Offered: the first three — all the
  generation prompt shows (`stage_generate.py`).
- Buckets, each case in exactly one:
    right_suggested  rule right, top suggestion right
    right_rescued    rule right, top suggestion wrong
    overridden       rule wrong, top suggestion right            (defect 11)
    ranked_low       rule wrong, gold offered as suggestion 2 or 3
    followed_wrong   rule wrong, gold not offered, rule = top suggestion
    wrong_elsewhere  rule wrong, gold not offered, rule differs from the top suggestion
- Secondary, web vs not web: a web category is `webserver` or `proxy`; web
  attack-vector telemetry is `webserver_access_log`, `web_proxy` or `waf`. Counts how
  often each stage says "web" when the gold rule is not a web rule (plan 2.3).
- Secondary: whether ANY rule of the response has the gold category, not only the
  first one that S3 scores.

POST-HOC measures, added after the first run, when the confusion list showed rule
categories such as `webserver_access_log` — the attack-vector stage's own label,
which no SigmaHQ rule uses. Reported separately from the buckets above:
- the rule's category is the attack-vector stage's telemetry label, verbatim;
- the rule's category is used by no rule in the local SigmaHQ corpus (`data/sigma`);
- S3 if the rule had used the analysis stage's top suggestion verbatim (category,
  product and service, scored by `eval.scorers.score_logsource`).

Usage:
    .venv/bin/python eval/diagnose_logsource.py eval/results/baseline60_v2.jsonl
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.scorers import _norm, score_logsource, strip_code_fences  # noqa: E402

BUCKETS = ("right_suggested", "right_rescued", "overridden",
           "ranked_low", "followed_wrong", "wrong_elsewhere")
OFFERED = 3  # suggestions the generation prompt shows
WEB_CATEGORIES = {"webserver", "proxy"}
WEB_TELEMETRY = {"webserver_access_log", "web_proxy", "waf"}


def bucket(gold: Optional[str], rule: Optional[str], suggestions: list) -> str:
    gold, rule = _norm(gold), _norm(rule)
    offered = [_norm(s) for s in suggestions[:OFFERED]]
    top = offered[0] if offered else None
    top_right = bool(offered) and top == gold
    if rule == gold:
        return "right_suggested" if top_right else "right_rescued"
    if top_right:
        return "overridden"
    if gold in offered[1:]:
        return "ranked_low"
    if offered and rule == top:
        return "followed_wrong"
    return "wrong_elsewhere"


def is_web_category(category: Optional[str]) -> bool:
    return _norm(category) in WEB_CATEGORIES


def is_web_telemetry(telemetry: Optional[str]) -> bool:
    return _norm(telemetry) in WEB_TELEMETRY


def gold_in_any_rule(gold: Optional[str], rules_yaml: list) -> bool:
    gold = _norm(gold)
    for text in rules_yaml or []:
        try:
            rule = yaml.safe_load(strip_code_fences(text))
        except yaml.YAMLError:
            continue
        if isinstance(rule, dict) and isinstance(rule.get("logsource"), dict):
            if _norm(rule["logsource"].get("category")) == gold:
                return True
    return False


def corpus_categories(root: Path) -> set:
    """Every logsource category used by at least one rule under `root` (post-hoc)."""
    found = set()
    for path in Path(root).rglob("*.yml"):
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError):
            continue
        if isinstance(rule, dict) and isinstance(rule.get("logsource"), dict):
            category = _norm(rule["logsource"].get("category"))
            if category:
                found.add(category)
    return found


def per_field_counts(rows: list) -> dict:
    """How often each S3 field matches — the reason `category` is the compared field."""
    scored = [r["scores"]["logsource"]["per_field"] for r in rows
              if (r.get("scores") or {}).get("logsource")]
    counts = {"n": len(scored)}
    for field in ("category", "product", "service"):
        counts[field] = sum(1 for pf in scored if pf[field]["match"])
    counts["only_service_wrong"] = sum(
        1 for pf in scored
        if pf["category"]["match"] and pf["product"]["match"] and not pf["service"]["match"])
    return counts


def top_category_and_product_right(row: dict) -> Optional[bool]:
    """Do the top suggestion's category AND product agree with gold? (post-hoc)"""
    suggestions = (row.get("pipeline") or {}).get("logsource_suggestions") or []
    if not suggestions:
        return None
    per_field = row["scores"]["logsource"]["per_field"]
    return all(_norm(suggestions[0].get(f)) == _norm((per_field.get(f) or {}).get("gold"))
               for f in ("category", "product"))


def top_service_right(row: dict) -> Optional[bool]:
    """Change 25's measure (fixed before its run): the top suggestion's service equals
    the gold rule's, absent matching absent as in S3."""
    suggestions = (row.get("pipeline") or {}).get("logsource_suggestions") or []
    if not suggestions:
        return None
    gold = (row["scores"]["logsource"]["per_field"].get("service") or {}).get("gold")
    service = _norm(suggestions[0].get("service"))
    return (None if service in ("-", "none", "n/a", "null") else service) == _norm(gold)


def first_rule_follows_top(row: dict) -> Optional[bool]:
    """Change 26's measure (fixed before its run): the first rule's log source equals
    the analysis stage's top suggestion - category, product and service, absent
    matching absent, placeholders ('-', 'none'…) counted as absent."""
    suggestions = (row.get("pipeline") or {}).get("logsource_suggestions") or []
    if not suggestions:
        return None
    clean = lambda v: None if _norm(v) in (None, "-", "none", "n/a", "null") else _norm(v)
    per_field = row["scores"]["logsource"]["per_field"]
    return all(clean((per_field.get(f) or {}).get("predicted")) == clean(suggestions[0].get(f))
               for f in ("category", "product", "service"))


def first_rule_adds_to_top(row: dict) -> Optional[set]:
    """Change 29's measure (fixed before its run): the fields ('product', 'service') a
    first rule adds to the analysis stage's top suggestion while keeping its category.
    None when not applicable: no scored first rule, no suggestion, or another category.
    Placeholders ('-', 'none'…) count as absent."""
    logsource = (row.get("scores") or {}).get("logsource")
    suggestions = (row.get("pipeline") or {}).get("logsource_suggestions") or []
    if not logsource or not suggestions or not isinstance(suggestions[0], dict):
        return None
    clean = lambda v: None if _norm(v) in (None, "-", "none", "n/a", "null") else _norm(v)
    fields = ("category", "product", "service")
    rule = {f: clean((logsource["per_field"].get(f) or {}).get("predicted")) for f in fields}
    top = {f: clean(suggestions[0].get(f)) for f in fields}
    if rule["category"] != top["category"]:
        return None
    return {f for f in ("product", "service") if rule[f] is not None and top[f] is None}


def top_suggestion_exact(row: dict) -> Optional[bool]:
    """S3 had the rule used the analysis stage's top suggestion verbatim (post-hoc)."""
    suggestions = (row.get("pipeline") or {}).get("logsource_suggestions") or []
    if not suggestions:
        return None
    per_field = row["scores"]["logsource"]["per_field"]
    gold = {f: (per_field.get(f) or {}).get("gold") for f in ("category", "product", "service")}
    top = {f: suggestions[0].get(f) for f in ("category", "product", "service")}
    return score_logsource(top, gold)["exact_match"]


def diagnose_case(row: dict) -> Optional[dict]:
    logsource = (row.get("scores") or {}).get("logsource")
    if not logsource:
        return None
    category = logsource["per_field"]["category"]
    pipeline = row.get("pipeline") or {}
    suggestions = [s.get("category") for s in pipeline.get("logsource_suggestions") or []]
    telemetry = (pipeline.get("attack_vector") or {}).get("primary_telemetry")
    gold, rule = category["gold"], category["predicted"]
    return {
        "rule_id": row["rule_id"],
        "gold": _norm(gold),
        "rule": _norm(rule),
        "top": _norm(suggestions[0]) if suggestions else None,
        "offered": [_norm(s) for s in suggestions[:OFFERED]],
        "telemetry": _norm(telemetry),
        "bucket": bucket(gold, rule, suggestions),
        "gold_web": is_web_category(gold),
        "telemetry_web": is_web_telemetry(telemetry),
        "top_web": is_web_category(suggestions[0]) if suggestions else False,
        "rule_web": is_web_category(rule),
        "gold_in_any_rule": gold_in_any_rule(gold, row.get("rules_yaml")),
        # post-hoc
        "rule_is_telemetry_label": _norm(rule) is not None and _norm(rule) == _norm(telemetry),
        "top_exact": top_suggestion_exact(row),
    }


def summarise(diagnoses: list, known_categories: Optional[set] = None) -> dict:
    ds = [d for d in diagnoses if d is not None]
    non_web = [d for d in ds if not d["gold_web"]]
    wrong = [d for d in ds if d["rule"] != d["gold"]]
    post_hoc = {
        "wrong": len(wrong),
        "wrong_rule_is_telemetry_label": sum(d["rule_is_telemetry_label"] for d in wrong),
        "overridden_rule_is_telemetry_label": sum(d["rule_is_telemetry_label"] for d in wrong
                                                  if d["bucket"] == "overridden"),
        "wrong_rule_category_unknown": (None if known_categories is None else
                                        sum(1 for d in wrong if d["rule"] is not None
                                            and d["rule"] not in known_categories)),
        "top_exact": sum(1 for d in ds if d.get("top_exact")),
    }
    return {
        **post_hoc,
        "n": len(ds),
        "buckets": {b: sum(1 for d in ds if d["bucket"] == b) for b in BUCKETS},
        "no_gold_category": {b: sum(1 for d in ds if d["bucket"] == b and d["gold"] is None)
                             for b in BUCKETS},
        "non_web_gold": len(non_web),
        "web_telemetry_on_non_web_gold": sum(d["telemetry_web"] for d in non_web),
        "web_top_on_non_web_gold": sum(d["top_web"] for d in non_web),
        "web_rule_on_non_web_gold": sum(d["rule_web"] for d in non_web),
        "rule_right": sum(1 for d in ds if d["rule"] == d["gold"]),
        "gold_in_any_rule": sum(d["gold_in_any_rule"] for d in ds),
    }


def main(argv: list) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 1
    rows = [json.loads(line) for line in Path(argv[1]).read_text(encoding="utf-8").splitlines()
            if line.strip()]
    ds = [d for d in (diagnose_case(r) for r in rows) if d is not None]
    corpus = REPO / "data/sigma"
    known = corpus_categories(corpus) if corpus.is_dir() else None
    s = summarise(ds, known)
    n = s["n"]
    print(f"{argv[1]}: {len(rows)} rows, {n} scored by S3 (first rule parses)\n")
    pf = per_field_counts(rows)
    print(f"S3 per field (rule vs gold): category {pf['category']} / {pf['n']}, product "
          f"{pf['product']} / {pf['n']}, service {pf['service']} / {pf['n']}; "
          f"only the service wrong: {pf['only_service_wrong']}\n")
    if not any(r.get("pipeline") for r in rows):
        print("No row carries the stages' results (`pipeline`, baseline v2 onward): "
              "per-field counts only.")
        return 0
    print("Where the category goes wrong (each case in one bucket):")
    for b in BUCKETS:
        extra = f"   ({s['no_gold_category'][b]} with no gold category)" if s["no_gold_category"][b] else ""
        print(f"  {b:16} {s['buckets'][b]:3} / {n}{extra}")
    print(f"\n  rule category right: {s['rule_right']} / {n};"
          f" gold category in ANY rule of the response: {s['gold_in_any_rule']} / {n}")
    print(f"\nWeb labels when the gold rule is not a web rule ({s['non_web_gold']} cases):")
    print(f"  attack-vector telemetry web : {s['web_telemetry_on_non_web_gold']}")
    print(f"  analysis top suggestion web : {s['web_top_on_non_web_gold']}")
    print(f"  generated rule web          : {s['web_rule_on_non_web_gold']}")
    print("\nConfusions (gold -> top suggestion -> rule), wrong rules only:")
    for (g, t, r), c in Counter((d["gold"], d["top"], d["rule"]) for d in ds
                                if d["rule"] != d["gold"]).most_common():
        print(f"  {c:2}  {g} -> {t} -> {r}")

    print(f"\nPOST-HOC (added after the first run; not pre-registered). Wrong rules: {s['wrong']}")
    print(f"  category = attack-vector telemetry label, verbatim : {s['wrong_rule_is_telemetry_label']}"
          f"  (of the {s['buckets']['overridden']} overridden: {s['overridden_rule_is_telemetry_label']})")
    if known is None:
        print("  category used by no SigmaHQ rule                  : n/a (data/sigma not found)")
    else:
        unknown = Counter(d["rule"] for d in ds if d["rule"] != d["gold"]
                          and d["rule"] is not None and d["rule"] not in known)
        print(f"  category used by no SigmaHQ rule                  : {s['wrong_rule_category_unknown']}"
              f"  {dict(unknown)}  ({len(known)} categories in the corpus)")
    print(f"  S3 had the rule used the top suggestion verbatim  : {s['top_exact']} / {n}"
          f"  (top suggestion's service: {dict(Counter(_top_service(r) for r in rows if diagnose_case(r)))})")
    cp = sum(1 for r in rows if diagnose_case(r) and top_category_and_product_right(r))
    print(f"  top suggestion's category AND product right       : {cp} / {n}")
    sv = sum(1 for r in rows if diagnose_case(r) and top_service_right(r))
    print(f"\nChange 25 measure: top suggestion's service = gold's  : {sv} / {n}")
    fr = sum(1 for r in rows if diagnose_case(r) and first_rule_follows_top(r))
    print(f"Change 26 measure: first rule = top suggestion       : {fr} / {n}")
    added = [first_rule_adds_to_top(r) for r in rows]
    same = [a for a in added if a is not None]
    print(f"Change 29 measure: first rules on the suggested category: {len(same)}; they add "
          f"a product: {sum('product' in a for a in same)}, a service: {sum('service' in a for a in same)}, "
          f"either: {sum(bool(a) for a in same)}")
    return 0


def _top_service(row: dict) -> Optional[str]:
    suggestions = (row.get("pipeline") or {}).get("logsource_suggestions") or []
    return _norm(suggestions[0].get("service")) if suggestions else None


if __name__ == "__main__":
    sys.exit(main(sys.argv))
