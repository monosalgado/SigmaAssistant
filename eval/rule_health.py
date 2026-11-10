#!/usr/bin/env python3
"""Rule health: properties of every delivered rule that need no expert rule (definitions fixed in the log,
2026-11-09 evening, before this tool existed).

Every other score compares the first rule with one expert rule, or checks that it loads and runs. This reads all the
rules a run delivered and says, without an expert rule:

Per rule
  1. runs                 it loads and its condition parses (`runnable_rules.can_run`)
  2. log source known     SigmaHQ's rules use that category, or, without a category, that product and service
  3. unused fields        detection fields no SigmaHQ rule uses with that log source (modifiers removed, exclusions
                          included, as written); judged only when 2 holds
  4. values in the report of its detection values of 6+ characters (S5v's extraction), those the report's text holds
  5. shape                an exclusion (a `filter...` selection or a `not` in the condition), a parent-process field
                          (a field whose name starts with `Parent`), the level
Per case
  6. rules delivered, tactics the attack-vector step listed, regenerated, coverage warnings left
  7. unlogged patterns    candidate patterns from file content, a network payload, a request or response body or a
                          response header that a rule uses anyway, and the field each lands in
  8. "do not use" hits    the strings the coverage check reported as used: in a detection, or only elsewhere
  9. generic pages        saved pages whose text is also saved for another page; a case whose whole input is such
                          text is a candidate "no report" case (listed for a person to confirm; nothing is excluded)

What it does not say: a field SigmaHQ never uses with a log source is not thereby invalid; a value the report lacks is
not thereby wrong; a rule that passes every item can still miss the attack. No model, no network, no knowledge base.

Usage:
    .venv/bin/python eval/rule_health.py eval/results/RUN.jsonl [more runs] --scope windows-linux [--out summary.json]
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urlparse

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from backend.pipeline.sigma_logsource import _clean, _rules, detection_fields  # noqa: E402
from eval.diagnose_detection import grounded  # noqa: E402
from eval.runnable_rules import can_run  # noqa: E402
from eval.scope import SCOPES, in_scope  # noqa: E402
from eval.scorers import extract_detection_values, strip_code_fences  # noqa: E402

SIGMA_RULE_DIRS = ("rules", "rules-emerging-threats", "rules-threat-hunting", "rules-dfir", "rules-compliance",
                   "rules-placeholder")
# Places a candidate pattern can be seen (`where`) that no Sigma log source in the scope records.
UNLOGGED_PLACES = frozenset({"file_content", "network_payload", "request_body", "response_body", "response_header"})
MIN_VALUE_CHARS = 6
MIN_PATTERN_CHARS = 3
_NOT_A_SELECTION = ("condition", "timeframe")
_NOT_RE = re.compile(r"\bnot\b", re.IGNORECASE)


# --- the reference: which fields SigmaHQ's rules use with each log source -------------------------------------------

def _logsource_key(rule: dict):
    logsource = rule.get("logsource") if isinstance(rule.get("logsource"), dict) else {}
    return _clean(logsource.get("category")), _clean(logsource.get("product")), _clean(logsource.get("service"))


def reference_from_rules(rules: Iterable[dict]) -> dict:
    """{"categories": {category: fields}, "services": {(product, service): fields}}: a category's fields are joined
    over its products; a rule without a category is filed under its product and service."""
    categories, services = defaultdict(set), defaultdict(set)
    for rule in rules:
        category, product, service = _logsource_key(rule)
        fields = detection_fields(rule.get("detection"))
        if category:
            categories[category] |= fields
        else:
            services[(product, service)] |= fields
    return {"categories": dict(categories), "services": dict(services)}


def load_reference(sigma_dir: Path) -> dict:
    return reference_from_rules(rule for name in SIGMA_RULE_DIRS for rule in _rules(Path(sigma_dir) / name))


# --- per rule ------------------------------------------------------------------------------------------------------

def read_rule(text: str) -> Optional[dict]:
    """The rule as a YAML mapping, or None."""
    try:
        rule = yaml.safe_load(strip_code_fences(text or ""))
    except yaml.YAMLError:
        return None
    return rule if isinstance(rule, dict) else None


def _detection(rule: dict) -> dict:
    return rule.get("detection") if isinstance(rule.get("detection"), dict) else {}


def _pairs(rule: dict) -> list:
    """(field without modifiers, value as written) for every value of every selection, exclusions included; a
    keyword has field "(keyword)"."""
    out = []

    def walk(node, field):
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, str(key).split("|")[0].strip())
        elif isinstance(node, list):
            for item in node:
                walk(item, field)
        elif node is not None:
            out.append((field or "(keyword)", str(node)))

    for name, selection in _detection(rule).items():
        if str(name).strip().lower() not in _NOT_A_SELECTION:
            walk(selection, "")
    return out


def rule_health(rule_text: str, reference: dict, report_text: Optional[str] = None) -> dict:
    rule = read_rule(rule_text)
    if rule is None:
        return {"readable": False, "runs": False, "logsource": None, "logsource_known": None, "unused_fields": None,
                "values": 0, "values_in_report": None, "has_exclusion": False, "uses_parent": False, "level": None}
    detection = _detection(rule)
    category, product, service = _logsource_key(rule)
    known = reference["categories"].get(category) if category else reference["services"].get((product, service))
    fields = detection_fields(detection)
    values = [v for _, v in extract_detection_values(detection) if len(v.lstrip("\\/")) >= MIN_VALUE_CHARS]
    condition = detection.get("condition")
    condition = " ".join(str(c) for c in condition) if isinstance(condition, list) else str(condition or "")
    return {
        "readable": True,
        "runs": can_run(rule_text)["runs"],
        "logsource": category or f"{product or '-'}/{service or '-'}",
        "logsource_known": known is not None,
        "unused_fields": None if known is None else sorted(f for f in fields if f not in known),
        "values": len(values),
        "values_in_report": (None if report_text is None
                             else sum(1 for v in values if grounded(v, report_text, MIN_VALUE_CHARS))),
        "has_exclusion": (any(str(name).strip().lower().startswith("filter") for name in detection)
                          or bool(_NOT_RE.search(condition))),
        "uses_parent": any(f.startswith("Parent") for f in fields),
        "level": str(rule["level"]) if rule.get("level") is not None else None,
    }


# --- per case ------------------------------------------------------------------------------------------------------

def _simplified(pattern) -> str:
    """A candidate pattern as the coverage check compares it: lower-cased, regex characters stripped from the ends,
    backslashes removed."""
    return str(pattern or "").lower().strip().strip("^$.*+?").replace("\\", "")


def unlogged_patterns_used(attack_vector: dict, rule_texts: list) -> list:
    """The candidate patterns from places no log records that some rule's detection value contains, each with the
    fields it lands in."""
    pairs = [(field, value.lower().replace("\\", "")) for text in rule_texts or []
             for rule in [read_rule(text)] if rule for field, value in _pairs(rule)]
    used = []
    for signature in (attack_vector or {}).get("payload_signatures") or []:
        if not isinstance(signature, dict) or signature.get("where") not in UNLOGGED_PLACES:
            continue
        pattern = _simplified(signature.get("pattern"))
        if len(pattern) < MIN_PATTERN_CHARS:
            continue
        fields = sorted({field for field, value in pairs if pattern in value})
        if fields:
            used.append({"pattern": signature.get("pattern"), "where": signature.get("where"), "fields": fields})
    return used


def do_not_use_hits(violations: list, rule_texts: list) -> dict:
    """Where each string the coverage check reported as used sits: in a detection, only elsewhere in a rule, or in
    neither (the check reads the rule's text; this reads it as YAML)."""
    detections, texts = [], []
    for text in rule_texts or []:
        texts.append((text or "").lower())
        rule = read_rule(text)
        if rule:
            strings = [s for pair in _pairs(rule) for s in pair]
            detections.append("\n".join(strings).lower() + "\n" + yaml.safe_dump(_detection(rule)).lower())
    out = {"in_detection": [], "elsewhere": [], "not_found": []}
    for violation in violations or []:
        value = str(violation).lower().strip()
        if any(value in d for d in detections):
            out["in_detection"].append(violation)
        elif any(value in t for t in texts):
            out["elsewhere"].append(violation)
        else:
            out["not_found"].append(violation)
    return out


def page_key(url: str) -> tuple:
    """A page by host and path: scheme, `www.`, query, fragment and a trailing slash say nothing about which page."""
    parsed = urlparse(str(url))
    host = parsed.netloc.lower()
    return (host[4:] if host.startswith("www.") else host), parsed.path.rstrip("/")


def generic_pages(pages: dict) -> set:
    """The URLs whose saved text (not empty) is also saved for a different page."""
    by_text = defaultdict(set)
    for url, text in pages.items():
        if (text or "").strip():
            by_text[text].add(url)
    return {url for urls in by_text.values() if len({page_key(u) for u in urls}) >= 2 for url in urls}


def generic_share(case_pages: dict, generic: set) -> Optional[float]:
    """The share of a case's input characters that come from generic pages; None for a case without page text."""
    total = sum(len(text or "") for text in case_pages.values())
    if not total:
        return None
    return sum(len(text or "") for url, text in case_pages.items() if url in generic) / total


def generic_cases(cases: dict, case_pages: dict, generic: set) -> list:
    """The cases with input from generic pages, most generic first, each with the pages concerned - the list a
    person confirms by eye."""
    out = []
    for rule_id, pages in case_pages.items():
        share = generic_share(pages, generic)
        if share:
            out.append({"rule_id": rule_id, "title": (cases.get(rule_id) or {}).get("title"), "share": share,
                        "urls": sorted(url for url in pages if url in generic)})
    return sorted(out, key=lambda c: (-c["share"], str(c["title"])))


def case_health(row: dict, reference: dict, report_text: Optional[str] = None,
                generic: Optional[float] = None) -> dict:
    pipeline = row.get("pipeline") or {}
    vector = pipeline.get("attack_vector") or {}
    coverage = pipeline.get("coverage_check") or {}
    rule_texts = list(row.get("rules_yaml") or [])
    signatures = [s for s in vector.get("payload_signatures") or [] if isinstance(s, dict)]
    return {
        "rule_id": row.get("rule_id"), "title": row.get("title"),
        "rules": [rule_health(text, reference, report_text) for text in rule_texts],
        "n_rules": len(rule_texts),
        "tactics": len(vector.get("kill_chain_stages") or []),
        "regenerated": bool(pipeline.get("generation_retried")),
        "coverage_warnings": len(coverage.get("warnings") or []),
        "patterns": len(signatures),
        "unlogged_patterns": sum(1 for s in signatures if s.get("where") in UNLOGGED_PLACES),
        "unlogged_patterns_used": unlogged_patterns_used(vector, rule_texts),
        "do_not_use_hits": do_not_use_hits(coverage.get("blacklist_violations") or [], rule_texts),
        "generic_share": generic,
    }


def expert_health(rows: list, reference: dict, texts: Optional[dict] = None, root: Path = REPO) -> list:
    """The same per-rule reading of each case's expert rule (the file the row names), for comparison; a row whose
    file is missing is skipped."""
    out = []
    for row in rows:
        path = Path(root) / str(row.get("rule_path") or "")
        if path.is_file():
            out.append(rule_health(path.read_text(encoding="utf-8"), reference,
                                   (texts or {}).get(row.get("rule_id"))))
    return out


# --- per run -------------------------------------------------------------------------------------------------------

def _rates(rules: list) -> dict:
    readable = [r for r in rules if r["readable"]]
    judged = [r for r in readable if r["logsource_known"]]
    with_text = [r for r in rules if r["values_in_report"] is not None]
    return {
        "rules": len(rules),
        "unreadable": len(rules) - len(readable),
        "run": sum(1 for r in rules if r["runs"]),
        "logsource_unknown": sum(1 for r in readable if not r["logsource_known"]),
        "judged_for_fields": len(judged),
        "with_unused_fields": sum(1 for r in judged if r["unused_fields"]),
        "values": sum(r["values"] for r in rules),
        "values_with_report": sum(r["values"] for r in with_text),
        "values_in_report": sum(r["values_in_report"] for r in with_text) if with_text else None,
        "with_exclusion": sum(1 for r in rules if r["has_exclusion"]),
        "with_parent_field": sum(1 for r in rules if r["uses_parent"]),
        "levels": dict(Counter(r["level"] for r in readable if r["level"])),
    }


def _spread(numbers: list) -> dict:
    return {"median": statistics.median(numbers) if numbers else None, "max": max(numbers) if numbers else None}


def run_summary(cases: list) -> dict:
    all_rules = [rule for case in cases for rule in case["rules"]]
    hits = Counter()
    for case in cases:
        for place, strings in case["do_not_use_hits"].items():
            hits[place] += len(strings)
    regenerated = [case for case in cases if case["regenerated"]]
    return {
        "cases": len(cases),
        "all_rules": _rates(all_rules),
        "first_rules": _rates([case["rules"][0] for case in cases if case["rules"]]),
        "first_rule_logsources": dict(Counter(case["rules"][0]["logsource"] for case in cases
                                              if case["rules"] and case["rules"][0]["logsource"])),
        "rules_per_case": _spread([case["n_rules"] for case in cases]),
        "tactics_per_case": _spread([case["tactics"] for case in cases]),
        "cases_with_rules_at_least_tactics": sum(1 for case in cases if case["n_rules"] >= case["tactics"]),
        "regenerated": len(regenerated),
        "regenerated_still_warned": sum(1 for case in regenerated if case["coverage_warnings"]),
        "cases_with_coverage_warnings": sum(1 for case in cases if case["coverage_warnings"]),
        "patterns": sum(case["patterns"] for case in cases),
        "unlogged_patterns": sum(case["unlogged_patterns"] for case in cases),
        "unlogged_patterns_used": sum(len(case["unlogged_patterns_used"]) for case in cases),
        "unlogged_landing": dict(Counter(f"{u['where']} -> {field}" for case in cases
                                         for u in case["unlogged_patterns_used"] for field in u["fields"])),
        "do_not_use_hits": {place: hits[place] for place in ("in_detection", "elsewhere", "not_found")},
        "unused_fields": dict(Counter(f"{rule['logsource']}:{field}" for rule in all_rules
                                      for field in rule["unused_fields"] or []).most_common(15)),
        "no_report_candidates": [case["title"] for case in cases if case["generic_share"] == 1.0],
        "partly_generic": sum(1 for case in cases if case["generic_share"] and case["generic_share"] < 1.0),
    }


# --- reading the saved pages ---------------------------------------------------------------------------------------

def load_inputs(manifests: list) -> tuple:
    """({rule_id: case}, {rule_id: {url: page text}}, generic URLs, {url: the page's own title}) for the cases of
    the manifests."""
    from backend.pipeline.stage_preprocess import PreprocessStage
    from eval.run_eval import load_cases, snapshot_key

    extractor, cases, case_pages, by_path, titles = PreprocessStage(client=None, model_name=""), {}, {}, {}, {}
    with contextlib.redirect_stdout(io.StringIO()):
        for manifest in manifests:
            for case in load_cases(Path(manifest), REPO, 2000):
                cases.setdefault(case["rule_id"], case)
        for rule_id, case in cases.items():
            pages = {}
            for url in case["urls"]:
                path = case["url_to_path"].get(snapshot_key(url))
                if path is None:
                    continue
                if path not in by_path:
                    by_path[path] = extractor._extract_page_content(Path(path).read_bytes(), url)
                pages[url], titles[url] = by_path[path]
            case_pages[rule_id] = pages
    generic = generic_pages({url: text for pages in case_pages.values() for url, text in pages.items()})
    return cases, case_pages, generic, titles


def _report_text(case: dict, url_map: dict) -> str:
    from eval.diagnose_detection import _case_text
    with contextlib.redirect_stdout(io.StringIO()):
        return _case_text(case, url_map)


def _ratio(part, whole) -> str:
    return f"{part}/{whole}" + (f" = {part / whole:.2f}" if whole else "")


def print_summary(name: str, s: dict) -> None:
    a, f = s["all_rules"], s["first_rules"]
    print(f"\n{name}: {s['cases']} cases, {a['rules']} rules (per case median {s['rules_per_case']['median']}, max "
          f"{s['rules_per_case']['max']}; tactics listed median {s['tactics_per_case']['median']}, max "
          f"{s['tactics_per_case']['max']}; rules >= tactics in {s['cases_with_rules_at_least_tactics']} cases)")
    print(f"  {'':34}{'all rules':>18}{'first rules':>18}")
    for label, key, whole in (("run", "run", "rules"), ("not readable as YAML", "unreadable", "rules"),
                              ("log source SigmaHQ does not use", "logsource_unknown", "rules"),
                              ("a field SigmaHQ never uses with it", "with_unused_fields", "judged_for_fields"),
                              ("have an exclusion", "with_exclusion", "rules"),
                              ("use a parent-process field", "with_parent_field", "rules")):
        print(f"  {label:34}{_ratio(a[key], a[whole]):>18}{_ratio(f[key], f[whole]):>18}")
    if a["values_in_report"] is not None:
        print(f"  {'values (6+ chars) in the report':34}{_ratio(a['values_in_report'], a['values_with_report']):>18}"
              f"{_ratio(f['values_in_report'], f['values_with_report']):>18}")
    print(f"  levels: all {a['levels']}; first {f['levels']}")
    print(f"  first rule's log source: {dict(sorted(s['first_rule_logsources'].items(), key=lambda kv: -kv[1]))}")
    print(f"  regenerated {s['regenerated']}/{s['cases']} cases, {s['regenerated_still_warned']} of them still with "
          f"coverage warnings; cases ending with coverage warnings {s['cases_with_coverage_warnings']}")
    print(f"  candidate patterns {s['patterns']}; from places no log records {s['unlogged_patterns']}; used anyway "
          f"{s['unlogged_patterns_used']}: {s['unlogged_landing']}")
    hits = s["do_not_use_hits"]
    print(f"  'do not use' hits {sum(hits.values())}: in a detection {hits['in_detection']}, only elsewhere "
          f"{hits['elsewhere']}, not found {hits['not_found']}")
    if s["unused_fields"]:
        print(f"  fields SigmaHQ never uses with the log source: {s['unused_fields']}")
    print(f"  candidate 'no report' cases {len(s['no_report_candidates'])}: {s['no_report_candidates']}; partly "
          f"generic input {s['partly_generic']}")


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results", nargs="+", type=Path)
    parser.add_argument("--scope", choices=sorted(SCOPES), default=None)
    parser.add_argument("--manifest", action="append", type=Path, default=None,
                        help="manifest(s) of the cases, for the report texts and the generic pages "
                             "(default eval/manifest.jsonl)")
    parser.add_argument("--no-pages", action="store_true", help="skip the saved pages (items 4 and 9)")
    parser.add_argument("--list-generic", action="store_true",
                        help="list every case of the manifest(s) with input from generic pages, to confirm by eye")
    parser.add_argument("--expert", action="store_true",
                        help="also read the expert rule of each case the same way, for comparison")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    reference = load_reference(REPO / "data" / "sigma")
    cases, case_pages, generic, url_map, texts = {}, {}, set(), {}, {}
    if not args.no_pages:
        from eval.run_eval import load_github_manifest
        cases, case_pages, generic, titles = load_inputs(args.manifest or [REPO / "eval" / "manifest.jsonl"])
        url_map = load_github_manifest(REPO / "eval" / "github_manifest.jsonl")
    listed = generic_cases(cases, case_pages, generic) if args.list_generic else []
    if args.list_generic:
        whole = [c for c in listed if c["share"] == 1.0]
        print(f"cases with input from generic pages: {len(listed)} of {len(cases)}; whole input {len(whole)}")
        for c in listed:
            pages = "; ".join(f"{url} [{str(titles.get(url) or '').strip()[:50]}]" for url in c["urls"])
            print(f"  {c['share']:.0%}  {str(c['title'])[:60]}  <-  {pages}")
    report = {}
    for path in args.results:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        rows = [r for r in rows if r.get("rules_yaml") is not None and (not args.scope or in_scope(r, args.scope))]
        results = []
        for row in rows:
            rule_id = row.get("rule_id")
            if rule_id in cases and rule_id not in texts:
                texts[rule_id] = _report_text(cases[rule_id], url_map)
            share = generic_share(case_pages[rule_id], generic) if rule_id in case_pages else None
            results.append(case_health(row, reference, texts.get(rule_id), share))
        report[path.name] = run_summary(results)
        print_summary(path.stem, report[path.name])
        if args.expert:
            e = report[path.name]["expert_rules"] = _rates(expert_health(rows, reference, texts))
            in_report = (_ratio(e["values_in_report"], e["values_with_report"]) if e["values_in_report"] is not None
                         else "-")
            print(f"  the expert rules of these cases ({e['rules']}): run {e['run']}; a field SigmaHQ never uses "
                  f"with it {e['with_unused_fields']}/{e['judged_for_fields']}; an exclusion {e['with_exclusion']}; "
                  f"a parent-process field {e['with_parent_field']}; values in the report {in_report}; levels "
                  f"{e['levels']}")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        summary = {"scope": args.scope, "runs": report}
        if args.list_generic:
            summary["generic_cases"] = listed
        args.out.write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
        print(f"\nsummary: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
