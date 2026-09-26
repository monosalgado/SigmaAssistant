"""Sigma's conventions for a log source's `service` field (Change 25, plan 2.2b).

A log source is category + product + service. SigmaHQ uses the service almost only
when there is no category: of its 2,880 rules with a category, 12 carry a service;
of its 811 rules without one, 792 do (`windows`/`security`, `aws`/`cloudtrail`,
`linux`/`auditd`…). A category such as `process_creation` means "whichever log
recorded it" - Sysmon, Windows auditing or an EDR - and a service would narrow it.

So a suggested log source with a category loses its service (the value is kept in
`service_dropped`). Without a category the service defines the log source and stays;
if SigmaHQ's rules never use that product/service pair, the suggestion is marked
`service_to_confirm` for the analyst. The known pairs come from `data/sigma/rules` -
the rules the retrieval index is built from - never from `rules-emerging-threats`,
which holds the evaluation's answers.

The analysis prompt's reference table (Change 28, plan 2.6) is built from the same
rules: every category with the products its rules use, and every product/service
pair used without a category, each with its most-used detection fields.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

KNOWN_SERVICES_PATH = Path(__file__).with_name("sigma_known_services.json")
LOGSOURCE_TABLE_PATH = Path(__file__).with_name("sigma_logsource_table.json")
FIELDS_PER_SOURCE = 5
_PLACEHOLDERS = {"", "-", "none", "n/a", "null"}
_NOT_A_SELECTION = {"condition", "timeframe"}


def _clean(value) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().lower()
    return None if text in _PLACEHOLDERS else text


def has_category(value) -> bool:
    return _clean(value) is not None


def load_known_services(path: Path = KNOWN_SERVICES_PATH) -> set:
    return {(p, s) for p, s in json.loads(Path(path).read_text(encoding="utf-8"))}


def _rules(rules_dir: Path):
    """Each readable rule with a logsource block; unreadable files are skipped."""
    import yaml

    for path in Path(rules_dir).rglob("*.yml"):
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError):
            continue
        if isinstance(rule, dict) and isinstance(rule.get("logsource"), dict):
            yield rule


def build_known_services(rules_dir: Path) -> set:
    """Every (product, service) pair SigmaHQ uses in rules without a category."""
    pairs = set()
    for rule in _rules(rules_dir):
        logsource = rule["logsource"]
        service = _clean(logsource.get("service"))
        if service and not has_category(logsource.get("category")):
            pairs.add((_clean(logsource.get("product")), service))
    return pairs


def detection_fields(detection) -> set:
    """Field names a rule's detection matches on, without modifiers (`Image|endswith`
    -> `Image`). Keyword lists name no field."""
    fields = set()
    if not isinstance(detection, dict):
        return fields
    for name, selection in detection.items():
        if name in _NOT_A_SELECTION:
            continue
        maps = selection if isinstance(selection, list) else [selection]
        for item in maps:
            if isinstance(item, dict):
                fields.update(str(k).split("|")[0] for k in item if str(k).split("|")[0])
    return fields


def _top_fields(counts: Counter) -> list:
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0].lower(), kv[0]))
    return [name for name, _ in ranked[:FIELDS_PER_SOURCE]]


def build_logsource_table(rules_dir: Path) -> dict:
    """Every log source SigmaHQ's rules use, in Sigma's two forms (Change 28).

    with_category: one row per category, the products its rules use (None = the rules
    carry no product) and the fields they match on most. without_category: one row per
    product/service pair. A category rule that also names a service is listed under its
    category only. Rows are alphabetical, so their order says nothing about frequency.
    """
    products = defaultdict(set)
    cat_fields = defaultdict(Counter)
    svc_fields = defaultdict(Counter)
    for rule in _rules(rules_dir):
        logsource = rule["logsource"]
        fields = detection_fields(rule.get("detection"))
        category = _clean(logsource.get("category"))
        product = _clean(logsource.get("product"))
        if category:
            products[category].add(product)
            cat_fields[category].update(fields)
        else:
            key = (product, _clean(logsource.get("service")))
            svc_fields[key].update(fields)
    by_name = lambda value: value or ""
    return {
        "with_category": [
            {"category": c, "products": sorted(products[c], key=by_name),
             "fields": _top_fields(cat_fields[c])}
            for c in sorted(products)],
        "without_category": [
            {"product": p, "service": s, "fields": _top_fields(svc_fields[(p, s)])}
            for p, s in sorted(svc_fields, key=lambda k: (by_name(k[0]), by_name(k[1])))],
    }


def load_logsource_table(path: Path = LOGSOURCE_TABLE_PATH) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _cell(value) -> str:
    return value if value else "(none)"


def format_category_table(table: dict) -> str:
    lines = ["| Category | Product | Typical fields |", "|---|---|---|"]
    for row in table["with_category"]:
        lines.append(f"| {row['category']} | {', '.join(_cell(p) for p in row['products'])} "
                     f"| {', '.join(row['fields'])} |")
    return "\n".join(lines)


def format_service_table(table: dict) -> str:
    lines = ["| Product | Service | Typical fields |", "|---|---|---|"]
    for row in table["without_category"]:
        lines.append(f"| {_cell(row['product'])} | {_cell(row['service'])} "
                     f"| {', '.join(row['fields'])} |")
    return "\n".join(lines)


def on_table(suggestion: dict, table: dict) -> bool:
    """Is the suggestion one of the table's log sources, in one of Sigma's two forms?

    A category with one of its listed products and no service, or - without a category -
    a listed product/service pair. Placeholders count as absent. Used to measure; the
    pipeline does not enforce it.
    """
    category = _clean(suggestion.get("category"))
    product = _clean(suggestion.get("product"))
    service = _clean(suggestion.get("service"))
    if category:
        row = next((r for r in table["with_category"] if r["category"] == category), None)
        return row is not None and service is None and product in row["products"]
    if not product and not service:
        return False
    return any(r["product"] == product and r["service"] == service
               for r in table["without_category"])


def normalise_suggestion(suggestion: dict, known_services: set) -> dict:
    """The suggestion under Sigma's service convention; the input is not modified."""
    out = dict(suggestion)
    service = suggestion.get("service")
    if has_category(suggestion.get("category")):
        out["service"] = None
        if _clean(service) is not None:
            out["service_dropped"] = service
    elif _clean(service) is not None:
        if (_clean(suggestion.get("product")), _clean(service)) not in known_services:
            out["service_to_confirm"] = True
    return out


def first_rule_logsource_block(logsource_info: dict) -> str:
    """The log source the generation prompt recommends for the first rule (Change 26).

    The analyst's confirmation wins; otherwise the analysis stage's top suggestion, as
    ready-to-use YAML with its confidence and reasoning, so the model can weigh it. It
    is a recommendation: the prompt lets the model choose otherwise and explain why.
    """
    if logsource_info.get("user_confirmed") and logsource_info.get("primary_source"):
        return (f"Log source confirmed by the analyst: {logsource_info['primary_source']}. "
                "Use it for the first rule.")
    suggestions = [s for s in logsource_info.get("suggestions") or [] if isinstance(s, dict)]
    if not suggestions:
        return ("No log source was recommended by the analysis; choose the one that best "
                "observes the behaviour described.")
    top = suggestions[0]
    lines = ["logsource:"] + [f"    {f}: {str(top[f]).strip()}" for f in ("category", "product", "service")
                              if _clean(top.get(f)) is not None]
    why = f"Confidence: {top.get('confidence', '?')}."
    if top.get("reasoning"):
        why += f" Why: {top['reasoning']}"
    return "\n".join(lines) + "\n" + why


def describe_suggestion(suggestion: dict) -> str:
    """category/product/service for the generation prompt, only the fields present."""
    parts = [str(suggestion[f]).strip() for f in ("category", "product", "service")
             if _clean(suggestion.get(f)) is not None]
    return "/".join(parts) or "?"
