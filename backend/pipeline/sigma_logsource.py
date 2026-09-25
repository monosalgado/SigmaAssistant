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
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

KNOWN_SERVICES_PATH = Path(__file__).with_name("sigma_known_services.json")
_PLACEHOLDERS = {"", "-", "none", "n/a", "null"}


def _clean(value) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().lower()
    return None if text in _PLACEHOLDERS else text


def has_category(value) -> bool:
    return _clean(value) is not None


def load_known_services(path: Path = KNOWN_SERVICES_PATH) -> set:
    return {(p, s) for p, s in json.loads(Path(path).read_text(encoding="utf-8"))}


def build_known_services(rules_dir: Path) -> set:
    """Every (product, service) pair SigmaHQ uses in rules without a category."""
    import yaml

    pairs = set()
    for path in Path(rules_dir).rglob("*.yml"):
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError):
            continue
        if not isinstance(rule, dict) or not isinstance(rule.get("logsource"), dict):
            continue
        logsource = rule["logsource"]
        service = _clean(logsource.get("service"))
        if service and not has_category(logsource.get("category")):
            pairs.add((_clean(logsource.get("product")), service))
    return pairs


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
