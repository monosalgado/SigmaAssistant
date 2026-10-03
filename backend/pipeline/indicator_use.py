"""Which of the analysis's indicators the generated rules use (Change 40: recorded, never enforced).

An indicator is used when one of a rule's detection values contains it, or is contained in it and is at least
half as long - the matching S5v uses for values (`eval/scorers.value_matches`). Values are compared lower-cased,
`*` at the ends removed, a doubled backslash read as one; an indicator under 3 characters is not judged;
selections named `filter...` (exclusions) are skipped, as in S5v.
"""

from __future__ import annotations

import yaml


def _norm(value) -> str:
    return str(value).strip().lower().strip("*").replace("\\\\", "\\").strip()


def _detection_values(rule_text: str) -> list:
    try:
        rule = yaml.safe_load(rule_text)
    except yaml.YAMLError:
        return []
    detection = rule.get("detection") if isinstance(rule, dict) else None
    values = []

    def walk(node):
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif node is not None:
            values.append(_norm(node))

    if isinstance(detection, dict):
        for name, selection in detection.items():
            name = str(name).strip().lower()
            if name not in ("condition", "timeframe") and not name.startswith("filter"):     # exclusions
                walk(selection)
    return [v for v in values if v]


def _matches(indicator: str, value: str) -> bool:
    return indicator in value or (value in indicator and 2 * len(value) >= len(indicator))


def indicator_use(indicators: list, rules: list) -> dict:
    """{given, used, unused}: the indicators' values (as given), in the analysis's order."""
    values = [v for rule in rules or [] for v in _detection_values(rule)]
    out = {"given": 0, "used": [], "unused": []}
    for indicator in indicators or []:
        raw = indicator.get("value") if isinstance(indicator, dict) else None
        if raw is None or len(_norm(raw)) < 3:
            continue
        out["given"] += 1
        key = "used" if any(_matches(_norm(raw), v) for v in values) else "unused"
        out[key].append(raw)
    return out
