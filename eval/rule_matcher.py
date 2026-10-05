#!/usr/bin/env python3
"""Evaluate a Sigma rule against events (R9, replay; definition fixed in the log 2026-10-04 before this code).

pySigma (already used by the review stage) parses the rule and its condition: modifiers become wildcard strings,
`1 of` / `all of` are expanded, and the condition becomes a tree of AND / OR / NOT over field-equals-value and
keyword nodes. This module only walks that tree for one event:
- a field is looked up by its exact name, else case-insensitively; a missing field does not match (a null does);
- a string matches when its `to_regex()` pattern matches the whole value, case-insensitively (`|cased`: sensitive);
- a number equals the value's number; `|re` is searched with its own flags; `|exists`, `|cidr`, `|lt/lte/gt/gte`,
  booleans, `|fieldref` and expansions (`|windash`, `|base64offset`: any alternative) as named;
- a keyword matches when its pattern is found anywhere in any value of the event.
Anything else raises CannotEvaluate - a verdict is never guessed. Log-source applicability is not decided here.
"""

from __future__ import annotations

import ipaddress
import json
import operator
import re
from collections import namedtuple
from pathlib import Path


class CannotEvaluate(Exception):
    """The rule or one of its values is outside what this matcher evaluates."""


ParsedRule = namedtuple("ParsedRule", "rule tree")
_MISSING = object()


def parse_rule(text: str) -> ParsedRule:
    from sigma.rule import SigmaRule
    try:
        rule = SigmaRule.from_yaml(text)
        conditions = rule.detection.parsed_condition
        if len(conditions) != 1:
            raise CannotEvaluate(f"{len(conditions)} conditions")
        return ParsedRule(rule, conditions[0].parse())
    except CannotEvaluate:
        raise
    except Exception as exc:                      # YAML errors, pySigma's own errors (e.g. deprecated aggregations)
        raise CannotEvaluate(f"{type(exc).__name__}: {exc}") from exc


def _lookup(event: dict, field: str):
    if field in event:
        return event[field]
    lowered = field.lower()
    for key, value in event.items():
        if str(key).lower() == lowered:
            return value
    return _MISSING


def _number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _value_matches(value, actual, event: dict) -> bool:
    from sigma import types as t
    if isinstance(value, t.SigmaExpansion):
        return any(_value_matches(v, actual, event) for v in value.values)
    if isinstance(value, t.SigmaNull):
        return actual is _MISSING or actual is None or actual == ""
    if isinstance(value, t.SigmaExists):
        return (actual is not _MISSING) == bool(value.exists)
    if actual is _MISSING or actual is None:
        return False
    if isinstance(value, t.SigmaCasedString):
        return re.fullmatch(value.to_regex().regexp, str(actual), re.DOTALL) is not None
    if isinstance(value, t.SigmaString):
        return re.fullmatch(value.to_regex().regexp, str(actual), re.IGNORECASE | re.DOTALL) is not None
    if isinstance(value, t.SigmaBool):
        return str(actual).strip().lower() == str(value.boolean).lower()
    if isinstance(value, t.SigmaNumber):
        number = _number(actual)
        return number is not None and number == float(value.number)
    if isinstance(value, t.SigmaRegularExpression):
        flags = 0
        for flag in value.flags or ():
            flags |= {"IGNORECASE": re.IGNORECASE, "MULTILINE": re.MULTILINE, "DOTALL": re.DOTALL}.get(flag.name, 0)
        return re.search(value.regexp, str(actual), flags) is not None
    if isinstance(value, t.SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(str(actual).strip()) in ipaddress.ip_network(value.cidr, strict=False)
        except ValueError:
            return False
    if isinstance(value, t.SigmaCompareExpression):
        number = _number(actual)
        compare = {"LT": operator.lt, "LTE": operator.le, "GT": operator.gt, "GTE": operator.ge}[value.op.name]
        return number is not None and compare(number, float(value.number.number))
    if isinstance(value, t.SigmaFieldReference):
        other = _lookup(event, value.field)
        return other is not _MISSING and str(other).lower() == str(actual).lower()
    raise CannotEvaluate(f"value type {type(value).__name__}")


def _keyword_matches(value, event: dict) -> bool:
    from sigma import types as t
    if isinstance(value, t.SigmaExpansion):
        return any(_keyword_matches(v, event) for v in value.values)
    if isinstance(value, t.SigmaNumber):                      # a numeric keyword: its text, anywhere
        return any(str(value.number) in str(v) for v in event.values() if v is not None)
    if not isinstance(value, t.SigmaString):
        raise CannotEvaluate(f"keyword type {type(value).__name__}")
    flags = re.DOTALL if isinstance(value, t.SigmaCasedString) else re.IGNORECASE | re.DOTALL
    pattern = re.compile(value.to_regex().regexp, flags)
    return any(pattern.search(str(v)) for v in event.values() if v is not None)


def _evaluate(node, event: dict) -> bool:
    from sigma import conditions as c
    if isinstance(node, c.ConditionAND):
        return all(_evaluate(a, event) for a in node.args)
    if isinstance(node, c.ConditionOR):
        return any(_evaluate(a, event) for a in node.args)
    if isinstance(node, c.ConditionNOT):
        return not _evaluate(node.args[0], event)
    if isinstance(node, c.ConditionFieldEqualsValueExpression):
        return _value_matches(node.value, _lookup(event, node.field), event)
    if isinstance(node, c.ConditionValueExpression):
        return _keyword_matches(node.value, event)
    raise CannotEvaluate(f"condition node {type(node).__name__}")


def rule_matches(parsed: ParsedRule, event: dict) -> bool:
    return _evaluate(parsed.tree, event)


def flatten_event(raw: dict) -> dict:
    """A Windows event (as `evtx_dump` writes it) as one map of fields; an already-flat map is returned as is."""
    event = raw.get("Event") if isinstance(raw, dict) else None
    if not isinstance(event, dict):
        return dict(raw)
    system = event.get("System") or {}
    data = event.get("EventData")
    if not isinstance(data, dict) or not data:
        user_data = event.get("UserData") or {}
        inner = [v for v in user_data.values() if isinstance(v, dict)] if isinstance(user_data, dict) else []
        data = inner[0] if inner else {}
    out = {k: v for k, v in data.items() if not str(k).startswith("#")}
    event_id = system.get("EventID")
    if isinstance(event_id, dict):
        event_id = event_id.get("#text")
    for key, value in (("EventID", event_id), ("Channel", system.get("Channel")),
                       ("Provider_Name", ((system.get("Provider") or {}).get("#attributes") or {}).get("Name")),
                       ("Computer", system.get("Computer"))):
        if value is not None:
            out[key] = value
    return out


def load_events(path) -> list:
    """Events from a JSON file holding one object, a list, or several objects written back to back."""
    text = Path(path).read_text(encoding="utf-8")
    decoder, events, i = json.JSONDecoder(), [], 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        obj, i = decoder.raw_decode(text, i)
        events.extend(obj if isinstance(obj, list) else [obj])
    return [flatten_event(e) for e in events]
