#!/usr/bin/env python3
"""Build the events a Sigma rule is written to catch (R9.2 synthetic replay; design fixed in the log 2026-10-05).

The rule's condition (parsed by pySigma, as `rule_matcher`) is put in disjunctive normal form with NOT pushed down
to the atoms; each conjunction is one way the rule can fire and becomes one event (at most CAP per rule, in a fixed
order). Values are minimal - nothing is invented: a wildcard string becomes its literal parts (`*` -> nothing,
`?` -> `x`); several strings on one field are joined by one space, starts-with parts first and ends-with parts last;
a number is itself; `|gt N` -> N+1, `|lt N` -> N-1; `|cidr` -> the network's first host; `|exists: true` -> `x`;
`exists: false` and null -> the field left out; booleans as written; `|fieldref` -> both fields `x`; an expansion ->
its first alternative; a keyword -> the field `Message`. A negated atom is satisfied by leaving its field out.
A regex, a placeholder or a contradiction (e.g. two exact values for one field) -> "cannot build", with the reason.
The builder does not check its own events: validation V1 does, and `verified_events` keeps only the events the
source rule fires on.
"""

from __future__ import annotations

import ipaddress

from eval.rule_matcher import CannotEvaluate, rule_matches

CAP = 20
_LIMIT = 1000          # bound on conjunctions while expanding
_ABSENT = object()


def dnf(node, negate: bool = False) -> list:
    """[[(atom, negated), ...], ...]: the condition as an OR of ANDs, NOT pushed down (De Morgan)."""
    from sigma import conditions as c
    if isinstance(node, c.ConditionNOT):
        return dnf(node.args[0], not negate)
    if isinstance(node, (c.ConditionAND, c.ConditionOR)):
        conjunctive = isinstance(node, c.ConditionAND) != negate
        parts = [dnf(a, negate) for a in node.args]
        if conjunctive:
            terms = [[]]
            for part in parts:
                terms = [t + u for t in terms for u in part][:_LIMIT]
            return terms
        return [t for part in parts for t in part][:_LIMIT]
    if isinstance(node, (c.ConditionFieldEqualsValueExpression, c.ConditionValueExpression)):
        return [[(node, negate)]]
    raise CannotEvaluate(f"condition node {type(node).__name__}")


def _literal(value):
    """(literal text, starts with a wildcard, ends with a wildcard) of a wildcard string; None for a placeholder."""
    from sigma import types as t
    parts, text = list(value.s), []
    for part in parts:
        if isinstance(part, str):
            text.append(part)
        elif part == t.SpecialChars.WILDCARD_SINGLE:
            text.append("x")
        elif part != t.SpecialChars.WILDCARD_MULTI:
            return None
    first, last = (parts[0], parts[-1]) if parts else (None, None)
    return "".join(text), first == t.SpecialChars.WILDCARD_MULTI, last == t.SpecialChars.WILDCARD_MULTI


def _strings(values: list):
    """One string satisfying every wildcard string, or (None, reason)."""
    exact, starts, contains, ends = [], [], [], []
    for value in values:
        lit = _literal(value)
        if lit is None:
            return None, "placeholder"
        text, lead, trail = lit
        (contains if lead and trail else ends if lead else starts if trail else exact).append(text)
    if len(set(exact)) > 1:
        return None, "contradiction"
    if exact:
        return exact[0], None                     # the others must hold for it; V1 checks
    return " ".join(starts + contains + ends), None


def _number(values: list):
    from sigma import types as t
    numbers = {v.number for v in values if isinstance(v, t.SigmaNumber)}
    if len(numbers) > 1:
        return None, "contradiction"
    candidates = list(numbers)
    for v in values:
        if isinstance(v, t.SigmaCompareExpression):
            n, op = v.number.number, v.op.name
            candidates.append(n + 1 if op == "GT" else n - 1 if op == "LT" else n)
    for candidate in candidates:
        if all(_satisfies_number(v, candidate) for v in values):
            return candidate, None
    return None, "contradiction"


def _satisfies_number(value, n) -> bool:
    from sigma import types as t
    if isinstance(value, t.SigmaNumber):
        return n == value.number
    m, op = value.number.number, value.op.name
    return {"LT": n < m, "LTE": n <= m, "GT": n > m, "GTE": n >= m}[op]


def _field_value(values: list):
    """(value, reason): the minimal value satisfying every positive atom on one field; _ABSENT to leave it out."""
    from sigma import types as t
    values = [v.values[0] if isinstance(v, t.SigmaExpansion) and v.values else v for v in values]
    if any(isinstance(v, t.SigmaRegularExpression) for v in values):
        return None, "regex"
    kinds = set()
    for v in values:
        if isinstance(v, t.SigmaString):
            kinds.add("string")
        elif isinstance(v, (t.SigmaNumber, t.SigmaCompareExpression)):
            kinds.add("number")
        elif isinstance(v, (t.SigmaNull, t.SigmaExists, t.SigmaBool, t.SigmaCIDRExpression)):
            kinds.add(type(v).__name__)
        else:
            return None, f"value type {type(v).__name__}"
    present = [v for v in values if not (isinstance(v, t.SigmaExists) and v.exists)]
    if any(isinstance(v, t.SigmaNull) or (isinstance(v, t.SigmaExists) and not v.exists) for v in present):
        return (_ABSENT, None) if len(present) == len(values) == 1 else (None, "contradiction")
    if not present:                               # only `exists: true`
        return "x", None
    kinds.discard("SigmaExists")
    if len(kinds) > 1:
        return None, "contradiction"
    kind = kinds.pop()
    if kind == "string":
        return _strings(present)
    if kind == "number":
        return _number(present)
    if kind == "SigmaBool":
        booleans = {v.boolean for v in present}
        return (booleans.pop(), None) if len(booleans) == 1 else (None, "contradiction")
    networks = [ipaddress.ip_network(v.cidr, strict=False) for v in present]
    host = networks[0].network_address + (1 if networks[0].num_addresses > 2 else 0)
    return (str(host), None) if all(host in n for n in networks) else (None, "contradiction")


def _build_term(term: list):
    from sigma import conditions as c
    from sigma import types as t
    positives, negatives, keywords, refs = {}, [], [], []
    for atom, negated in term:
        if isinstance(atom, c.ConditionValueExpression):
            if not negated:
                keywords.append(atom.value)
            continue
        if negated:
            negatives.append((atom.field, atom.value))
        elif isinstance(atom.value, t.SigmaFieldReference):
            refs.append((atom.field, atom.value.field))
        else:
            positives.setdefault(atom.field.lower(), (atom.field, []))[1].append(atom.value)
    event = {}
    for field, values in positives.values():
        value, reason = _field_value(values)
        if reason:
            return None, reason
        if value is not _ABSENT:
            event[field] = value
    for field, other in refs:
        shared = event.get(other, event.get(field, "x"))
        event.setdefault(field, shared)
        event.setdefault(other, shared)
    if keywords:
        text, reason = _strings([k.values[0] if isinstance(k, t.SigmaExpansion) else k for k in keywords])
        if reason:
            return None, reason
        event["Message"] = text
    lowered = {k.lower() for k in event}
    for field, value in negatives:                # a negated null / `exists: false` needs the field present
        if field.lower() not in lowered and (isinstance(value, t.SigmaNull)
                                             or (isinstance(value, t.SigmaExists) and not value.exists)):
            event[field] = "x"
    return event, None


def build_events(parsed) -> dict:
    """{"events": [...], "cannot_build": [reason per conjunction not built], "conjunctions": n}."""
    terms = dnf(parsed.tree)
    events, cannot = [], []
    for term in terms[:CAP]:
        event, reason = _build_term(term)
        if reason:
            cannot.append(reason)
        elif event not in events:
            events.append(event)
    return {"events": events, "cannot_build": cannot, "conjunctions": len(terms)}


def verified_events(parsed, events: list) -> list:
    """The built events the source rule fires on (validation V1; only these are used to score)."""
    out = []
    for event in events:
        try:
            if rule_matches(parsed, event):
                out.append(event)
        except CannotEvaluate:
            continue
    return out
