#!/usr/bin/env python3
"""Score generated rules by synthetic replay (R9.2; design and amendment fixed in the log 2026-10-05).

For a case, the **human event sets** are the events built (`event_builder`) from the gold rule and from every other
human-written SigmaHQ rule for the same report (Pany's definition: an emerging-threats rule citing one of the case's
input URLs; a URL cited by more than MAX_CITING rules links nothing); only events the source rule fires on are used.
Our rule **sees** an event when every log-source field it names equals the event's, or the event's leaves it unnamed.

Per case: **hit** (primary) - any of the case's rules fires on any event of any human set; `hit_first` - the first
rule; `hit_gold` - the gold rule's set alone; `coverage` - the share of the human events caught; `hit_logic` - with
the log source ignored; the **miss reason** (no rule parses / log source / field absent / value mismatch); and,
with the report's text, whether a miss is **report-grounded** (one of our rules has every judgeable value in the
report: a plausible different detection, unverified). **Breadth** - the share of other cases our rules hit.
A replay hit means "catches what a human targeted"; a miss is not proof of failure (the replay is a lower bound).
"""

from __future__ import annotations

from eval.event_builder import build_events, dnf, verified_events
from eval.rule_matcher import CannotEvaluate, parse_rule, rule_matches

FIELDS = ("category", "product", "service")


def _clean(value):
    from backend.pipeline.sigma_logsource import _clean as clean
    return clean(value)


def applies(ours: dict, event: dict) -> bool:
    for field in FIELDS:
        mine, theirs = _clean((ours or {}).get(field)), _clean((event or {}).get(field))
        if mine is not None and theirs is not None and mine != theirs:
            return False
    return True


def human_set(rule_text: str, rule_id: str = None) -> dict:
    """{rule_id, logsource, events (verified), cannot_build, error}."""
    out = {"rule_id": rule_id, "logsource": {}, "events": [], "cannot_build": [], "error": None}
    try:
        parsed = parse_rule(rule_text)
        built = build_events(parsed)
    except CannotEvaluate as exc:
        out["error"] = str(exc)[:200]
        return out
    ls = parsed.rule.logsource
    out.update(logsource={"category": ls.category, "product": ls.product, "service": ls.service},
               events=verified_events(parsed, built["events"]), cannot_build=built["cannot_build"])
    return out


def _parse_ours(rules: list) -> list:
    """[(parsed, log source) or None] for each of our rules, in order."""
    out = []
    for text in rules or []:
        try:
            parsed = parse_rule(text)
            ls = parsed.rule.logsource
            out.append((parsed, {"category": ls.category, "product": ls.product, "service": ls.service}))
        except CannotEvaluate:
            out.append(None)
    return out


def _fires(entry, sets: list, event, logsource, use_logsource=True) -> bool:
    if entry is None:
        return False
    parsed, ours = entry
    if use_logsource and not applies(ours, logsource):
        return False
    try:
        return rule_matches(parsed, event)
    except CannotEvaluate:
        return False


def _positive_fields(parsed) -> list:
    """For each way the rule can fire: the fields it needs present."""
    from sigma import conditions as c
    from sigma import types as t
    out = []
    for term in dnf(parsed.tree):
        needed = {a.field.lower() for a, neg in term if not neg and isinstance(a, c.ConditionFieldEqualsValueExpression)
                  and not isinstance(a.value, t.SigmaNull)
                  and not (isinstance(a.value, t.SigmaExists) and not a.value.exists)}
        out.append(needed)
    return out


def _field_absent(entries: list, events: list) -> bool:
    for entry in entries:
        if entry is None:
            continue
        for event in events:
            present = {k.lower() for k in event}
            if any(needed <= present for needed in _positive_fields(entry[0])):
                return False
    return True


def case_score(rules: list, sets: list) -> dict:
    ours = _parse_ours(rules)
    events = [(e, s["logsource"], i) for i, s in enumerate(sets) for e in s["events"]]
    out = {"rules": len(ours), "parsed": sum(e is not None for e in ours), "human_events": len(events),
           "hit": False, "hit_first": False, "hit_gold": False, "hit_logic": False, "coverage": None, "miss": None}
    if not events:
        out["miss"] = "no human events"
        return out
    caught = [any(_fires(o, sets, e, ls) for o in ours) for e, ls, _ in events]
    out["hit"] = any(caught)
    out["coverage"] = sum(caught) / len(events)
    out["hit_first"] = bool(ours) and any(_fires(ours[0], sets, e, ls) for e, ls, _ in events)
    out["hit_gold"] = any(c for c, (_, _, i) in zip(caught, events) if i == 0)
    out["hit_logic"] = any(_fires(o, sets, e, ls, use_logsource=False) for o in ours for e, ls, _ in events)
    if not out["hit"]:
        out["miss"] = ("no rule parses" if not out["parsed"] else "log source" if out["hit_logic"] else
                       "field absent" if _field_absent(ours, [e for e, _, _ in events]) else "value mismatch")
    return out


def breadth(rules: list, others: dict) -> float:
    """The share of other cases (case -> human sets) on which any of our rules fires."""
    ours = _parse_ours(rules)
    if not others:
        return None
    hits = sum(1 for sets in others.values()
               if any(_fires(o, sets, e, s["logsource"]) for o in ours for s in sets for e in s["events"]))
    return hits / len(others)


def grounded_rule(rules: list, text: str) -> bool:
    """One of our rules parses and every judgeable value of it (>= 3 characters) occurs in the report."""
    from eval.diagnose_detection import grounded
    from eval.scorers import extract_detection_values
    import yaml
    for rule_text, entry in zip(rules or [], _parse_ours(rules)):
        if entry is None:
            continue
        rule = yaml.safe_load(rule_text)
        values = {v for _, v in extract_detection_values(rule.get("detection") if isinstance(rule, dict) else None)}
        judged = [grounded(v, text) for v in values]
        judged = [j for j in judged if j is not None]
        if judged and all(judged):
            return True
    return False


def alternative_rule_ids(case: dict, index: dict) -> list:
    """The other human rules for the case's report (Pany's definition, `alternative_logsources`)."""
    from eval.alternative_logsources import MAX_CITING, norm_url
    out = []
    for url in case.get("references_usable") or []:
        citing = index.get(norm_url(url), [])
        if len(citing) > MAX_CITING:
            continue
        for rule_id, _ in citing:
            if rule_id != case["rule_id"] and rule_id not in out:
                out.append(rule_id)
    return out
