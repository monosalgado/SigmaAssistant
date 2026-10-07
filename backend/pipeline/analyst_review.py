"""The analyst's review of a saved analysis, applied before any rule is written.

Plan Phase 3/4 (user, 2026-09-27): the analyst checks what the model understood about
the attack. Design `thesis/ASSISTANT_DESIGN.md`, P4: what the analyst confirms is final,
what the model suggests stays a recommendation.

A review refers to the saved analysis's lists by position:

    {"logsource":  {"category": ..., "product": ..., "service": ...},  # the analyst's choice
     "techniques": {"1": "rejected", "0": "confirmed"},
     "indicators": {...}, "patterns": {...},       # confirmed | rejected
     "excluded":   {"0": "restored"},
     "note":       "free text for the rule writer"}

Rejected techniques, indicators and attack patterns do not reach generation. One decision per
string: rejecting a pattern or an indicator also rejects its copies in both lists - the model often
lists the same string twice (`ysoserial.exe`, SharePoint, 2026-09-27) - matched exactly, case and
spacing aside, never by "contains"; the copies are recorded as `linked`. A rejected
pattern is not added to the excluded strings: rejecting the bare pattern `sudo` as too broad
does not mean no rule may contain "sudo" (live test, 2026-09-27). A restored excluded string
becomes an attack pattern. A confirmed log source goes first and is marked as the analyst's
decision. Confirming anything else is recorded only.

Code validates the review against the saved lists and SigmaHQ's log source table and
records it; it never decides for the analyst.
"""

from __future__ import annotations

import copy

import yaml

from backend.pipeline.sigma_logsource import _NOT_A_SELECTION, _clean, describe_suggestion, on_table

MAX_NOTE = 2000

# kind -> (where the list lives in the context, the statuses the analyst can give)
_LISTS = {
    "techniques": (("ttp_mapping", "mappings"), {"confirmed", "rejected"}),
    "indicators": (("extraction", "indicators"), {"confirmed", "rejected"}),
    "patterns": (("attack_vector", "payload_signatures"), {"confirmed", "rejected"}),
    "excluded": (("attack_vector", "incidental_artifacts"), {"restored"}),
}
_KINDS = set(_LISTS) | {"logsource", "note"}

# The lists whose strings the rule writer receives: a rejected string goes from both.
_LINKED = ("patterns", "indicators")


class ReviewError(ValueError):
    """A review that does not fit the saved analysis or the spec."""


def _label(kind: str, item) -> str:
    """How the record names an item: the technique ID, the value, the pattern."""
    if not isinstance(item, dict):
        return str(item)
    key = {"techniques": "technique_id", "patterns": "pattern"}.get(kind, "value")
    return str(item.get(key, ""))


def same_string(value) -> str:
    """How copies of a string are matched: exactly, ignoring case and spacing."""
    return " ".join(str(value).split()).lower()


def _decisions(kind: str, given, n_items: int) -> dict:
    """{position: status}, validated against the saved list."""
    if not isinstance(given, dict):
        raise ReviewError(f"{kind}: expected {{position: status}}")
    allowed = _LISTS[kind][1]
    out = {}
    for key, status in given.items():
        try:
            pos = int(key)
        except (TypeError, ValueError):
            raise ReviewError(f"{kind}: {key!r} is not a position")
        if not 0 <= pos < n_items:
            raise ReviewError(f"{kind}: position {pos} is not in the saved analysis ({n_items} items)")
        if status not in allowed:
            raise ReviewError(f"{kind}: status {status!r} is not one of {sorted(allowed)}")
        out[pos] = status
    return out


def _logsource(given, table: dict) -> dict:
    """The analyst's log source, in Sigma's form, if it is on SigmaHQ's table."""
    if not isinstance(given, dict):
        raise ReviewError("logsource: expected {category, product, service}")
    choice = {f: _clean(given.get(f)) for f in ("category", "product", "service")}
    if not on_table(choice, table):
        raise ReviewError(f"logsource: {describe_suggestion(choice)} is not a log source in SigmaHQ's rules")
    return choice


def _same_source(suggestion: dict, choice: dict) -> bool:
    return all(_clean(suggestion.get(f)) == choice[f] for f in ("category", "product", "service"))


def logsource_choices(table: dict) -> list:
    """Every log source in SigmaHQ's table, in Sigma's two forms, for the analyst to pick."""
    choices = [{"category": row["category"], "product": product, "service": None}
               for row in table["with_category"] for product in row["products"]]
    choices += [{"category": None, "product": row["product"], "service": row["service"]}
                for row in table["without_category"]]
    return choices


def apply_review(context: dict, review: dict, table: dict) -> dict:
    """A copy of the saved analysis with the analyst's review applied and recorded.

    Raises ReviewError, before changing anything, for a review that does not fit.
    """
    if not isinstance(review, dict):
        raise ReviewError("expected a review object")
    unknown = set(review) - _KINDS
    if unknown:
        raise ReviewError(f"unknown review fields: {sorted(unknown)}")

    note = review.get("note") or ""
    if not isinstance(note, str):
        raise ReviewError("note: expected text")
    note = note.strip()
    if len(note) > MAX_NOTE:
        raise ReviewError(f"note: longer than {MAX_NOTE} characters")

    choice = _logsource(review["logsource"], table) if review.get("logsource") is not None else None

    saved = {kind: list((context.get(path[0]) or {}).get(path[1]) or [])
             for kind, (path, _) in _LISTS.items()}
    decided = {kind: _decisions(kind, review.get(kind) or {}, len(saved[kind])) for kind in _LISTS}

    # One decision per string: the copies of a rejected string are rejected with it.
    rejected = {same_string(_label(k, saved[k][pos])) for k in _LINKED
                for pos, status in decided[k].items() if status == "rejected"} - {""}
    for k in _LINKED:
        for pos, status in decided[k].items():
            if status == "confirmed" and same_string(_label(k, saved[k][pos])) in rejected:
                raise ReviewError(f"{k}: {_label(k, saved[k][pos])!r} is confirmed here and rejected elsewhere")
    linked = {k: [pos for pos, item in enumerate(saved[k])
                  if pos not in decided[k] and same_string(_label(k, item)) in rejected]
              for k in _LINKED}

    # Everything is valid: build the new context.
    out = copy.deepcopy(context)
    record = {kind: {status: [_label(kind, saved[kind][pos]) for pos, s in sorted(decided[kind].items())
                              if s == status]
                     for status in sorted(_LISTS[kind][1])}
              for kind in _LISTS}
    for k in _LINKED:
        record[k]["linked"] = [_label(k, saved[k][pos]) for pos in linked[k]]
    record["logsource"] = None
    record["note"] = note

    kept = {kind: [item for pos, item in enumerate(saved[kind])
                   if decided[kind].get(pos) not in ("rejected", "restored") and pos not in linked.get(kind, [])]
            for kind in _LISTS}
    for pos, status in sorted(decided["excluded"].items()):
        item = saved["excluded"][pos]
        reason = item.get("reason", "") if isinstance(item, dict) else ""
        kept["patterns"].append({
            "pattern": _label("excluded", item),
            "where": "not stated",
            "derived_from": "Restored by the analyst" + (f" (it had been excluded as: {reason})" if reason else ""),
        })

    # A restored excluded string moves to the patterns.
    touched = {kind: bool(decided[kind]) or bool(linked.get(kind)) for kind in _LISTS}
    touched["patterns"] |= bool(decided["excluded"])
    for kind, (path, _) in _LISTS.items():
        if touched[kind]:
            out.setdefault(path[0], {})[path[1]] = kept[kind]

    if choice is not None:
        ls = out.setdefault("logsource_suggestion", {})
        suggestions = [s for s in ls.get("suggestions") or []]
        rank = next((i for i, s in enumerate(suggestions) if isinstance(s, dict) and _same_source(s, choice)), None)
        if rank is not None:
            chosen = suggestions.pop(rank)
        else:
            chosen = dict(choice, confidence=None, reasoning="Chosen by the analyst", relevant_fields=[])
        ls["suggestions"] = [chosen] + suggestions
        ls["primary_source"] = describe_suggestion(choice)
        ls["user_confirmed"] = True
        ls["confirmed_logsource"] = choice
        record["logsource"] = dict(choice, suggested_rank=None if rank is None else rank + 1)

    if note:
        out["user_feedback_notes"] = note
    out["analyst_review"] = record
    return out


def review_from_record(record, context: dict) -> dict:
    """The review a version's record (`analyst_review`) stands for, by position in the saved analysis - so the next
    correction round starts with these corrections marked (user, 2026-10-07: "carry corrections forward"). Copies
    rejected with a string (`linked`) are not decisions of their own; `apply_review` derives them again."""
    if not record:
        return {}
    out = {}
    for kind, (path, statuses) in _LISTS.items():
        labels = [_label(kind, item) for item in (context.get(path[0]) or {}).get(path[1]) or []]
        decided = {}
        for status in sorted(statuses):
            for label in (record.get(kind) or {}).get(status) or []:
                pos = next((i for i, l in enumerate(labels) if l == label and str(i) not in decided), None)
                if pos is not None:
                    decided[str(pos)] = status
        if decided:
            out[kind] = decided
    if record.get("logsource"):
        out["logsource"] = {k: record["logsource"].get(k) for k in ("category", "product", "service")}
    if record.get("note"):
        out["note"] = record["note"]
    return out


# --- The rules against the review (design P4) -------------------------------------------------

# Departures that get one rewrite: unambiguous decisions. A rejected string used in a detection is
# only shown - it can be right inside a larger condition (live, 2026-09-27: the bare pattern `sudo`
# rejected, and rules selecting the sudo process AND the `-u#-1` argument were flagged).
ENFORCED_DEPARTURES = ("logsource", "technique")

def _plain(value) -> str:
    """A detection value or rejected string as compared: exact, case and spacing aside, without
    Sigma's `*` wildcards or a leading path separator (`\\ysoserial.exe` detects on ysoserial.exe)."""
    return same_string(value).strip("*").lstrip("\\/")


def _detection_values(detection) -> list:
    """Every value a rule matches on, in its detection's selections (not the condition)."""
    found = []

    def walk(node):
        if isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
        elif node is not None:
            found.append(str(node))

    for name, selection in (detection or {}).items():
        if name not in _NOT_A_SELECTION:
            walk(selection)
    return found


def _checkable(record: dict) -> dict:
    """What the review asks of the rules: the log source, rejected techniques, rejected strings."""
    record = record or {}
    strings = {}
    for kind in _LINKED:
        for status in ("rejected", "linked"):
            for value in (record.get(kind) or {}).get(status) or []:
                strings.setdefault(_plain(value), str(value).strip())
    strings.pop("", None)
    return {
        "logsource": record.get("logsource"),
        "techniques": [str(t).strip().lower() for t in (record.get("techniques") or {}).get("rejected") or []],
        "strings": strings,
    }


def has_checks(context: dict) -> bool:
    """Whether the analyst's review asks anything of the rules."""
    wanted = _checkable(context.get("analyst_review"))
    return bool(wanted["logsource"] or wanted["techniques"] or wanted["strings"])


def review_departures(rules: list, context: dict) -> list:
    """Where the rules depart from the analyst's review; empty when there is no review.

    The first rule's log source against the analyst's choice (the prompt asks for it on the
    first rule); every rule's ATT&CK tags against the rejected techniques; every rule's
    detection values against the rejected strings, copies included. A rule that does not parse
    is left to validation. Code only compares; it never edits a rule. Which departures get a
    rewrite is the orchestrator's (ENFORCED_DEPARTURES).
    """
    wanted = _checkable(context.get("analyst_review"))
    choice = (context.get("logsource_suggestion") or {}).get("confirmed_logsource") if wanted["logsource"] else None
    out = []
    for i, rule in enumerate(rules or []):
        try:
            doc = yaml.safe_load(rule.get("yaml_content") or "")
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        title = str(doc.get("title") or f"Rule {i + 1}")

        def depart(kind, message):
            out.append({"rule": i + 1, "title": title, "kind": kind, "message": message})

        if i == 0 and choice:
            ls = doc.get("logsource") if isinstance(doc.get("logsource"), dict) else {}
            got = {f: _clean(ls.get(f)) for f in ("category", "product", "service")}
            if got != {f: _clean(choice.get(f)) for f in ("category", "product", "service")}:
                depart("logsource", f"its log source is {describe_suggestion(got)}; the analyst chose "
                                    f"{describe_suggestion(choice)} for the first rule")
        tags = [str(t).strip().lower() for t in doc.get("tags") or []]
        for technique in wanted["techniques"]:
            if f"attack.{technique}" in tags:
                depart("technique", f"it is tagged attack.{technique}, a technique the analyst rejected")
        detection = doc.get("detection") if isinstance(doc.get("detection"), dict) else {}
        seen = set()
        for value in _detection_values(detection):
            key = _plain(value)
            if key in wanted["strings"] and key not in seen:
                seen.add(key)
                depart("value", f"it detects on '{wanted['strings'][key]}', which the analyst rejected")
    return out


def format_departures(departures: list) -> str:
    """The departures as the reason given to the model for its one rewrite, and to the analyst."""
    return "\n".join(f'- Rule {d["rule"]} "{d["title"]}": {d["message"]}.' for d in departures)
