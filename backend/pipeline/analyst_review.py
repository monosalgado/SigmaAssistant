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

Rejected techniques, indicators and attack patterns do not reach generation. A rejected
pattern is not added to the excluded strings: rejecting the bare pattern `sudo` as too broad
does not mean no rule may contain "sudo" (live test, 2026-09-27). A restored excluded string
becomes an attack pattern. A confirmed log source goes first and is marked as the analyst's
decision. Confirming anything else is recorded only.

Code validates the review against the saved lists and SigmaHQ's log source table and
records it; it never decides for the analyst.
"""

from __future__ import annotations

import copy

from backend.pipeline.sigma_logsource import _clean, describe_suggestion, on_table

MAX_NOTE = 2000

# kind -> (where the list lives in the context, the statuses the analyst can give)
_LISTS = {
    "techniques": (("ttp_mapping", "mappings"), {"confirmed", "rejected"}),
    "indicators": (("extraction", "indicators"), {"confirmed", "rejected"}),
    "patterns": (("attack_vector", "payload_signatures"), {"confirmed", "rejected"}),
    "excluded": (("attack_vector", "incidental_artifacts"), {"restored"}),
}
_KINDS = set(_LISTS) | {"logsource", "note"}


class ReviewError(ValueError):
    """A review that does not fit the saved analysis or the spec."""


def _label(kind: str, item) -> str:
    """How the record names an item: the technique ID, the value, the pattern."""
    if not isinstance(item, dict):
        return str(item)
    key = {"techniques": "technique_id", "patterns": "pattern"}.get(kind, "value")
    return str(item.get(key, ""))


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

    # Everything is valid: build the new context.
    out = copy.deepcopy(context)
    record = {kind: {status: [_label(kind, saved[kind][pos]) for pos, s in sorted(decided[kind].items())
                              if s == status]
                     for status in sorted(_LISTS[kind][1])}
              for kind in _LISTS}
    record["logsource"] = None
    record["note"] = note

    kept = {kind: [item for pos, item in enumerate(saved[kind])
                   if decided[kind].get(pos) not in ("rejected", "restored")]
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
    touched = {kind: bool(decided[kind]) for kind in _LISTS}
    touched["patterns"] |= touched["excluded"]
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
