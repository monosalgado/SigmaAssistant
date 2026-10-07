"""Analyses saved in the session while the analyst reviews them (plan Phase 3/4).

Design decision 2 (user, 2026-09-26): the analysis waiting for the analyst's review is
kept in the session record persisted to `data/sessions.json`, so reviewing can take a
while and a page reload does not lose it. The checkpoint is an assistant message with
the saved analysis (`state`), the Analysis panel's data and a status:

    awaiting_review -> generating -> generated     (back to awaiting_review on failure)

Change 46 (user, 2026-10-07): the rules come first. The web app saves the analysis at the checkpoint and generation
goes on (`first_pass_events`); the analyst's corrections then regenerate from the saved analysis. Every set of rules is
kept as a numbered version (1 = automatic), so a generated analysis can be generated from again (generated ->
generating -> generated); a failed generation leaves the versions as they were. These functions only touch the
message list; `backend/main.py` saves the sessions.
"""

from __future__ import annotations

from backend.pipeline.analyst_review import review_from_record

AWAITING, GENERATING, GENERATED = "awaiting_review", "generating", "generated"

READY_TEXT = ("The analysis is ready. Check what the model understood in the Analysis panel - "
              "confirm or reject each item, change the log source if it is wrong - then generate the rules.")


class AnalysisNotFound(KeyError):
    """No analysis with that id in the session."""


class AnalysisNotAwaiting(ValueError):
    """The analysis is being generated from."""


def checkpoint_message(analysis_id: str, checkpoint: dict) -> dict:
    """The session message for an analysis waiting for the analyst's review."""
    return {
        "role": "assistant",
        "content": READY_TEXT,
        "analysis_id": analysis_id,
        "status": AWAITING,
        "state": checkpoint["state"],
        "pipeline_metadata": checkpoint["pipeline_metadata"],
        "context": checkpoint["context"],
    }


def _find(messages: list, analysis_id: str) -> int:
    for i, msg in enumerate(messages):
        if msg.get("analysis_id") == analysis_id and "status" in msg:
            return i
    raise AnalysisNotFound(analysis_id)


def start_generation(messages: list, analysis_id: str) -> tuple:
    """Mark the analysis as being generated from; returns (saved analysis, conversation).

    The conversation is what came before the message the analysis answered - what the
    one-pass run passes as history.
    """
    i = _find(messages, analysis_id)
    msg = messages[i]
    if msg["status"] not in (AWAITING, GENERATED):
        raise AnalysisNotAwaiting(f"analysis {analysis_id} is {msg['status']}")
    msg["status"] = GENERATING
    history = messages[:i]
    if history and history[-1].get("role") == "user":
        history = history[:-1]
    return msg["state"], history


def _versions(messages: list, analysis_id: str) -> int:
    return sum(1 for m in messages if m.get("analysis_id") == analysis_id and "version" in m)


def finish_generation(messages: list, analysis_id: str, result: dict) -> int:
    """Record the analyst's review on the analysis and append the rules as the next version; returns its number."""
    msg = messages[_find(messages, analysis_id)]
    msg["status"] = GENERATED
    msg["review"] = (result.get("pipeline_metadata") or {}).get("analyst_review")
    version = _versions(messages, analysis_id) + 1
    messages.append({
        "role": "assistant",
        "content": result.get("rule", ""),
        "context": result.get("context", {}),
        "pipeline_metadata": result.get("pipeline_metadata"),
        "analysis_id": analysis_id,
        "version": version,
        # The corrections behind this version, in words, for the screen and a reload (None: automatic).
        "corrections": corrections_summary(msg["review"]) if msg["review"] else None,
        # The same corrections by position in the saved analysis: the next round starts with them marked.
        "carry_review": review_from_record(msg["review"], msg.get("state") or {}) if msg["review"] else None,
    })
    return version


def abandon_generation(messages: list, analysis_id: str) -> None:
    """A generation that failed: the versions stay as they were (none yet: the analysis waits again)."""
    messages[_find(messages, analysis_id)]["status"] = GENERATED if _versions(messages, analysis_id) else AWAITING


def reset_interrupted(sessions: dict) -> None:
    """At start-up: a generation cut by a restart can be run again."""
    for messages in sessions.values():
        for msg in messages:
            if msg.get("status") == GENERATING:
                msg["status"] = GENERATED if _versions(messages, msg["analysis_id"]) else AWAITING


def saved_analysis_metadata(messages: list, analysis_id: str) -> dict:
    """What the Analysis panel shows for the saved analysis - what the analyst's corrections refer to."""
    return messages[_find(messages, analysis_id)]["pipeline_metadata"]


def generation_failure(result: dict):
    """Why a generation wrote no rules (its last recorded error), or None if it wrote some. "No rules" means the result
    says so (`pre_review_rules` present and empty, M1); a record without the field is taken as it is."""
    meta = result.get("pipeline_metadata") or {}
    if "pre_review_rules" in meta and not meta["pre_review_rules"]:
        errors = [g.get("parse_error") for g in meta.get("generations") or [] if isinstance(g, dict) and g.get("parse_error")]
        return errors[-1] if errors else "no rules were written"
    return None


def record_result(messages: list, analysis_id: str, data: dict):
    """A generation's result: the next version - or, with no rules, nothing: the versions stay as they were, the
    analysis and the corrections are kept, and the browser is told to try again (`retry_analysis_id`). Found in the
    live check, 2026-10-07: a regeneration that failed on a connection error was saved as a version."""
    failure = generation_failure(data)
    if failure:
        abandon_generation(messages, analysis_id)
        data["retry_analysis_id"] = analysis_id
        data["generation_failed"] = failure
        return None
    data["version"] = finish_generation(messages, analysis_id, data)
    return data["version"]


def analysis_message(analysis_id: str, checkpoint: dict) -> dict:
    """The session message for an analysis saved on the way to the rules (Change 46): no chat text of its own."""
    return dict(checkpoint_message(analysis_id, checkpoint), content="", status=GENERATING)


def first_pass_events(messages: list, events, analysis_id: str):
    """The web app's first pass (Change 46), as (event, data) for the browser: the analysis is saved at the
    checkpoint (not sent), the rules become version 1. A failure before the checkpoint is a plain message; after it,
    the analysis is kept so it can be generated from again."""
    saved = False
    for event in events:
        kind, data = event.get("event", "stage"), event.get("data", {})
        if kind == "checkpoint":
            messages.append(analysis_message(analysis_id, data))
            saved = True
            continue
        if kind == "result":
            if saved and data.get("pipeline_metadata") is not None and not generation_failure(data):
                data["version"] = finish_generation(messages, analysis_id, data)
                data["analysis_id"] = analysis_id
                data["analysis_metadata"] = saved_analysis_metadata(messages, analysis_id)
            else:
                messages.append({"role": "assistant", "content": data.get("rule", ""),
                                 "context": data.get("context", {})})
                if saved:
                    abandon_generation(messages, analysis_id)
                    data["retry_analysis_id"] = analysis_id
        yield kind, data


def _count(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def corrections_summary(record: dict) -> str:
    """The analyst's corrections behind a version, in plain words (from `analyst_review`)."""
    if not record:
        return "no corrections"
    words = {"techniques": "technique", "indicators": "indicator", "patterns": "pattern"}
    parts = []
    ls = record.get("logsource")
    if ls:
        parts.append("log source " + " / ".join(v for v in (ls.get("category"), ls.get("product"), ls.get("service")) if v))
    for status in ("rejected", "confirmed"):
        counts = [_count(len((record.get(k) or {}).get(status) or []), w) for k, w in words.items()
                  if (record.get(k) or {}).get(status)]
        if counts:
            parts.append(f"{status} " + ", ".join(counts))
    restored = len((record.get("excluded") or {}).get("restored") or [])
    if restored:
        parts.append("restored " + _count(restored, "string"))
    if record.get("note"):
        parts.append(f"note: {record['note']}")
    return "; ".join(parts) or "no corrections"


def public_messages(messages: list) -> list:
    """The messages for the browser: without the saved analysis, which only the server needs."""
    return [{k: v for k, v in msg.items() if k != "state"} for msg in messages]
