"""Analyses saved in the session while the analyst reviews them (plan Phase 3/4).

Design decision 2 (user, 2026-09-26): the analysis waiting for the analyst's review is
kept in the session record persisted to `data/sessions.json`, so reviewing can take a
while and a page reload does not lose it. The checkpoint is an assistant message with
the saved analysis (`state`), the Analysis panel's data and a status:

    awaiting_review -> generating -> generated     (back to awaiting_review on failure)

Each analysis is generated from once. These functions only touch the message list;
`backend/main.py` saves the sessions.
"""

from __future__ import annotations

AWAITING, GENERATING, GENERATED = "awaiting_review", "generating", "generated"

READY_TEXT = ("The analysis is ready. Check what the model understood in the Analysis panel - "
              "confirm or reject each item, change the log source if it is wrong - then generate the rules.")


class AnalysisNotFound(KeyError):
    """No analysis with that id in the session."""


class AnalysisNotAwaiting(ValueError):
    """The analysis is being generated from, or already was."""


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
    if msg["status"] != AWAITING:
        raise AnalysisNotAwaiting(f"analysis {analysis_id} is {msg['status']}")
    msg["status"] = GENERATING
    history = messages[:i]
    if history and history[-1].get("role") == "user":
        history = history[:-1]
    return msg["state"], history


def finish_generation(messages: list, analysis_id: str, result: dict) -> None:
    """Record the analyst's review on the analysis and append the rules."""
    msg = messages[_find(messages, analysis_id)]
    msg["status"] = GENERATED
    msg["review"] = (result.get("pipeline_metadata") or {}).get("analyst_review")
    messages.append({
        "role": "assistant",
        "content": result.get("rule", ""),
        "context": result.get("context", {}),
        "pipeline_metadata": result.get("pipeline_metadata"),
        "analysis_id": analysis_id,
    })


def abandon_generation(messages: list, analysis_id: str) -> None:
    """A generation that failed: the analysis waits for the analyst again."""
    messages[_find(messages, analysis_id)]["status"] = AWAITING


def reset_interrupted(sessions: dict) -> None:
    """At start-up: a generation cut by a restart can be run again."""
    for messages in sessions.values():
        for msg in messages:
            if msg.get("status") == GENERATING:
                msg["status"] = AWAITING


def public_messages(messages: list) -> list:
    """The messages for the browser: without the saved analysis, which only the server needs."""
    return [{k: v for k, v in msg.items() if k != "state"} for msg in messages]
