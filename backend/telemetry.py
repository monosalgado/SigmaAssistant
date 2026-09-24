"""Per-call LLM telemetry: token usage, latency, tier routing.

Why this exists
---------------
Before this module the system had no measurement of cost or latency at all, so
C1 (tokens/cost per rule) and C2 (latency per rule per tier) were unmeasurable and
tier-routing claims were unverifiable. Both backends discarded their usage metadata:
Gemini returned `response.text` and Ollama returned
`response.choices[0].message.content`, so the token counts were gone before any
caller could see them.

Why the counts are captured, not estimated
------------------------------------------
Dividing character counts by ~4 is a common shortcut and a poor one: the ratio
varies by tokenizer, language, and how much of the payload is code or base64.
Reporting an estimate as a measurement would not survive scrutiny. Both SDKs
return exact counts; this module records those and reports None when a backend
does not supply them.

Thinking tokens are counted
---------------------------
gemini-2.5-flash is a thinking model. Reasoning tokens are billed at the output
rate but are excluded from `candidates_token_count`, so deriving a total as
prompt + completion undercounts every request by the whole thinking budget.
`summary()` prefers the provider's own `total_token_count` and reports thinking
tokens as their own line.

Missing data is None, never 0
-----------------------------
A call whose token count is unavailable is not a call that used zero tokens.
Summing None as 0 would understate cost while looking precise. `summary()`
therefore reports `calls_without_token_data` alongside the totals, so a partial
total can never be mistaken for a complete one. This mirrors the same decision in
eval/scorers.py.

Recording is always on. The cost is one append to a bounded deque per LLM call,
which is negligible against a network round trip.

Each call is attributed to a stage
----------------------------------
Every call used to record operation="generate", so the stages of one case could
only be told apart by call order, which shifts whenever the PoC stage or a
regeneration runs. `stage_scope()` sets the current stage in a context variable
and `record()` reads it, so the clients need no stage argument and every call made
inside a stage carries its name. Calls made outside any stage record None.
"""

from __future__ import annotations

import threading
from collections import deque
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from typing import Any, Iterator, Optional


# The pipeline stage making the current LLM call. A context variable rather than
# a global: the web server runs requests on worker threads, and each keeps its own.
_current_stage: ContextVar[Optional[str]] = ContextVar("llm_stage", default=None)


@contextmanager
def stage_scope(name: str) -> Iterator[None]:
    """Attribute every LLM call made inside this block to stage `name`."""
    token = _current_stage.set(name)
    try:
        yield
    finally:
        _current_stage.reset(token)


@dataclass
class LLMCall:
    """One LLM API call."""

    backend: str          # "gemini" | "ollama"
    tier: str             # "primary" | "fast" | "economy"
    model: str
    operation: str        # "generate" | "web_search"
    latency_s: float
    prompt_chars: int
    response_chars: int
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    # Gemini 2.5 is a thinking model. Reasoning tokens are billed at the output
    # rate but are NOT included in candidates_token_count, so they are tracked
    # separately; omitting them undercounts cost while looking precise.
    thinking_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    ok: bool = True
    error: Optional[str] = None
    stage: Optional[str] = None  # None = made outside any pipeline stage
    # The answer stopped at the output limit (Change 24). The call itself worked -
    # `ok` stays True - but the model did not finish: a model failure, not an
    # infrastructure one.
    output_limited: bool = False


def extract_gemini_usage(response: Any) -> dict:
    """Read token counts from a google-genai response.

    Returns None values rather than raising: telemetry must never break a
    generation call, and SDK field names change between versions.
    """
    meta = getattr(response, "usage_metadata", None)
    if meta is None:
        return {}
    return {
        "prompt_tokens": getattr(meta, "prompt_token_count", None),
        "completion_tokens": getattr(meta, "candidates_token_count", None),
        "thinking_tokens": getattr(meta, "thoughts_token_count", None),
        "total_tokens": getattr(meta, "total_token_count", None),
    }


def extract_openai_usage(response: Any) -> dict:
    """Read token counts from an OpenAI-compatible response (Ollama, LM Studio)."""
    usage = getattr(response, "usage", None)
    if usage is None:
        return {}
    return {
        "prompt_tokens": getattr(usage, "prompt_tokens", None),
        "completion_tokens": getattr(usage, "completion_tokens", None),
        "total_tokens": getattr(usage, "total_tokens", None),
    }


class LLMTelemetry:
    """Thread-safe, bounded record of LLM calls.

    Bounded because the FastAPI server is long-running; the evaluation runner
    calls `reset()` per case, and a pipeline run makes well under ten calls.
    """

    def __init__(self, maxlen: int = 2000) -> None:
        self._calls: deque = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def record(
        self,
        *,
        backend: str,
        tier: str,
        model: str,
        operation: str,
        latency_s: float,
        prompt_chars: int,
        response_chars: int = 0,
        usage: Optional[dict] = None,
        ok: bool = True,
        error: Optional[str] = None,
        output_limited: bool = False,
    ) -> None:
        usage = usage or {}
        call = LLMCall(
            backend=backend,
            tier=tier,
            model=model,
            operation=operation,
            latency_s=latency_s,
            prompt_chars=prompt_chars,
            response_chars=response_chars,
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            thinking_tokens=usage.get("thinking_tokens"),
            total_tokens=usage.get("total_tokens"),
            ok=ok,
            error=error,
            stage=_current_stage.get(),
            output_limited=output_limited,
        )
        with self._lock:
            self._calls.append(call)

    def reset(self) -> None:
        with self._lock:
            self._calls.clear()

    def calls(self) -> list:
        with self._lock:
            return list(self._calls)

    def as_dicts(self) -> list:
        return [asdict(c) for c in self.calls()]

    def summary(self) -> dict:
        """Aggregate the recorded calls.

        Token totals sum only the calls that reported counts;
        `calls_without_token_data` states how many did not, so a partial total is
        never mistaken for a complete one.
        """
        calls = self.calls()
        by_tier: dict = {}
        missing = 0
        prompt_total = completion_total = thinking_total = grand_total = 0
        counted = 0

        for call in calls:
            bucket = by_tier.setdefault(
                call.tier,
                {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0,
                 "thinking_tokens": 0, "total_tokens": 0,
                 "latency_s": 0.0, "errors": 0, "model": call.model},
            )
            bucket["calls"] += 1
            bucket["latency_s"] += call.latency_s
            if not call.ok:
                bucket["errors"] += 1

            if (call.prompt_tokens is None and call.completion_tokens is None
                    and call.total_tokens is None):
                missing += 1
                continue

            counted += 1
            prompt = call.prompt_tokens or 0
            completion = call.completion_tokens or 0
            thinking = call.thinking_tokens or 0

            # Prefer the provider's own total. Recomputing it as
            # prompt + completion would drop thinking tokens, which Gemini bills
            # but excludes from candidates_token_count.
            if call.total_tokens is not None:
                total = call.total_tokens
            else:
                total = prompt + completion + thinking

            prompt_total += prompt
            completion_total += completion
            thinking_total += thinking
            grand_total += total

            bucket["prompt_tokens"] += prompt
            bucket["completion_tokens"] += completion
            bucket["thinking_tokens"] += thinking
            bucket["total_tokens"] += total

        return {
            "n_calls": len(calls),
            "n_errors": sum(1 for c in calls if not c.ok),
            "calls_output_limited": sum(1 for c in calls if c.output_limited),
            "total_latency_s": round(sum(c.latency_s for c in calls), 3),
            "prompt_tokens": prompt_total if counted else None,
            "completion_tokens": completion_total if counted else None,
            "thinking_tokens": thinking_total if counted else None,
            "total_tokens": grand_total if counted else None,
            "calls_with_token_data": counted,
            "calls_without_token_data": missing,
            "by_tier": by_tier,
        }


TELEMETRY = LLMTelemetry()
