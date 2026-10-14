"""Base class for all pipeline stages."""

from abc import ABC, abstractmethod
from typing import Any, Callable, Optional
import json
import time

from backend.llm_client import PromptTooLarge
from backend.telemetry import stage_scope


# Upper bound on how much extracted source text a stage puts into its prompt.
# The attack-vector and analysis stages used to read only the first 8000 and
# 4000 characters. On pages that open with site navigation, that window held
# no article at all, and the attack-vector stage fell back on its own prompt
# examples (defect 15). 100,000 characters covers the longest text in the
# evaluation corpus (79,800) at roughly 25k tokens, well inside the 262k
# context the Spark serves qwen3-coder with.
SOURCE_TEXT_MAX_CHARS = 100_000

# Kept in a repaired answer: the escapes a path never contains. \b \f \n \r \t are doubled too - in an
# answer that already failed on a stray backslash, "C:\temp" is a folder, not "C:" + a tab.
_KEPT_ESCAPES = set('"\\/')
_HEX = set("0123456789abcdefABCDEF")


def repair_json_escapes(text: str) -> str:
    """Double the backslashes of an answer JSON could not read, so it reads as the model wrote it (Change 37).

    Models write Windows paths and regexes (C:\\Windows, \\d+) inside JSON strings with single
    backslashes; one such backslash made the whole answer unreadable ("Invalid \\escape") and the
    stage fell back to its empty default - the analysis stage lost its log-source recommendation this
    way in 2-4 of 60 tuning cases per run. Kept: \\" \\\\ \\/ and a real \\uXXXX; every other backslash is
    doubled. Called only on an answer that already failed to parse.
    """
    out, i, n = [], 0, len(text)
    while i < n:
        if text[i] != "\\":
            out.append(text[i])
            i += 1
            continue
        nxt = text[i + 1] if i + 1 < n else ""
        if nxt and nxt in _KEPT_ESCAPES:
            out.append(text[i:i + 2])
            i += 2
        elif nxt == "u" and all(c in _HEX for c in text[i + 2:i + 6]) and i + 6 <= n:
            out.append(text[i:i + 6])
            i += 6
        else:
            out.append("\\\\")
            i += 1
    return "".join(out)


class PipelineStage(ABC):
    """Abstract base class for pipeline stages."""

    name: str = "base"
    description: str = "Base stage"

    def __init__(self, client, model_name: str = ""):
        self.client = client
        self.model_name = model_name or getattr(client, "model_name", "")

    @abstractmethod
    def run(self, context: dict) -> dict:
        """Execute this stage. Receives and returns the pipeline context dict."""
        pass

    def llm_call(
        self,
        prompt: str,
        temperature: float = 0.0,
        json_mode: bool = True,
        media_parts: list = None,
        max_retries: int = 3,
        fast: bool = False,
        economy: bool = False,
    ) -> str:
        """Make an LLM call with retry logic and optional JSON mode.

        Routing (Hybrid mode — ECONOMY_PROVIDER=ollama):
            economy=True  → Spark / Ollama (qwen3-coder:30b)
                            classify, conversational, poc, analysis, attack_vector,
                            review, logsource, extract, ttp_map, validate, translator
            fast=True     → Gemini fast (gemini-2.5-flash-lite)  — web search only
            default       → Gemini primary (gemini-2.5-flash)
                            rule generation, optimization, image transcription

        Pure Gemini mode (no ECONOMY_PROVIDER): economy/fast/default all go
        through Gemini at the corresponding tier.
        """
        for attempt in range(max_retries + 1):
            try:
                # Labels the telemetry record with this stage, including a failed
                # call and any fallback the hybrid client makes to Gemini.
                with stage_scope(self.name):
                    return self.client.generate(
                        prompt=prompt,
                        temperature=temperature,
                        json_mode=json_mode,
                        media_parts=media_parts,
                        fast=fast,
                        economy=economy,
                    )
            except PromptTooLarge:
                raise  # Change 49: not sent; resending would be refused again (its token count can contain "429")
            except Exception as e:
                err_str = str(e)
                is_retryable = (
                    "429" in err_str
                    or "RESOURCE_EXHAUSTED" in err_str
                    or "503" in err_str
                    or "UNAVAILABLE" in err_str
                    or "high demand" in err_str.lower()
                    or "overloaded" in err_str.lower()
                )
                if is_retryable and attempt < max_retries:
                    wait_time = (2 ** attempt) * 5  # 5s, 10s — give Gemini time to recover
                    print(f"[{self.name}] Gemini unavailable (attempt {attempt + 1}/{max_retries + 1}). Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    raise

    def source_text(self, text: str) -> str:
        """The part of the extracted source this stage may put in its prompt.

        A cut is logged, so a page longer than the window cannot silently lose
        its end the way the old fixed windows lost everything after the start.
        """
        if len(text) > SOURCE_TEXT_MAX_CHARS:
            print(f"[{self.name}] Source text cut from {len(text)} to "
                  f"{SOURCE_TEXT_MAX_CHARS} characters")
            return text[:SOURCE_TEXT_MAX_CHARS]
        return text

    def parse_json(self, text: str) -> Any:
        """Parse JSON from LLM response, handling common issues."""
        text = text.strip()
        # Strip markdown code fences if present
        if text.startswith("```"):
            lines = text.split("\n")
            lines = lines[1:]  # remove opening fence
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines)
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            if "escape" not in str(exc):
                raise
            # Change 37: repair only the backslashes JSON cannot read; an answer that already
            # parsed never reaches this line.
            print(f"[{self.name}] repaired invalid JSON escapes ({exc})")
            return json.loads(repair_json_escapes(text))
