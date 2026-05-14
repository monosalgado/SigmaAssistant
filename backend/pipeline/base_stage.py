"""Base class for all pipeline stages."""

from abc import ABC, abstractmethod
from typing import Any, Callable, Optional
import json
import time


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
                return self.client.generate(
                    prompt=prompt,
                    temperature=temperature,
                    json_mode=json_mode,
                    media_parts=media_parts,
                    fast=fast,
                    economy=economy,
                )
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
        return json.loads(text)
