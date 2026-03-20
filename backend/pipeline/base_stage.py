"""Base class for all pipeline stages."""

from abc import ABC, abstractmethod
from typing import Any, Callable, Optional
import json
import time


class PipelineStage(ABC):
    """Abstract base class for pipeline stages."""

    name: str = "base"
    description: str = "Base stage"

    def __init__(self, client, model_name: str):
        self.client = client
        self.model_name = model_name

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
        max_retries: int = 2,
    ) -> str:
        """Make an LLM call with retry logic and optional JSON mode."""
        from google.genai import types

        config = types.GenerateContentConfig(
            temperature=temperature,
        )
        if json_mode:
            config.response_mime_type = "application/json"

        contents = [prompt]
        if media_parts:
            contents.extend(media_parts)

        for attempt in range(max_retries + 1):
            try:
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=contents,
                    config=config,
                )
                return response.text
            except Exception as e:
                err_str = str(e)
                if ("429" in err_str or "RESOURCE_EXHAUSTED" in err_str) and attempt < max_retries:
                    wait_time = (2 ** attempt) * 2
                    print(f"[{self.name}] Rate limit hit. Retrying in {wait_time}s (attempt {attempt + 1})")
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
