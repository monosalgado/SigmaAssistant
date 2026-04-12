"""
Unified LLM client abstraction for SigmaAssistant.
Supports Gemini (cloud) and Ollama (local) as interchangeable backends.
Switch via LLM_PROVIDER env variable: "gemini" or "ollama".
"""

from __future__ import annotations
import os


class LLMClient:
    """Abstract base class for all LLM backends."""

    model_name: str = ""

    def generate(
        self,
        prompt: str,
        temperature: float = 0.0,
        json_mode: bool = True,
        media_parts: list = None,
    ) -> str:
        raise NotImplementedError

    def make_image_part(self, file_path: str, mime_type: str):
        """Return a backend-specific image part object, or None if unsupported."""
        return None


class GeminiLLMClient(LLMClient):
    """Gemini backend using the google-genai SDK."""

    def __init__(self, api_key: str, model_name: str):
        from google import genai
        self._genai_client = genai.Client(api_key=api_key)
        self.model_name = model_name

    def generate(
        self,
        prompt: str,
        temperature: float = 0.0,
        json_mode: bool = True,
        media_parts: list = None,
    ) -> str:
        from google.genai import types

        config = types.GenerateContentConfig(temperature=temperature)
        if json_mode:
            config.response_mime_type = "application/json"

        contents = [prompt] + (media_parts or [])
        response = self._genai_client.models.generate_content(
            model=self.model_name,
            contents=contents,
            config=config,
        )
        return response.text

    def make_image_part(self, file_path: str, mime_type: str):
        """Return a Gemini Part for multimodal image input."""
        from google.genai import types
        with open(file_path, "rb") as f:
            data = f.read()
        return types.Part.from_bytes(data=data, mime_type=mime_type)


class OllamaLLMClient(LLMClient):
    """Ollama backend via the OpenAI-compatible local API."""

    def __init__(self, base_url: str, model_name: str):
        from openai import OpenAI
        self._openai = OpenAI(
            base_url=f"{base_url.rstrip('/')}/v1",
            api_key="ollama",  # Ollama doesn't need a real key
        )
        self.model_name = model_name
        self.base_url = base_url

    def generate(
        self,
        prompt: str,
        temperature: float = 0.0,
        json_mode: bool = True,
        media_parts: list = None,
    ) -> str:
        kwargs = dict(
            model=self.model_name,
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
        )
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        response = self._openai.chat.completions.create(**kwargs)
        return response.choices[0].message.content

    def make_image_part(self, file_path: str, mime_type: str):
        """Image transcription not supported for text-only Ollama models."""
        return None


def create_llm_client() -> LLMClient:
    """
    Factory function — reads LLM_PROVIDER from environment and returns
    the appropriate configured client.

    Environment variables:
        LLM_PROVIDER     : "gemini" (default) or "ollama"
        GEMINI_API_KEY   : required when provider=gemini
        GEMINI_MODEL     : model name (default: gemini-2.5-flash)
        OLLAMA_BASE_URL  : Ollama server URL (default: http://localhost:11434)
        OLLAMA_MODEL     : model name (default: qwen2.5:14b)
    """
    from dotenv import load_dotenv
    load_dotenv()

    provider = os.getenv("LLM_PROVIDER", "gemini").lower().strip()

    if provider == "ollama":
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        model = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
        print(f"[LLM] Backend: Ollama — {model} @ {base_url}")
        return OllamaLLMClient(base_url, model)

    else:  # default: gemini
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in environment / .env file")
        model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        print(f"[LLM] Backend: Gemini — {model}")
        return GeminiLLMClient(api_key, model)
