"""
Unified LLM client abstraction for SigmaAssistant.
Supports Gemini (cloud) and Ollama/LM Studio (local) as interchangeable backends.
Switch via LLM_PROVIDER env variable: "gemini" or "ollama".

Gemini three-tier model support:
  - Primary   (GEMINI_MODEL):         Best model — only for rule generation.
  - Fast      (GEMINI_FAST_MODEL):    Mid-tier  — attack vector extraction, threat analysis.
  - Economy   (GEMINI_ECONOMY_MODEL): Cheapest  — classification, PoC scan, review, chat.

  Typical free-tier assignment:
    primary  = gemini-2.5-flash      (~1 call/request, highest quality)
    fast     = gemini-2.5-flash-lite (~2 calls/request)
    economy  = gemini-2.0-flash      (~4 calls/request, most quota headroom)
"""

from __future__ import annotations
import os
import time
import threading
from collections import deque


# ---------------------------------------------------------------------------
# Rate limiter (token bucket) — prevents self-inflicted 429s on Gemini free tier
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Simple sliding-window rate limiter.

    Guarantees at most `max_calls` requests per `window_seconds`. If a call
    would exceed the limit, it blocks until the oldest call ages out of the
    window. Thread-safe. Shared across all stages via a single GeminiLLMClient.
    """

    def __init__(self, max_calls: int, window_seconds: float, label: str = "rate-limiter"):
        self.max_calls = max_calls
        self.window = window_seconds
        self.label = label
        self._timestamps: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                # Drop timestamps older than the window
                while self._timestamps and (now - self._timestamps[0]) >= self.window:
                    self._timestamps.popleft()
                if len(self._timestamps) < self.max_calls:
                    self._timestamps.append(now)
                    return
                wait = self.window - (now - self._timestamps[0])
            wait = max(wait, 0.05)
            print(f"[{self.label}] Quota window full ({self.max_calls}/{self.window:.0f}s). "
                  f"Sleeping {wait:.1f}s to avoid 429")
            time.sleep(wait)


class LLMClient:
    """Abstract base class for all LLM backends."""

    model_name: str = ""
    fast_model_name: str = ""
    economy_model_name: str = ""

    def generate(
        self,
        prompt: str,
        temperature: float = 0.0,
        json_mode: bool = True,
        media_parts: list = None,
        fast: bool = False,
        economy: bool = False,
    ) -> str:
        raise NotImplementedError

    def web_search(self, query: str) -> dict:
        """Search the web and return enriched context + source URLs.
        Returns: {"text": str, "sources": [{"url": str, "title": str}]}
        Override in subclasses that support web search.
        """
        return {"text": "", "sources": []}

    def make_image_part(self, file_path: str, mime_type: str):
        """Return a backend-specific image part object, or None if unsupported."""
        return None


class GeminiLLMClient(LLMClient):
    """Gemini backend using the google-genai SDK with three-tier model support."""

    def __init__(self, api_key: str, model_name: str, fast_model_name: str = None, economy_model_name: str = None):
        from google import genai
        self._genai_client = genai.Client(api_key=api_key)
        self.model_name = model_name
        self.fast_model_name = fast_model_name or model_name
        self.economy_model_name = economy_model_name or fast_model_name or model_name

        # Per-tier sliding-window rate limiters (Gemini free-tier RPM safety).
        # Values default to Gemini 2.5 free-tier published limits — conservative
        # by 1 call to leave headroom for the web-search grounding call.
        primary_rpm = int(os.getenv("GEMINI_PRIMARY_RPM", "9"))   # 2.5-flash = 10 RPM
        fast_rpm    = int(os.getenv("GEMINI_FAST_RPM",    "14"))  # 2.5-flash-lite = 15 RPM
        economy_rpm = int(os.getenv("GEMINI_ECONOMY_RPM", "29"))  # 2.0-flash = 30 RPM
        self._limiters = {
            "primary": _RateLimiter(primary_rpm, 60.0, f"gemini-primary ({model_name})"),
            "fast":    _RateLimiter(fast_rpm,    60.0, f"gemini-fast ({self.fast_model_name})"),
            "economy": _RateLimiter(economy_rpm, 60.0, f"gemini-economy ({self.economy_model_name})"),
        }

    def generate(
        self,
        prompt: str,
        temperature: float = 0.0,
        json_mode: bool = True,
        media_parts: list = None,
        fast: bool = False,
        economy: bool = False,
    ) -> str:
        from google.genai import types

        # Three-tier model selection: economy → fast → primary
        if economy:
            model = self.economy_model_name
            tier = "economy"
        elif fast:
            model = self.fast_model_name
            tier = "fast"
        else:
            model = self.model_name
            tier = "primary"

        config = types.GenerateContentConfig(temperature=temperature)
        if json_mode:
            config.response_mime_type = "application/json"

        contents = [prompt] + (media_parts or [])
        # Pre-flight RPM check — block instead of firing and getting a 429.
        self._limiters[tier].acquire()
        response = self._genai_client.models.generate_content(
            model=model,
            contents=contents,
            config=config,
        )
        return response.text

    def web_search(self, query: str) -> dict:
        """Use Gemini's built-in Google Search grounding to search the web.
        Returns enriched text and source URLs from real Google Search results.
        """
        from google.genai import types

        prompt = (
            f"Search the web for the following and provide a detailed technical summary "
            f"focused on indicators of compromise (IoCs), exploit details, affected software, "
            f"detection guidance, and any code snippets or commands used in the attack:\n\n"
            f"{query}"
        )

        import time
        max_retries = 3
        for attempt in range(max_retries + 1):
            try:
                config = types.GenerateContentConfig(
                    tools=[types.Tool(google_search=types.GoogleSearch())],
                    temperature=0.0,
                )

                # Use primary model — web search is critical for downstream
                # context quality, so we use the best model for synthesis.
                # Pre-flight RPM check against the same primary bucket.
                self._limiters["primary"].acquire()
                response = self._genai_client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=config,
                )

                # Extract source URLs from grounding metadata
                sources = []
                seen_urls = set()
                if hasattr(response, "candidates") and response.candidates:
                    gm = getattr(response.candidates[0], "grounding_metadata", None)
                    if gm:
                        chunks = getattr(gm, "grounding_chunks", []) or []
                        for chunk in chunks:
                            web = getattr(chunk, "web", None)
                            if web:
                                url = getattr(web, "uri", "")
                                title = getattr(web, "title", "")
                                if url and url not in seen_urls:
                                    seen_urls.add(url)
                                    real_url = self._resolve_redirect(url)
                                    sources.append({"url": real_url, "title": title})

                return {
                    "text": response.text or "",
                    "sources": sources,
                }

            except Exception as e:
                err_str = str(e)
                is_retryable = (
                    "429" in err_str
                    or "RESOURCE_EXHAUSTED" in err_str
                    or "503" in err_str
                    or "UNAVAILABLE" in err_str
                    or "high demand" in err_str.lower()
                )
                if is_retryable and attempt < max_retries:
                    wait_time = (2 ** attempt) * 5
                    print(f"[LLM] Web search rate-limited (attempt {attempt + 1}/{max_retries + 1}). Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    print(f"[LLM] Google Search grounding failed: {e}")
                    return {"text": "", "sources": []}

    @staticmethod
    def _resolve_redirect(url: str) -> str:
        """Resolve Google's grounding-api-redirect URLs to real destinations."""
        if "grounding-api-redirect" not in url:
            return url
        try:
            import requests
            resp = requests.head(url, allow_redirects=True, timeout=5)
            return resp.url
        except Exception:
            return url  # Return the redirect URL if resolution fails

    def make_image_part(self, file_path: str, mime_type: str):
        """Return a Gemini Part for multimodal image input."""
        from google.genai import types
        with open(file_path, "rb") as f:
            data = f.read()
        return types.Part.from_bytes(data=data, mime_type=mime_type)


class OllamaLLMClient(LLMClient):
    """Ollama/LM Studio backend via the OpenAI-compatible local API."""

    def __init__(self, base_url: str, model_name: str):
        from openai import OpenAI
        self._openai = OpenAI(
            base_url=f"{base_url.rstrip('/')}/v1",
            api_key="ollama",  # Ollama/LM Studio doesn't need a real key
        )
        self.model_name = model_name
        self.fast_model_name = model_name  # Same model for local
        self.base_url = base_url

    def generate(
        self,
        prompt: str,
        temperature: float = 0.0,
        json_mode: bool = True,
        media_parts: list = None,
        fast: bool = False,
        economy: bool = False,
    ) -> str:
        messages = []
        if json_mode:
            messages.append({
                "role": "system",
                "content": "You must respond with valid JSON only. Do not include any text, explanation, or markdown outside the JSON object.",
            })
        messages.append({"role": "user", "content": prompt})

        response = self._openai.chat.completions.create(
            model=self.model_name,
            messages=messages,
            temperature=temperature,
        )
        return response.choices[0].message.content

    def make_image_part(self, file_path: str, mime_type: str):
        """Image transcription not supported for text-only local models."""
        return None


class HybridLLMClient(LLMClient):
    """Routes economy calls to a local Ollama server (via SSH tunnel) and
    all other calls to Gemini. If Ollama is unreachable, economy calls
    automatically fall back to the Gemini fast model — the app never crashes.

    Tier routing:
        economy=True  → Ollama (Spark)          e.g. qwen3-coder:30b
        fast=True     → Gemini fast model       e.g. gemini-2.5-flash-lite
        default       → Gemini primary model    e.g. gemini-2.5-flash
    """

    def __init__(self, gemini: GeminiLLMClient, ollama: OllamaLLMClient):
        self._gemini = gemini
        self._ollama = ollama
        # Expose model names so the rest of the pipeline can log them
        self.model_name = gemini.model_name
        self.fast_model_name = gemini.fast_model_name
        self.economy_model_name = ollama.model_name

    def generate(
        self,
        prompt: str,
        temperature: float = 0.0,
        json_mode: bool = True,
        media_parts: list = None,
        fast: bool = False,
        economy: bool = False,
    ) -> str:
        if economy:
            try:
                return self._ollama.generate(
                    prompt,
                    temperature=temperature,
                    json_mode=json_mode,
                    media_parts=media_parts,
                    fast=fast,
                    economy=economy,
                )
            except Exception as e:
                print(f"[hybrid] Ollama unavailable ({e.__class__.__name__}): {e}")
                print(f"[hybrid] Falling back to Gemini fast model for this call")
                # Fall through to Gemini fast below

        return self._gemini.generate(
            prompt,
            temperature=temperature,
            json_mode=json_mode,
            media_parts=media_parts,
            fast=True if economy else fast,   # economy fallback uses fast tier
            economy=False,
        )

    def web_search(self, query: str) -> dict:
        """Web search always uses Gemini (Google Search grounding)."""
        return self._gemini.web_search(query)

    def make_image_part(self, file_path: str, mime_type: str):
        """Image input always uses Gemini (Ollama doesn't support it)."""
        return self._gemini.make_image_part(file_path, mime_type)


def create_llm_client() -> LLMClient:
    """
    Factory function - reads LLM_PROVIDER from environment and returns
    the appropriate configured client.

    Environment variables:
        LLM_PROVIDER            : "gemini" (default) or "ollama"
        GEMINI_API_KEY          : required when provider=gemini
        GEMINI_MODEL            : primary model    (default: gemini-2.5-flash)
        GEMINI_FAST_MODEL       : mid-tier model   (default: gemini-2.5-flash-lite)
        GEMINI_ECONOMY_MODEL    : cheapest model   (default: gemini-2.0-flash)
        OLLAMA_BASE_URL         : Ollama/LM Studio server URL (default: http://localhost:11434)
        OLLAMA_MODEL            : model name (default: qwen2.5:14b)

    Three-tier Gemini strategy (free-tier optimized):
        primary  → rule generation only           (~1 call/request)
        fast     → attack vector + analysis       (~2 calls/request)
        economy  → classification, PoC, review, chat  (~4 calls/request)
    """
    from dotenv import load_dotenv
    load_dotenv()

    provider = os.getenv("LLM_PROVIDER", "gemini").lower().strip()

    if provider == "ollama":
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        model = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
        print(f"[LLM] Backend: Ollama - {model} @ {base_url}")
        return OllamaLLMClient(base_url, model)

    else:  # default: gemini (or hybrid)
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in environment / .env file")
        model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        fast_model = os.getenv("GEMINI_FAST_MODEL", "gemini-2.5-flash-lite")
        economy_model = os.getenv("GEMINI_ECONOMY_MODEL", "gemini-2.0-flash")

        gemini = GeminiLLMClient(api_key, model, fast_model, economy_model)

        # Hybrid mode: economy calls go to local Ollama (via SSH tunnel)
        economy_provider = os.getenv("ECONOMY_PROVIDER", "").lower().strip()
        if economy_provider == "ollama":
            ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
            ollama_model = os.getenv("OLLAMA_MODEL", "qwen3-coder:30b")
            ollama = OllamaLLMClient(ollama_url, ollama_model)
            print(f"[LLM] Backend: Hybrid")
            print(f"[LLM]   primary  → Gemini {model}")
            print(f"[LLM]   fast     → Gemini {fast_model}")
            print(f"[LLM]   economy  → Ollama {ollama_model} @ {ollama_url}")
            return HybridLLMClient(gemini, ollama)

        print(f"[LLM] Backend: Gemini - primary={model}, fast={fast_model}, economy={economy_model}")
        return gemini
