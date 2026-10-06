"""Web search for the local pipeline (Change 45): Ollama's web search API.

The web enrichment stage was a silent no-op once the pipeline went all-local - only the Gemini client could search.
Ollama's API (`POST https://ollama.com/api/web_search`, a free account's key in `.env` as `OLLAMA_API_KEY`) returns
each result's title, URL and page text. Only the query leaves the machine.

A search never raises: its record holds the status, the results, an error and whether a limit was hit (the free
account answered ~25 searches per hour and ~50 per "session" in the probe, 2026-10-06) - never the key. Each answer
is saved per query in a JSON-lines file, so the same query is not sent twice; offline (the evaluation's saved file),
nothing is ever sent and a query not in the file is recorded as missing.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from backend.telemetry import TELEMETRY

ENDPOINT = "https://ollama.com/api/web_search"
MAX_RESULTS = 5


class OllamaWebSearch:
    def __init__(self, api_key: Optional[str], cache_path=None, offline: bool = False, session=None,
                 max_results: int = MAX_RESULTS, timeout: float = 60):
        self._key = api_key or ""
        self.cache_path = Path(cache_path) if cache_path else None
        self.offline = offline
        self._session = session
        self.max_results = max_results
        self.timeout = timeout
        self._saved = self._load()

    def _load(self) -> dict:
        saved = {}
        if self.cache_path and self.cache_path.exists():
            for line in self.cache_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    record = json.loads(line)
                    if not record.get("error"):
                        saved[record["query"]] = record["results"]
        return saved

    def _save(self, query: str, results: list) -> None:
        self._saved[query] = results
        if self.cache_path:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with self.cache_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"query": query, "results": results, "error": None,
                                    "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S")}) + "\n")

    def search(self, query: str) -> dict:
        """{"results": [{"title", "url", "content"}], "status", "error", "limited", "cached"}."""
        if query in self._saved:
            return {"results": self._saved[query], "status": 200, "error": None, "limited": False, "cached": True}
        if self.offline:
            return {"results": [], "status": None, "error": "not in the saved file", "limited": False, "cached": False}
        session = self._session
        if session is None:
            import requests
            session = requests
        started = time.monotonic()
        try:
            response = session.post(ENDPOINT, json={"query": query, "max_results": self.max_results},
                                    headers={"Authorization": f"Bearer {self._key}"}, timeout=self.timeout)
            status = response.status_code
            try:
                body = response.json()
            except ValueError:
                body = {}
            results = [{"title": r.get("title", ""), "url": r.get("url", ""), "content": r.get("content", "")}
                       for r in (body.get("results") or [])] if status == 200 else []
            error = None if status == 200 else str(body.get("error") or f"HTTP {status}")[:300]
        except Exception as exc:  # noqa: BLE001 - recorded, not raised
            status, results, error = None, [], f"{type(exc).__name__}: {exc}"[:300]
        if error and self._key:
            error = error.replace(self._key, "<key>")
        TELEMETRY.record(backend="ollama-web", tier="web", model="web_search", operation="web_search",
                         latency_s=time.monotonic() - started, prompt_chars=len(query),
                         response_chars=sum(len(r["content"] or "") for r in results), ok=error is None, error=error)
        if error is None:
            self._save(query, results)
        return {"results": results, "status": status, "error": error, "cached": False,
                "limited": status == 429 and "limit" in (error or "")}
