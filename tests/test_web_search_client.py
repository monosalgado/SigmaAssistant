"""Tests for Change 45, part 2: the local client searches the web when a key is set (user 2026-10-06).

`OllamaLLMClient.web_search` used to inherit the base no-op, so the web stage silently did nothing all-local. With
`OLLAMA_API_KEY` in the environment, `create_llm_client` gives the client an `OllamaWebSearch` that saves its answers in
`data/web_cache.jsonl`; `web_search` returns the old `{"text", "sources"}` plus the raw `results`, the error and whether
a limit was hit. Without a key, the old no-op. Offline: a stand-in searcher.
"""

from __future__ import annotations

from pathlib import Path

from backend.llm_client import OllamaLLMClient, create_llm_client

PAGE = {"title": "T", "url": "https://a.example/x", "content": "page text"}


class _Searcher:
    def __init__(self):
        self.queries = []

    def search(self, query):
        self.queries.append(query)
        return {"results": [PAGE], "status": 200, "error": None, "limited": False, "cached": False}


def test_with_a_searcher_the_client_returns_the_results_and_their_sources():
    searcher = _Searcher()
    client = OllamaLLMClient("http://localhost:11434", "m", web_searcher=searcher)
    out = client.web_search("foo exploit")
    assert searcher.queries == ["foo exploit"]
    assert out["results"] == [PAGE] and out["sources"] == [{"url": PAGE["url"], "title": PAGE["title"]}]
    assert out["text"] == "" and out["error"] is None and out["limited"] is False


def test_without_a_searcher_the_old_no_op_stays():
    assert OllamaLLMClient("http://localhost:11434", "m").web_search("q") == {"text": "", "sources": []}


def test_create_llm_client_gives_the_local_client_a_searcher_only_with_a_key(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_API_KEY", "k")
    client = create_llm_client()
    assert client._web_searcher is not None
    assert Path(client._web_searcher.cache_path).name == "web_cache.jsonl"
    assert client._web_searcher.offline is False
    monkeypatch.setenv("OLLAMA_API_KEY", "")
    assert create_llm_client()._web_searcher is None
