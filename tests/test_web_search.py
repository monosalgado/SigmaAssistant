"""Tests for Change 45, part 1: the local web search (user 2026-10-06: "start building the stage"; design in the log).

Ollama's web search API (`POST https://ollama.com/api/web_search`, the key from `.env`, 5 results). The search never
raises: its record holds the status, the results, an error and whether a limit was hit (the free account answered
~25 searches per hour and ~50 per "session" in the probe), never the key. Each query's answer is saved, so the same
query is not sent twice; offline (the evaluation's saved file), nothing is ever sent. Offline tests: a stand-in session.
"""

from __future__ import annotations

from backend.telemetry import TELEMETRY
from backend.web_search import OllamaWebSearch


class _Response:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        return self._body


class _Session:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append({"url": url, "json": json, "headers": headers})
        return self.responses.pop(0)


PAGE = {"title": "T", "url": "https://a.example/x", "content": "page text"}


def test_a_search_posts_the_query_with_the_key_and_returns_the_results(tmp_path):
    session = _Session(_Response(200, {"results": [PAGE]}))
    out = OllamaWebSearch("secret-key", cache_path=tmp_path / "c.jsonl", session=session).search("foo exploit")
    call = session.calls[0]
    assert call["url"] == "https://ollama.com/api/web_search"
    assert call["json"] == {"query": "foo exploit", "max_results": 5}
    assert call["headers"]["Authorization"] == "Bearer secret-key"
    assert out["results"] == [PAGE] and out["error"] is None and not out["limited"] and not out["cached"]
    assert "secret-key" not in repr(out)


def test_a_limit_is_recorded_not_raised_and_not_saved(tmp_path):
    body = {"error": "you have reached your web search hourly request limit, upgrade for higher limits"}
    searcher = OllamaWebSearch("secret-key", cache_path=tmp_path / "c.jsonl",
                               session=_Session(_Response(429, body), _Response(200, {"results": [PAGE]})))
    out = searcher.search("q")
    assert out["limited"] and out["results"] == [] and "hourly" in out["error"] and "secret-key" not in repr(out)
    assert searcher.search("q")["results"] == [PAGE]          # the error was not saved: asked again


def test_a_network_failure_is_recorded_not_raised(tmp_path):
    class _Broken:
        def post(self, *a, **k):
            raise ConnectionError("no route to host")
    out = OllamaWebSearch("k", cache_path=tmp_path / "c.jsonl", session=_Broken()).search("q")
    assert out["results"] == [] and "ConnectionError" in out["error"] and not out["limited"]


def test_the_same_query_is_answered_from_the_saved_file(tmp_path):
    path = tmp_path / "c.jsonl"
    session = _Session(_Response(200, {"results": [PAGE]}))
    OllamaWebSearch("k", cache_path=path, session=session).search("q")
    again = OllamaWebSearch("k", cache_path=path, session=_Session()).search("q")   # a new searcher, same file
    assert again["results"] == [PAGE] and again["cached"] and len(session.calls) == 1


def test_offline_never_sends_and_records_a_missing_query(tmp_path):
    path = tmp_path / "snap.jsonl"
    OllamaWebSearch("k", cache_path=path, session=_Session(_Response(200, {"results": [PAGE]}))).search("saved q")
    offline = OllamaWebSearch(None, cache_path=path, offline=True, session=_Session())
    assert offline.search("saved q")["results"] == [PAGE]
    missing = offline.search("other q")
    assert missing["results"] == [] and missing["error"] == "not in the saved file"


def test_each_sent_search_has_a_telemetry_record(tmp_path):
    TELEMETRY.reset()
    OllamaWebSearch("k", cache_path=tmp_path / "c.jsonl",
                    session=_Session(_Response(200, {"results": [PAGE]}))).search("q")
    calls = TELEMETRY.as_dicts()
    assert len(calls) == 1 and calls[0]["operation"] == "web_search" and calls[0]["ok"]
