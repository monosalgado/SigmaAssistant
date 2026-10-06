"""Tests for Change 45, part 5: building the evaluation's saved web search answers (user 2026-10-06: "if the max is
50 searches per session how are we going to do the whole run?" - search once per case, save, every run reads the file).

For each case the stage's own query is computed offline; a query already in the output file is skipped; one the
probe already answered with exactly the same query is copied from the probe's file (nothing sent); only the rest is
searched. On the hourly limit the builder waits; on the session limit it stops (a rerun continues). The output file is
the format `OllamaWebSearch` reads, so `run_eval.py --web-snapshots` answers from it. Offline.
"""

from __future__ import annotations

import json

from backend.web_search import OllamaWebSearch
from eval.build_web_snapshots import copy_answer, limit_kind, plan


def _jsonl(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


PAGE = {"title": "T", "url": "https://a.example/x", "content": "page text"}


def test_each_query_is_skipped_copied_or_searched(tmp_path):
    out = _jsonl(tmp_path / "out.jsonl", [{"query": "q saved", "results": [PAGE], "error": None}])
    probe = _jsonl(tmp_path / "probe.jsonl", [
        {"rule_id": "a", "variant": "stage", "query": "q probe", "results": [PAGE], "error": None},
        {"rule_id": "b", "variant": "stage", "query": "q failed", "results": [], "error": "hourly request limit"},
        {"rule_id": "c", "variant": "cve", "query": "q cve only", "results": [PAGE], "error": None}])
    steps = plan(["q saved", "q probe", "q failed", "q cve only", "q new"], out, [probe])
    assert steps == {"q saved": "saved", "q probe": "copy", "q failed": "search", "q cve only": "search",
                     "q new": "search"}


def test_a_copied_answer_is_read_back_by_the_offline_search(tmp_path):
    out = tmp_path / "out.jsonl"
    probe = _jsonl(tmp_path / "probe.jsonl", [
        {"rule_id": "a", "variant": "stage", "query": "q probe", "results": [PAGE], "error": None}])
    copy_answer("q probe", [probe], out)
    assert OllamaWebSearch(None, cache_path=out, offline=True).search("q probe")["results"] == [PAGE]


def test_the_hourly_and_the_session_limits_are_told_apart():
    assert limit_kind("you have reached your web search hourly request limit, upgrade") == "hourly"
    assert limit_kind("you have reached your web search session request limit, upgrade") == "session"
    assert limit_kind("HTTP 500") is None and limit_kind(None) is None


def test_the_builder_waits_out_both_limits():
    # User 2026-10-06: "when it hit the quota ... it can just continue". The session limit reset within ~2 hours that
    # day, so the builder waits it out too (every 30 minutes, at most 12 hours), instead of stopping.
    from eval.build_web_snapshots import LIMIT_WAIT_MAX_S, wait_seconds
    assert wait_seconds("hourly") == 600 and wait_seconds("session") == 1800 and wait_seconds(None) is None
    assert LIMIT_WAIT_MAX_S == 12 * 3600
