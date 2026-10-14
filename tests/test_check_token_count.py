"""Tests for Change 49's live check (`eval/check_token_count.py`): is the laptop's count of a request ever below
what Ollama counts by more than the template allowance? Only the verdict is tested here - the check itself sends
requests and is run by hand, one request at a time. Offline."""

from __future__ import annotations

from eval.check_token_count import verdict


def test_within_the_allowance_passes_and_beyond_it_fails():
    rows = [{"name": "a", "ours": 100, "ollama": 120}, {"name": "b", "ours": 2000, "ollama": 2010}]
    assert verdict(rows, allowance=64) == (True, [])
    rows.append({"name": "c", "ours": 500, "ollama": 600})
    ok, over = verdict(rows, allowance=64)
    assert not ok and over == ["c"]


def test_counting_more_than_ollama_is_safe():
    assert verdict([{"name": "a", "ours": 900, "ollama": 700}], allowance=64) == (True, [])


def test_a_request_without_ollamas_count_cannot_pass():
    ok, over = verdict([{"name": "a", "ours": 10, "ollama": None}], allowance=64)
    assert not ok and over == ["a"]
