"""Tests for Change 49, part 3: the web digest reads the pages in pieces (user 2026-10-08: "we are breaking the spark
and we need to stop that"; all three halts came during a one-call digest with a long prompt).

- Each piece's prompt is <= 16,000 tokens: the report's opening (its first 6,000 tokens) plus as many pages as fit.
  Every kept page is still read in full: the pages keep one numbering across pieces, and a page too long for one piece
  is split at line breaks into parts (`[n] ... (part k of m)`).
- One call per piece; a cut answer keeps its complete items, a failed piece is recorded and the others go on.
- The items of all pieces are checked together against the whole pages (`check_digest`, unchanged); then code drops a
  string the full report already contains (the model now sees only its opening) and an item whose strings were all
  dropped, and an item whose strings all appear in an item already kept from the same page (a duplicate).
- Recorded per piece: page numbers, tokens, error, cut, items proposed; the totals as before.
Offline: a stand-in client and a stand-in counter (one token per word).
"""

from __future__ import annotations

import json
import re

import pytest

from backend.llm_client import OutputLimitReached
from backend.pipeline import prompts, stage_web_enrich
from backend.pipeline.stage_web_enrich import WebEnrichStage

REPORT_WORDS = 50
PAGE_ROOM = 300                    # words of pages per piece, about
# Read before the fixture below replaces them with test sizes.
DEFAULT_PIECE_MAX = getattr(stage_web_enrich, "WEB_PIECE_MAX_TOKENS", None)
DEFAULT_REPORT = getattr(stage_web_enrich, "WEB_REPORT_TOKENS", None)


def _words(text):
    return len(text.split())


def _first_words(text, n):
    m = re.match(r"\s*(?:\S+\s+){%d}" % n, text)
    return text if m is None else text[:m.end()].rstrip()


OVERHEAD = _words(prompts.WEB_DIGEST.format(report="", pages=""))


@pytest.fixture(autouse=True)
def word_counter(monkeypatch):
    monkeypatch.setattr(stage_web_enrich, "count_tokens", _words)
    monkeypatch.setattr(stage_web_enrich, "truncate_to_tokens", _first_words)
    monkeypatch.setattr(stage_web_enrich, "WEB_REPORT_TOKENS", REPORT_WORDS)
    monkeypatch.setattr(stage_web_enrich, "WEB_PIECE_MAX_TOKENS", OVERHEAD + REPORT_WORDS + PAGE_ROOM)


def _page(n, words=120, per_line=10):
    body = [f"p{n}w{j}" for j in range(words)]
    lines = [" ".join(body[i:i + per_line]) for i in range(0, words, per_line)]
    return {"title": f"Page {n}", "url": f"https://site{n}.example/a", "content": "\n".join(lines)}


class _Client:
    """Answers each piece with `answer(prompt)`; records every prompt."""

    def __init__(self, pages, answer=lambda prompt: {"items": []}):
        self.pages, self.answer, self.prompts = pages, answer, []
        self.model_name = "fake"

    def web_search(self, query):
        return {"text": "", "sources": [], "results": self.pages, "error": None, "limited": False}

    def generate(self, prompt, **kwargs):
        self.prompts.append(prompt)
        out = self.answer(prompt)
        if isinstance(out, Exception):
            raise out
        return json.dumps(out)


def _run(client, report="REPORT " + " ".join(f"r{i}" for i in range(200)) + " cmd.exe /c whoami TAILMARK"):
    context = {"original_query": "https://own.example/report", "preprocessed": {
        "original_query": "https://own.example/report", "combined_text": report, "segments": [],
        "url_content": [{"url": "https://own.example/report", "title": "The report"}]}}
    return WebEnrichStage(client, "").run(context)["enrichment"]


def _pages_in(prompt):
    return sorted({int(n) for n in re.findall(r"^\[(\d+)\] ", prompt.split("## Web pages")[1], re.M)})


def test_the_limits_are_below_the_halted_calls():
    assert DEFAULT_PIECE_MAX == 16_000 and DEFAULT_REPORT == 6_000
    assert DEFAULT_PIECE_MAX < 28_099


def test_every_piece_is_within_the_limit_and_every_page_is_read():
    pages = [_page(n) for n in range(1, 6)]
    client = _Client(pages)
    enrichment = _run(client)
    assert len(client.prompts) == 3
    assert all(_words(p) <= stage_web_enrich.WEB_PIECE_MAX_TOKENS for p in client.prompts)
    assert [_pages_in(p) for p in client.prompts] == [[1, 2], [3, 4], [5]]
    sent = " ".join(client.prompts)
    assert all(f"p{n}w{j}" in sent for n in range(1, 6) for j in range(120))
    assert [piece["pages"] for piece in enrichment["digest"]["pieces"]] == [[1, 2], [3, 4], [5]]


def test_a_page_too_long_for_one_piece_is_split_into_parts():
    pages = [_page(1, words=40), _page(2, words=1000)]
    client = _Client(pages)
    _run(client)
    assert all(_words(p) <= stage_web_enrich.WEB_PIECE_MAX_TOKENS for p in client.prompts)
    parts = re.findall(r"^\[2\] Page 2 \(part (\d+) of (\d+)\)$", "\n".join(client.prompts), re.M)
    assert len(parts) >= 4 and {m for _, m in parts} == {str(len(parts))}
    sent = " ".join(client.prompts)
    assert all(f"p2w{j}" in sent for j in range(1000))


def test_a_line_too_long_for_a_piece_is_cut_at_a_token_boundary():
    client = _Client([_page(1, words=900, per_line=900)])
    _run(client)
    assert len(client.prompts) >= 3
    assert all(_words(p) <= stage_web_enrich.WEB_PIECE_MAX_TOKENS for p in client.prompts)
    assert all(f"p1w{j}" in " ".join(client.prompts) for j in range(900))


def test_each_piece_shows_the_reports_opening_only():
    client = _Client([_page(1)])
    _run(client)
    report_part = client.prompts[0].split("## The report")[1].split("## Web pages")[0]
    assert "r0" in report_part and f"r{REPORT_WORDS - 2}" in report_part
    assert "TAILMARK" not in report_part and _words(report_part) <= REPORT_WORDS


def test_items_of_all_pieces_are_checked_against_the_whole_pages():
    pages = [_page(n) for n in range(1, 6)]

    def answer(prompt):
        n = _pages_in(prompt)[-1]
        return {"items": [{"finding": f"from page {n}", "strings": [f"p{n}w3 p{n}w4", "invented.dll"], "source": n}]}
    enrichment = _run(_Client(pages, answer))
    kept = enrichment["digest"]["kept"]
    assert [i["strings"] for i in kept] == [["p2w3 p2w4"], ["p4w3 p4w4"], ["p5w3 p5w4"]]
    assert enrichment["digest"]["proposed"] == 3
    assert sum(d.get("string") == "invented.dll" for d in enrichment["digest"]["dropped"]) == 3


def test_a_failed_piece_does_not_lose_the_others():
    pages = [_page(n) for n in range(1, 6)]

    def answer(prompt):
        n = _pages_in(prompt)[-1]
        if n == 4:
            return RuntimeError("Connection error.")
        if n == 5:
            return OutputLimitReached("cut", partial='{"items": [{"finding": "f5", "strings": ["p5w1 p5w2"], '
                                                      '"source": 5}, {"finding": "half')
        return {"items": [{"finding": f"f{n}", "strings": [f"p{n}w1 p{n}w2"], "source": n}]}
    digest = _run(_Client(pages, answer))["digest"]
    assert [i["finding"] for i in digest["kept"]] == ["f2", "f5"]
    assert [bool(p["error"]) for p in digest["pieces"]] == [False, True, True]
    assert [p["cut"] for p in digest["pieces"]] == [False, False, True]
    assert digest["error"] and digest["cut"] is True


def test_a_string_the_report_already_has_is_dropped():
    page = _page(1)
    page["content"] += "\nthe loader ran cmd.exe /c whoami then TAILMARK and new.dll"

    def answer(prompt):
        return {"items": [
            {"finding": "known and new", "strings": ["cmd.exe /c whoami", "new.dll"], "source": 1},
            {"finding": "all known", "strings": ["TAILMARK"], "source": 1},          # past the report's opening
            {"finding": "a description", "strings": [], "source": 1}]}
    digest = _run(_Client([page], answer))["digest"]
    assert [(i["finding"], i["strings"]) for i in digest["kept"]] == [("known and new", ["new.dll"]),
                                                                       ("a description", [])]
    reasons = [(d.get("string") or d.get("strings"), d["reason"]) for d in digest["dropped"]]
    assert ("cmd.exe /c whoami", "already in the report") in reasons
    assert (["TAILMARK"], "every string is already in the report") in reasons


def test_an_item_repeated_from_another_part_of_the_same_page_is_dropped():
    def answer(prompt):
        return {"items": [{"finding": "the same", "strings": ["p1w0 p1w1"], "source": 1}]}
    client = _Client([_page(1, words=1000)], answer)
    digest = _run(client)["digest"]
    assert len(client.prompts) >= 4 and len(digest["kept"]) == 1
    assert sum(d["reason"] == "duplicate of an item already kept from this page" for d in digest["dropped"]) \
        == len(client.prompts) - 1


def test_the_record_says_what_each_piece_held():
    pages = [_page(n) for n in range(1, 4)]
    digest = _run(_Client(pages))["digest"]
    piece = digest["pieces"][0]
    assert set(piece) >= {"pages", "tokens", "error", "cut", "proposed"}
    assert piece["tokens"] <= stage_web_enrich.WEB_PIECE_MAX_TOKENS
    assert digest["report_tokens"] == REPORT_WORDS and digest["report_tokens_total"] > REPORT_WORDS
