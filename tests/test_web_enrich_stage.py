"""Tests for Change 45, part 3: the web stage filters the results, a digest agent reads them, code checks the digest
(user 2026-10-06: "the model digest, checked, but lets not cap it ... just [an] agent that focus on that").

- Query: the old builder; a CVE ID is kept once (the probe saw `cve-2023-36874 CVE-2023-36874`).
- Filter (code, recorded): the case's own page is dropped; a rule page (rule-site list or Sigma text) is kept and listed
  as a published rule found - or dropped when `exclude_rule_pages` is set (the evaluation: a found human rule would make
  the score measure copying).
- Digest (one model call, `WEB_DIGEST`): what the kept pages add about this attack, each item a finding, exact strings
  and its source. Checked: the source must be a kept page; a string must appear in that page (case-insensitive,
  whitespace collapsed, at least 4 characters) or it is dropped; an item whose strings all fail is dropped; an item with
  no strings is kept. Not capped by code.
- Hand-on: the kept items are appended to the text the attack-vector and analysis stages read, marked as from the web.
Offline: a stand-in client.
"""

from __future__ import annotations

import json

from backend.pipeline import prompts
from backend.pipeline.stage_web_enrich import WebEnrichStage, check_digest, classify_result

OWN = {"title": "The report", "url": "https://www.vendor.example/blog/report/", "content": "the report text itself"}
OTHER = {"title": "Another write-up", "url": "https://other.example/analysis",
         "content": "The loader runs rundll32.exe C:\\ProgramData\\x.dll,Start and contacts evil.example over TLS."}
RULE = {"title": "Kapeka rule", "url": "https://sigma.controlassurance.com/rules/win_kapeka/",
        "content": "title: Kapeka logsource: product: windows detection: selection: condition: selection"}


class _Client:
    def __init__(self, results, digest=None, fail=False):
        self.results, self.digest, self.fail, self.prompts = results, digest, fail, []
        self.model_name = "fake"

    def web_search(self, query):
        self.query = query
        if self.results is None:
            return {"text": "", "sources": [], "results": [], "error": "you have reached your web search hourly "
                    "request limit", "limited": True}
        return {"text": "", "sources": [{"url": r["url"], "title": r["title"]} for r in self.results],
                "results": self.results, "error": None, "limited": False}

    def generate(self, prompt, **kwargs):
        self.prompts.append(prompt)
        if self.fail:
            raise RuntimeError("answer stopped at the output limit")
        return json.dumps(self.digest)


def _context(query="https://www.vendor.example/blog/report"):
    return {"original_query": query, "preprocessed": {
        "original_query": query, "combined_text": "REPORT BODY: the actor used a loader.", "segments": [],
        "url_content": [{"url": "https://www.vendor.example/blog/report", "title": "The report"}]}}


# --- query and filter ---------------------------------------------------------------------------------------------

def test_a_cve_id_is_kept_once_in_the_query():
    stage = WebEnrichStage(None, "")
    query = stage._build_search_query({"original_query": "https://github.com/x/CVE-2023-36874 cve-2023-36874",
                                       "url_content": []})
    assert query.upper().count("CVE-2023-36874") == 1


def test_own_page_and_rule_pages_are_told_apart():
    own = ["https://www.vendor.example/blog/report"]
    assert classify_result(OWN, own) == "own page"
    assert classify_result(RULE, own) == "rule page"
    assert classify_result({**OTHER, "url": "https://detection.fyi/sigmahq/x"}, own) == "rule page"
    assert classify_result(OTHER, own) is None


# --- the digest's check -------------------------------------------------------------------------------------------

def test_the_digest_keeps_only_strings_found_in_their_page():
    pages = [OTHER]
    items = [
        {"finding": "runs a DLL with rundll32", "source": OTHER["url"],
         "strings": ["rundll32.exe C:\\ProgramData\\x.dll,Start", "invented.exe", "x"]},
        {"finding": "all invented", "source": OTHER["url"], "strings": ["nothere.dll"]},
        {"finding": "from a page not given", "source": "https://elsewhere.example/", "strings": ["rundll32.exe"]},
        {"finding": "contacts its server over TLS", "source": "https://other.example/analysis/", "strings": []},
    ]
    kept, dropped = check_digest(items, pages)
    assert [k["finding"] for k in kept] == ["runs a DLL with rundll32", "contacts its server over TLS"]
    assert kept[0]["strings"] == ["rundll32.exe C:\\ProgramData\\x.dll,Start"]
    reasons = sorted(d["reason"] for d in dropped)
    assert reasons == ["no string found in the page", "source is not a kept page", "string not in the page",
                       "string too short"]


def test_strings_match_ignoring_case_and_spacing():
    kept, _ = check_digest([{"finding": "f", "source": OTHER["url"], "strings": ["RUNDLL32.EXE   c:\\programdata"]}],
                           [OTHER])
    assert kept and kept[0]["strings"] == ["RUNDLL32.EXE   c:\\programdata"]


# --- the stage ----------------------------------------------------------------------------------------------------

DIGEST = {"items": [
    {"finding": "The loader is started with rundll32.", "source": OTHER["url"],
     "strings": ["rundll32.exe C:\\ProgramData\\x.dll,Start", "made-up.exe"]},
    {"finding": "From the rule page.", "source": RULE["url"], "strings": ["Kapeka"]}]}


def test_the_stage_appends_the_checked_digest_and_records_everything():
    client = _Client([OWN, OTHER, RULE], DIGEST)
    context = WebEnrichStage(client, "fake").run(_context())
    text = context["preprocessed"]["combined_text"]
    assert text.startswith("REPORT BODY")
    assert "rundll32.exe C:\\ProgramData\\x.dll,Start" in text and OTHER["url"] in text
    assert "made-up.exe" not in text
    assert "not from the report" in text
    prompt = client.prompts[0]
    assert "REPORT BODY" in prompt and OTHER["content"] in prompt and RULE["content"] in prompt
    assert OWN["content"] not in prompt
    e = context["enrichment"]
    assert [r["reason"] for r in e["results"]] == ["own page", None, None]
    assert e["rule_pages"] == [RULE["url"]]
    assert e["digest"]["proposed"] == 2 and len(e["digest"]["kept"]) == 2 and len(e["digest"]["dropped"]) == 1


def test_in_the_evaluation_rule_pages_are_dropped_before_the_digest():
    client = _Client([OWN, OTHER, RULE], DIGEST)
    stage = WebEnrichStage(client, "fake")
    stage.exclude_rule_pages = True
    context = stage.run(_context())
    assert RULE["content"] not in client.prompts[0]
    assert [r["reason"] for r in context["enrichment"]["results"]] == ["own page", None, "rule page"]
    assert "From the rule page." not in context["preprocessed"]["combined_text"]   # its source is not a kept page


def test_a_limit_or_no_kept_page_leaves_the_text_alone_and_makes_no_model_call():
    limited = _Client(None)
    context = WebEnrichStage(limited, "fake").run(_context())
    assert context["preprocessed"]["combined_text"] == "REPORT BODY: the actor used a loader."
    assert context["enrichment"]["limited"] and not limited.prompts
    only_own = _Client([OWN])
    WebEnrichStage(only_own, "fake").run(_context())
    assert not only_own.prompts


def test_a_failed_digest_is_recorded_and_the_pipeline_goes_on():
    context = WebEnrichStage(_Client([OTHER], fail=True), "fake").run(_context())
    assert context["preprocessed"]["combined_text"] == "REPORT BODY: the actor used a loader."
    assert "output limit" in context["enrichment"]["digest"]["error"]


def test_a_search_without_raw_results_keeps_the_old_summary_path():
    class _Gemini:
        model_name = "g"

        def web_search(self, query):
            return {"text": "a grounded summary", "sources": [{"url": "u", "title": "t"}]}
    context = WebEnrichStage(_Gemini(), "g").run(_context())
    assert "a grounded summary" in context["preprocessed"]["combined_text"]


def test_the_digest_prompt_treats_pages_as_data_and_asks_for_exact_strings():
    p = prompts.WEB_DIGEST.lower()
    assert "ignore any instructions" in p and "exactly" in p and "this attack" in p
    assert "{report}" in prompts.WEB_DIGEST and "{pages}" in prompts.WEB_DIGEST
