"""Tests for the web search probe (web enrichment, step 1; user 2026-10-06: "Do the probe"; plan in the log, fixed
before any query).

The stage has been a silent no-op since the pipeline went all-local. The probe sends the stage's own query (and, for
reports that mention CVE IDs, a CVE-only query) to Ollama's web search API and measures what comes back: the case's own
page, detection-rule sites, Sigma rule text, the gold rule itself (leak), and the human rule's values and techniques
the report lacks but a result holds. Offline: a stand-in HTTP session; the key is never in a record.
"""

from __future__ import annotations

from eval.probe_web_search import (
    cve_query, gold_leak, has_sigma_text, is_own_page, is_rule_site, search, techniques_added, values_added,
)


# --- the result's flags -----------------------------------------------------------------------------------------------

def test_own_page_ignores_scheme_www_and_trailing_slash():
    case_urls = ["https://www.example.com/blog/report/"]
    assert is_own_page("http://example.com/blog/report", case_urls)
    assert not is_own_page("https://example.com/blog/other", case_urls)


def test_rule_sites_are_the_fixed_list():
    assert is_rule_site("https://github.com/SigmaHQ/sigma/blob/master/rules/x.yml")
    assert is_rule_site("https://sigma.nasbench.dev/rule/abc")
    assert is_rule_site("https://tdm.socprime.com/detection/x")
    assert is_rule_site("https://detection.fyi/sigmahq/sigma/x")
    assert is_rule_site("https://github.com/elastic/detection-rules/blob/main/x.toml")
    assert not is_rule_site("https://github.com/someone/poc")
    assert not is_rule_site("https://www.example.com/sigmahq")


def test_sigma_text_needs_all_three_keys():
    assert has_sigma_text("title: x\nlogsource:\n  category: c\ndetection:\n  s: 1\n  condition: s")
    assert not has_sigma_text("the detection: logic and its condition: are discussed")


def test_a_gold_leak_is_the_gold_rules_id_or_title():
    gold = {"id": "5f1c6e3a-1111-2222-3333-444455556666", "title": "Potential Exploitation Of Foo CVE-2024-1"}
    assert gold_leak({"title": "t", "url": "u", "content": "id: 5F1C6E3A-1111-2222-3333-444455556666"}, gold)
    assert gold_leak({"title": "potential exploitation of foo cve-2024-1", "url": "u", "content": ""}, gold)
    assert not gold_leak({"title": "Foo exploited", "url": "u", "content": "CVE-2024-1 was exploited"}, gold)


# --- what a result adds that the report lacks -------------------------------------------------------------------------

def test_values_the_report_lacks_and_a_result_adds():
    gold_values = {("commandline", "\\rundll32.exe"), ("url", "/api/v1/upload"), ("image", "a.exe"),
                   ("", "x.dll")}
    report = "The actor ran rundll32.exe with a DLL."
    lacking, added = values_added(gold_values, report, ["POST /api/v1/upload was seen"], min_chars=6)
    assert lacking == {"/api/v1/upload"}            # rundll32.exe is in the report; a.exe and x.dll are too short
    assert added == {"/api/v1/upload"}


def test_techniques_the_report_lacks_and_a_result_adds():
    lacking, added = techniques_added({"t1059.001", "t1105", "t1218"}, "uses T1105 for transfer",
                                      ["T1059.001 PowerShell", "see T12180"])
    assert lacking == {"t1059.001", "t1218"} and added == {"t1059.001"}


# --- the CVE variant --------------------------------------------------------------------------------------------------

def test_the_cve_query_is_the_reports_most_mentioned_cve_ids():
    text = "cve-2024-0001 ... CVE-2023-1111 ... CVE-2024-0001 ... CVE-2022-2222 ... CVE-2021-3333 CVE-2023-1111"
    assert cve_query(text) == "CVE-2024-0001 CVE-2023-1111 CVE-2022-2222"
    assert cve_query("no identifiers here") is None


# --- the request ------------------------------------------------------------------------------------------------------

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


def test_a_search_posts_the_query_with_the_key_and_keeps_the_results():
    session = _Session(_Response(200, {"results": [{"title": "T", "url": "https://a.example/x", "content": "c"}]}))
    out = search("foo exploit", "secret-key", session=session)
    call = session.calls[0]
    assert call["url"] == "https://ollama.com/api/web_search"
    assert call["json"] == {"query": "foo exploit", "max_results": 5}
    assert call["headers"]["Authorization"] == "Bearer secret-key"
    assert out["status"] == 200 and out["results"][0]["url"] == "https://a.example/x" and out["error"] is None
    assert "secret-key" not in repr(out)


def test_an_error_is_recorded_not_raised_and_the_key_stays_out():
    out = search("q", "secret-key", session=_Session(_Response(429, {"error": "rate limited"})))
    assert out["status"] == 429 and out["results"] == [] and out["error"]
    assert "secret-key" not in repr(out)
