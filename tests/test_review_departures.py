"""Tests for checking the rules against the analyst's review (design P4, user 2026-09-27).

Fully offline: `review_departures` is a pure function over the rules' YAML.

What the analyst decides is final. After generation, code compares the rules with the review:
the first rule's log source with the analyst's choice (the prompt asks for it on the first
rule), every rule's ATT&CK tags with the rejected techniques, and every rule's detection
values with the rejected strings (their copies included). A description may name a rejected
string - it is context, not detection (SharePoint, 2026-09-27: "ysoserial.exe is used to
generate ViewState payloads"). Code never edits a rule. A log-source or technique departure gets
one rewrite by the model with the reason; a rejected string used in a detection is only shown, since
it can be right inside a larger condition (tests/test_review_checkpoint.py).
"""

from __future__ import annotations

import json

from backend.pipeline.analyst_review import format_departures, review_departures
from backend.pipeline.stage_generate import GenerateStage


def _rule(title, logsource, detection, tags=()):
    lines = [f"title: {title}", "logsource:"] + [f"    {k}: {v}" for k, v in logsource.items()]
    if tags:
        lines += ["tags:"] + [f"    - {t}" for t in tags]
    lines += ["detection:"] + [f"    {line}" for line in detection.strip("\n").splitlines()]
    return {"yaml_content": "\n".join(lines) + "\n"}


LINUX = {"category": "process_creation", "product": "linux"}
SELECT_SUDO = """
selection:
    CommandLine|contains: 'sudo -u#-1'
condition: selection
"""


def _context(logsource=None, techniques=(), patterns=(), indicators=(), linked=()):
    record = {
        "techniques": {"confirmed": [], "rejected": list(techniques)},
        "patterns": {"confirmed": [], "rejected": list(patterns), "linked": []},
        "indicators": {"confirmed": [], "rejected": list(indicators), "linked": list(linked)},
        "excluded": {"restored": []},
        "logsource": dict(logsource, suggested_rank=None) if logsource else None,
        "note": "",
    }
    ctx = {"analyst_review": record, "logsource_suggestion": {"suggestions": []}}
    if logsource:
        ctx["logsource_suggestion"].update(user_confirmed=True, confirmed_logsource=logsource)
    return ctx


CHOSEN_LINUX = {"category": "process_creation", "product": "linux", "service": None}


# --- nothing to check -------------------------------------------------------------

def test_without_a_review_there_is_nothing_to_check():
    rules = [_rule("A", {"category": "webserver"}, SELECT_SUDO, ["attack.t1068"])]
    assert review_departures(rules, {"logsource_suggestion": {"suggestions": []}}) == []


def test_rules_that_follow_the_review_have_no_departures():
    rules = [_rule("A", LINUX, SELECT_SUDO, ["attack.privilege-escalation", "attack.t1068"])]
    ctx = _context(CHOSEN_LINUX, techniques=["T1548.004"], patterns=["sudo"])
    assert review_departures(rules, ctx) == []


# --- the log source ---------------------------------------------------------------

def test_a_first_rule_on_another_log_source_departs():
    rules = [_rule("Sudo on Windows", {"category": "process_creation", "product": "windows"}, SELECT_SUDO),
             _rule("Second", {"category": "file_event", "product": "windows"}, SELECT_SUDO)]
    out = review_departures(rules, _context(CHOSEN_LINUX))
    assert [(d["rule"], d["kind"]) for d in out] == [(1, "logsource")]
    assert "process_creation/windows" in out[0]["message"] and "process_creation/linux" in out[0]["message"]


def test_only_the_first_rule_is_held_to_the_log_source():
    rules = [_rule("First", LINUX, SELECT_SUDO), _rule("Second", {"category": "file_event", "product": "linux"}, SELECT_SUDO)]
    assert review_departures(rules, _context(CHOSEN_LINUX)) == []


def test_a_field_the_analyst_left_out_is_a_departure():
    web = {"category": "webserver", "product": None, "service": None}
    rules = [_rule("Web", {"category": "webserver", "product": "windows"}, SELECT_SUDO)]
    assert [d["kind"] for d in review_departures(rules, _context(web))] == ["logsource"]


def test_case_and_placeholders_do_not_count():
    rules = [_rule("A", {"category": "Process_Creation", "product": "Linux", "service": "none"}, SELECT_SUDO)]
    assert review_departures(rules, _context(CHOSEN_LINUX)) == []


# --- techniques -------------------------------------------------------------------

def test_a_tag_of_a_rejected_technique_departs():
    rules = [_rule("A", LINUX, SELECT_SUDO, ["attack.initial-access", "attack.T1566.002"])]
    out = review_departures(rules, _context(techniques=["T1566.002"]))
    assert [(d["rule"], d["kind"]) for d in out] == [(1, "technique")]
    assert "attack.t1566.002" in out[0]["message"]


def test_the_parent_of_a_rejected_sub_technique_is_not_a_departure():
    rules = [_rule("A", LINUX, SELECT_SUDO, ["attack.t1566"])]
    assert review_departures(rules, _context(techniques=["T1566.002"])) == []


# --- rejected strings in detection -----------------------------------------------

def test_a_detection_value_equal_to_a_rejected_string_departs():
    detection = """
selection:
    Image|endswith: '\\ysoserial.exe'
condition: selection
"""
    rules = [_rule("Payload builder", {"category": "process_creation", "product": "windows"}, detection)]
    out = review_departures(rules, _context(patterns=["ysoserial.exe"]))
    assert [(d["rule"], d["kind"]) for d in out] == [(1, "value")]
    assert "ysoserial.exe" in out[0]["message"]


def test_wildcards_lists_and_keyword_lists_are_values_too():
    detection = """
selection:
    CommandLine|contains:
        - '*YSoSerial.exe*'
        - 'other'
keywords:
    - '/etc/sudoers'
condition: selection or keywords
"""
    rules = [_rule("A", LINUX, detection)]
    out = review_departures(rules, _context(patterns=["ysoserial.exe"], indicators=["/etc/sudoers"]))
    assert sorted(d["message"] for d in out) == sorted([
        "it detects on 'ysoserial.exe', which the analyst rejected",
        "it detects on '/etc/sudoers', which the analyst rejected"])


def test_a_longer_value_containing_a_rejected_string_is_not_a_departure():
    # The analyst rejected the bare `sudo` as too broad, not every sudo pattern.
    rules = [_rule("A", LINUX, SELECT_SUDO)]
    assert review_departures(rules, _context(patterns=["sudo"])) == []


def test_a_rejected_string_in_the_description_is_not_a_departure():
    rule = _rule("ViewState", {"category": "webserver"}, """
selection:
    cs-uri-query|contains: '__VIEWSTATEGENERATOR'
condition: selection
""")
    rule["yaml_content"] = rule["yaml_content"].replace(
        "logsource:", "description: ysoserial.exe is used to generate ViewState payloads\nlogsource:")
    assert review_departures([rule], _context(patterns=["ysoserial.exe"])) == []


def test_copies_rejected_with_a_string_count():
    detection = """
selection:
    Image|endswith: '\\ysoserial.exe'
condition: selection
"""
    rules = [_rule("A", LINUX, detection)]
    assert [d["kind"] for d in review_departures(rules, _context(linked=["ysoserial.exe"]))] == ["value"]


def test_a_rule_that_does_not_parse_is_left_to_validation():
    assert review_departures([{"yaml_content": "title: [unclosed"}], _context(CHOSEN_LINUX)) == []


# --- the reason given to the model ----------------------------------------------------

def test_the_reason_names_each_rule_and_what_to_change():
    out = review_departures([_rule("Sudo on Windows", {"category": "process_creation", "product": "windows"},
                                   SELECT_SUDO, ["attack.t1566.002"])],
                            _context(CHOSEN_LINUX, techniques=["T1566.002"]))
    text = format_departures(out)
    assert text.count('Rule 1 "Sudo on Windows"') == 2
    assert "log source" in text and "attack.t1566.002" in text


class _CapturingClient:
    model_name = "fake"

    def __init__(self):
        self.prompts = []

    def generate(self, prompt, **kwargs):
        self.prompts.append(prompt)
        return json.dumps({"rules": [], "notes": ""})


class _NoRag:
    def search(self, *args, **kwargs):
        return {}


def _generation_prompt(extra):
    client = _CapturingClient()
    GenerateStage(client, "fake", _NoRag()).run(dict({
        "original_query": "https://example.com/a", "history": [],
        "preprocessed": {"url_content": [], "combined_text": "text"},
        "extraction": {"attack_summary": "summary", "indicators": []},
        "ttp_mapping": {"mappings": []},
        "logsource_suggestion": {"suggestions": []},
    }, **extra))
    return client.prompts[0]


def test_the_rewrite_gets_the_departures_as_the_analysts_final_decisions():
    prompt = _generation_prompt({"analyst_check_feedback": '- Rule 1 "X": its log source is a/b'})
    assert "departs from the analyst's review" in prompt
    assert '- Rule 1 "X": its log source is a/b' in prompt


def test_without_departures_the_prompt_has_no_such_section():
    assert "departs from the analyst's review" not in _generation_prompt({})
