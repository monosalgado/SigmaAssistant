"""Tests for the rule evaluator (R9, replay; user 2026-10-04: "design the evaluator"). pySigma parses the rule and
its condition; our matcher evaluates the parsed condition against an event. Definition fixed in the log before
this code. Offline; no LLM.
"""

from __future__ import annotations

import json

import pytest

from eval.rule_matcher import CannotEvaluate, flatten_event, load_events, parse_rule, rule_matches


def _rule(selection: str, condition: str = "sel", extra: str = "") -> str:
    return ("title: t\nlogsource: {category: process_creation, product: windows}\ndetection:\n"
            f"  sel:\n    {selection}\n{extra}  condition: {condition}\n")


def _m(selection, event, condition="sel", extra=""):
    return rule_matches(parse_rule(_rule(selection, condition, extra)), event)


EV = {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA", "ParentImage": "C:\\Windows\\explorer.exe",
      "EventID": 1, "User": "CORP\\bob", "DestinationIp": "10.1.2.3", "Size": "250"}


# --- strings: pySigma applies the modifiers; the match is case-insensitive ------------------------

def test_endswith_contains_and_startswith():
    assert _m("Image|endswith: '\\\\POWERSHELL.EXE'", EV)
    assert _m("CommandLine|contains: ' -ENC '", EV)
    assert _m("ParentImage|startswith: 'c:\\\\windows\\\\'", EV)
    assert not _m("Image|endswith: '\\\\cmd.exe'", EV)


def test_a_plain_value_must_equal_the_whole_field():
    assert not _m("Image: 'powershell.exe'", EV)
    assert _m("Image: 'C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe'", EV)


def test_contains_all_needs_every_value_and_a_list_needs_one():
    assert _m("CommandLine|contains|all: ['-nop', 'hidden']", EV)
    assert not _m("CommandLine|contains|all: ['-nop', 'bypass']", EV)
    assert _m("CommandLine|contains: ['bypass', 'hidden']", EV)


def test_cased_is_case_sensitive():
    assert not _m("CommandLine|cased|contains: 'HIDDEN'", EV)
    assert _m("CommandLine|cased|contains: 'hidden'", EV)


def test_a_field_is_found_by_its_exact_name_else_case_insensitively_and_a_missing_one_does_not_match():
    assert _m("commandline|contains: 'hidden'", EV)
    assert not _m("TargetFilename|contains: 'x'", EV)


def test_a_wildcard_alone_needs_the_field_to_be_there():
    # `Field: '*'` matches any value of a present field; a missing field is not an empty one.
    assert _m("User: '*'", EV)
    assert not _m("Hashes: '*'", EV)


# --- other value types ---------------------------------------------------------------------------

def test_numbers_match_numbers_and_numeric_strings():
    assert _m("EventID: 1", EV) and _m("Size: 250", EV) and not _m("EventID: 4688", EV)


def test_null_matches_a_missing_or_empty_field():
    assert _m("OriginalFileName: null", EV) and _m("OriginalFileName: null", {"OriginalFileName": ""})
    assert not _m("User: null", EV)


def test_regex_is_searched_and_case_sensitive_unless_i():
    assert _m("CommandLine|re: '-w\\s+hidden'", EV)
    assert not _m("CommandLine|re: 'HIDDEN'", EV)
    assert _m("CommandLine|re|i: 'HIDDEN'", EV)


def test_exists_cidr_compare_and_fieldref():
    assert _m("User|exists: true", EV) and not _m("Hashes|exists: true", EV)
    assert _m("DestinationIp|cidr: '10.0.0.0/8'", EV) and not _m("DestinationIp|cidr: '192.168.0.0/16'", EV)
    assert _m("Size|gt: 100", EV) and not _m("Size|lt: 100", EV)
    assert _m("Image|fieldref: Image", EV) and not _m("Image|fieldref: ParentImage", EV)


def test_expansions_match_any_alternative():
    assert _m("CommandLine|windash|contains: '/enc'", EV)            # windash adds the '-' form
    assert not _m("CommandLine|windash|contains: '/bypass'", EV)


# --- the condition -------------------------------------------------------------------------------

def test_and_or_not_and_the_one_of_forms():
    filt = "  filter_main:\n    ParentImage|endswith: '\\\\explorer.exe'\n"
    assert not _m("Image|endswith: '\\\\powershell.exe'", EV, "sel and not filter_main", filt)
    assert _m("Image|endswith: '\\\\powershell.exe'", EV, "sel or filter_main", filt)
    assert _m("Image|endswith: '\\\\powershell.exe'", EV, "all of sel* and 1 of filter_*", filt)


def test_a_keyword_matches_anywhere_in_the_event():
    rule = ("title: t\nlogsource: {product: windows}\ndetection:\n  keywords:\n    - 'SQBFAFgA'\n"
            "  condition: keywords\n")
    assert rule_matches(parse_rule(rule), EV)
    assert not rule_matches(parse_rule(rule.replace("SQBFAFgA", "mimikatz")), EV)


# --- what cannot be evaluated is said, never guessed ----------------------------------------------

def test_an_unparsable_rule_or_an_aggregation_cannot_be_evaluated():
    with pytest.raises(CannotEvaluate):
        parse_rule("title: [unclosed")
    with pytest.raises(CannotEvaluate):
        parse_rule(_rule("Image|endswith: 'x.exe'", "sel | count() > 5"))


# --- events --------------------------------------------------------------------------------------

def test_a_windows_event_is_flattened_to_its_fields():
    raw = {"Event": {"System": {"Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}}, "EventID": 1,
                                "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "pc1"},
                     "EventData": {"Image": "C:\\x.exe", "CommandLine": "x.exe /q"}}}
    assert flatten_event(raw) == {"Image": "C:\\x.exe", "CommandLine": "x.exe /q", "EventID": 1,
                                  "Channel": "Microsoft-Windows-Sysmon/Operational",
                                  "Provider_Name": "Microsoft-Windows-Sysmon", "Computer": "pc1"}
    assert flatten_event({"Image": "a"}) == {"Image": "a"}                     # already flat
    user_data = {"Event": {"System": {"EventID": 4}, "UserData": {"RuleAndFileData": {"FilePath": "C:\\f"}}}}
    assert flatten_event(user_data)["FilePath"] == "C:\\f"


def test_events_load_from_one_object_or_several_written_back_to_back(tmp_path):
    one = tmp_path / "one.json"
    one.write_text(json.dumps({"Event": {"System": {"EventID": 1}, "EventData": {"Image": "a"}}}))
    many = tmp_path / "many.json"
    many.write_text(json.dumps({"Image": "a"}, indent=2) + "\n" + json.dumps({"Image": "b"}, indent=2))
    assert [e["Image"] for e in load_events(one)] == ["a"]
    assert [e["Image"] for e in load_events(many)] == ["a", "b"]


def test_a_numeric_keyword_matches_its_text_anywhere():
    # Found by the replay's first validation pass: a keyword may be a number.
    rule = "title: t\nlogsource: {product: windows}\ndetection:\n  keywords:\n    - 4698\n  condition: keywords\n"
    assert rule_matches(parse_rule(rule), {"Message": "event 4698 logged"})
    assert not rule_matches(parse_rule(rule), {"Message": "event 4699"})
