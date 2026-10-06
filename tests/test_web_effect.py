"""Tests for measuring what the web stage changes (Change 45's two-arm run; user 2026-10-06: "prepare the run"; the
measures fixed in the log before the run).

Per case: the digest's kept strings that are new to the report (>= 6 characters, `diagnose_detection.grounded`, as
CH6 §6.5c); which of them the first rule uses (`scorers.value_matches`, the web string as the reference); the human
rule's values the report lacks, those the web offers, and those the first rule has (per arm: the mechanism); and leaks -
a page the stage kept whose text holds the gold rule's id. Offline; made-up rows.
"""

from __future__ import annotations

import yaml

from eval.web_effect import case_measures, human_gain, leaks, new_strings, uses

REPORT = "The actor ran rundll32.exe and dropped payload.dll in the temp folder."


def _row(rule_values, kept_strings, results=None, query="q"):
    rule = yaml.safe_dump({"title": "r", "logsource": {"category": "process_creation"},
                           "detection": {"selection": {"CommandLine|contains": list(rule_values)},
                                         "condition": "selection"}})
    return {"rule_id": "x", "rules_yaml": [rule], "scores": {"validity": {"parses": True}},
            "pipeline": {"web_enrichment": {"search_queries": [query], "results": results or [],
                                            "digest": {"kept": [{"finding": "f", "strings": list(kept_strings),
                                                                 "source": "u"}]}}}}


def test_new_strings_are_the_kept_strings_the_report_lacks():
    assert new_strings(["rundll32.exe", "SpeedFan.sys", "Goad.sys", "x.sys"], REPORT) == ["speedfan.sys", "goad.sys"]


def test_a_rule_uses_a_web_string_only_when_it_is_new_to_the_report():
    rule_vals = {"speedfan.sys", "rundll32.exe"}
    assert uses(rule_vals, ["speedfan.sys", "goad.sys"]) == ["speedfan.sys"]


def test_the_human_values_the_report_lacks_offered_and_found():
    gold = {("imageloaded", "\\speedfan.sys"), ("imageloaded", "\\goad.sys"), ("image", "\\rundll32.exe"),
            ("", "abc")}
    g = human_gain(gold, REPORT, web=["speedfan.sys", "goad.sys"], rule_vals={"speedfan.sys"})
    assert g == {"lacking": 2, "offered": 2, "found": 1}       # rundll32.exe is in the report; "abc" is too short


def test_a_leak_is_a_kept_page_with_the_gold_id():
    gold = {"id": "6d29520b-0000-1111-2222-333344445555"}
    pages = {("q", "https://kept.example/"): "rule id: 6D29520B-0000-1111-2222-333344445555",
             ("q", "https://dropped.example/"): "id: 6d29520b-0000-1111-2222-333344445555"}
    row = _row([], [], results=[{"url": "https://kept.example/", "reason": None},
                                {"url": "https://dropped.example/", "reason": "rule page"}])
    assert leaks(row, gold, pages) == 1


def test_case_measures_put_it_together():
    gold = {"id": "i", "detection": {"selection": {"ImageLoaded|endswith": ["\\SpeedFan.sys", "\\Goad.sys"]},
                                     "condition": "selection"}}
    m = case_measures(_row(["SpeedFan.sys"], ["SpeedFan.sys", "Goad.sys", "rundll32.exe"]), gold, REPORT, {})
    assert m["web_strings"] == 3 and m["new_strings"] == 2 and m["used_new"] == 1
    assert (m["lacking"], m["offered"], m["found"], m["leaks"]) == (2, 2, 1, 0)
    plain = case_measures(_row(["SpeedFan.sys"], []), gold, REPORT, {})
    assert plain["web_strings"] == 0 and plain["found"] == 1 and plain["offered"] == 0


def test_use_by_any_rule_is_counted_too():
    # Only the first rule is scored; any rule shows whether web strings reach the rules at all (the pipeline writes
    # several - 6 for Slingshot in the live check).
    gold = {"id": "i", "detection": {"selection": {"ImageLoaded|endswith": ["\\SpeedFan.sys"]}, "condition": "selection"}}
    row = _row(["rundll32.exe"], ["SpeedFan.sys", "Goad.sys"])
    second = yaml.safe_dump({"title": "r2", "logsource": {"category": "driver_load"},
                             "detection": {"selection": {"ImageLoaded|endswith": ["\\Goad.sys"]},
                                           "condition": "selection"}})
    row["rules_yaml"].append(second)
    m = case_measures(row, gold, REPORT, {})
    assert m["used_new"] == 0 and m["used_new_any_rule"] == 1
