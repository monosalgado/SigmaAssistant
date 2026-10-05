"""Tests for scoring our rules by synthetic replay (R9.2; design and amendment fixed in the log 2026-10-05).

A case's human event sets: the events built from the gold rule and from every other human rule for the same report
(Pany's definition). Our rule sees an event when every log-source field it names equals the event's, or the event's
leaves it unnamed. Primary: **hit** = any of the case's rules fires on any event of any human set; also the first
rule, the gold rule's set alone, coverage, firing with the log source ignored, breadth over other cases' sets, the
miss reason, and "report-grounded" misses. Offline; made-up rules.
"""

from __future__ import annotations

from eval.replay import alternative_rule_ids, applies, breadth, case_score, grounded_rule, human_set

GOLD = ("title: g\nlogsource: {category: process_creation, product: windows}\ndetection:\n"
        "  sel:\n    Image|endswith: '\\\\schtasks.exe'\n    CommandLine|contains: '/create'\n  condition: sel\n")
ALT = ("title: a\nlogsource: {category: file_event, product: windows}\ndetection:\n"
       "  sel:\n    TargetFilename|endswith: '\\\\evil.dll'\n  condition: sel\n")


def _ours(category, detection):
    return (f"title: o\nlogsource: {{category: {category}, product: windows}}\ndetection:\n{detection}"
            "  condition: sel\n")


CATCHES_GOLD = _ours("process_creation", "  sel:\n    CommandLine|contains: '/create'\n")
CATCHES_ALT = _ours("file_event", "  sel:\n    TargetFilename|contains: 'evil'\n")
WRONG_SOURCE = _ours("registry_set", "  sel:\n    CommandLine|contains: '/create'\n")
NEEDS_PARENT = _ours("process_creation", "  sel:\n    ParentImage|endswith: '\\\\winword.exe'\n")
WRONG_VALUE = _ours("process_creation", "  sel:\n    CommandLine|contains: '/delete'\n")
SETS = [human_set(GOLD), human_set(ALT)]


def test_log_source_applies_leniently_on_fields_the_event_leaves_unnamed():
    assert applies({"category": "webserver", "product": "windows"}, {"category": "webserver"})
    assert not applies({"category": "process_creation", "product": "linux"},
                       {"category": "process_creation", "product": "windows"})
    assert applies({"product": "windows", "service": "security"}, {"product": "windows", "service": "security"})


def test_a_hit_is_any_rule_firing_on_any_human_rules_events():
    s = case_score([WRONG_VALUE, CATCHES_ALT], SETS)
    assert s["hit"] is True and s["hit_first"] is False and s["hit_gold"] is False
    s = case_score([CATCHES_GOLD], SETS)
    assert s["hit"] and s["hit_first"] and s["hit_gold"] and s["coverage"] == 0.5


def test_the_log_source_must_fit_but_logic_alone_is_reported_too():
    s = case_score([WRONG_SOURCE], SETS)
    assert s["hit"] is False and s["hit_logic"] is True and s["miss"] == "log source"


def test_miss_reasons_say_why():
    assert case_score([NEEDS_PARENT], SETS)["miss"] == "field absent"
    assert case_score([WRONG_VALUE], SETS)["miss"] == "value mismatch"
    assert case_score(["title: [unclosed"], SETS)["miss"] == "no rule parses"


def test_breadth_is_the_share_of_other_cases_our_rules_fire_on():
    others = {"b": [human_set(GOLD)], "c": [human_set(ALT)], "d": [human_set(GOLD)]}
    assert breadth([CATCHES_GOLD], others) == 2 / 3
    assert breadth([WRONG_VALUE], others) == 0.0


def test_a_miss_whose_rule_is_built_from_the_report_is_report_grounded():
    text = "The actor runs schtasks.exe /create and drops C:\\Users\\Public\\winword.exe"
    assert grounded_rule([NEEDS_PARENT], text) is True
    assert grounded_rule([WRONG_VALUE], text) is False           # '/delete' is not in the report
    assert grounded_rule(["title: [unclosed"], text) is False


def test_the_other_human_rules_are_found_by_the_reports_urls():
    index = {"https://a.example/report": [("gold", {}), ("alt1", {})],
             "https://b.example/tool": [(f"r{i}", {}) for i in range(6)]}           # cited by > 5: links nothing
    case = {"rule_id": "gold", "references_usable": ["https://a.example/report/", "https://b.example/tool"]}
    assert alternative_rule_ids(case, index) == ["alt1"]
