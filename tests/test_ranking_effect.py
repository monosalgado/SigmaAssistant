"""Tests for measuring Change 38 v3's ranking step inside one run: every row records the analysis's own
order of log sources (`before`) and the order after the ranking step (`after`), so the step's effect on the
top pick is read on the same answers - free of run-to-run variation. Also: whether the first rule was
written on the new top pick or the old one. Offline: stand-in rows; no LLM.
"""

from __future__ import annotations

from eval.ranking_effect import effect, first_rule_name, top_before_after

GOLD_PROC = {"category": "process_creation", "product": "windows"}
PROC = {"category": "process_creation", "product": "windows", "service": None}
FILE = {"category": "file_event", "product": "windows", "service": None}
NET = {"category": "network_connection", "product": "windows", "service": None}


def _rule(category, product="windows"):
    return f"title: t\nlogsource:\n  category: {category}\n  product: {product}\ndetection:\n  sel: {{a: b}}\n"


def _row(rid, before, after, suggestions, rules=None, error=None, ran=True):
    ranking = {"ran": ran, "before": before, "after": after, "changed_top": bool(before) and before[0] != after[0],
               "added": [], "dropped": [], "reason": "", "error": error}
    return {"rule_id": rid, "rules_yaml": rules or [],
            "pipeline": {"logsource_suggestions": suggestions, "logsource_ranking": ranking}}


MOVED_AWAY = _row("a", ["process_creation/windows", "file_event/windows"],
                  ["file_event/windows", "process_creation/windows"], [FILE, PROC], [_rule("file_event")])
KEPT = _row("b", ["process_creation/windows", "network_connection/windows"],
            ["process_creation/windows", "network_connection/windows"], [PROC, NET], [_rule("process_creation")])
MOVED_TO_GOLD = _row("c", ["network_connection/windows", "process_creation/windows"],
                     ["process_creation/windows", "network_connection/windows"], [PROC, NET],
                     [_rule("network_connection")])
NO_PICK = _row("d", [], [], [], ran=False)
PICKS = {rid: (GOLD_PROC, []) for rid in "abcd"}


def test_the_analysis_own_top_pick_is_read_from_the_record():
    before, after = top_before_after(MOVED_AWAY)
    assert before["category"] == "process_creation" and after["category"] == "file_event"


def test_a_case_with_no_suggestion_has_no_pick_either_way():
    assert top_before_after(NO_PICK) == (None, None)


def test_the_first_rule_name_uses_the_same_form_as_the_record():
    assert first_rule_name(MOVED_AWAY) == "file_event/windows"
    assert first_rule_name(_row("e", [], [], [], ["title: [unclosed"])) == "(does not parse)"
    assert first_rule_name(NO_PICK) == "(no rule)"


def test_the_effect_counts_the_moves_and_the_picks_before_and_after():
    e = effect([MOVED_AWAY, KEPT, MOVED_TO_GOLD, NO_PICK], PICKS)
    assert e["cases"] == 4 and e["ran"] == 3 and e["changed_top"] == 2
    assert e["P_before"] == 2 and e["P_after"] == 2           # a: gold -> not; c: not -> gold; b: gold kept
    assert e["moves"] == {("gold", "neither"): 1, ("neither", "gold"): 1}


def test_the_effect_says_which_top_pick_the_first_rule_followed():
    e = effect([MOVED_AWAY, KEPT, MOVED_TO_GOLD], PICKS)
    assert e["rule_follows"] == {"new top": 1, "old top": 1}   # only cases whose top changed


def test_the_cases_whose_top_changed_are_listed_with_their_gold():
    e = effect([MOVED_AWAY, KEPT], PICKS)
    assert e["changed"] == [("a", "process_creation/windows", "file_event/windows", "process_creation/windows")]
