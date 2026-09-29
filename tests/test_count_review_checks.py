"""Tests for the adherence counts of the simulated-analyst run (plan 5.3), fixed in its plan:
how often the rules departed from the analyst's decision, how many got the one rewrite, and
what remained. Offline: reads result rows only.
"""

from __future__ import annotations

from eval.count_review_checks import count_checks


def _row(rule_id, check=None, error=None):
    row = {"rule_id": rule_id, "error": error, "pipeline": {}}
    if check is not None:
        row["pipeline"]["analyst_check"] = check
    return row


DEP = {"rule": 1, "title": "t", "kind": "logsource", "message": "m"}
ROWS = [
    _row("a", {"departures_before": [], "departures": [], "flagged": [], "rewritten": False, "rewrite_failed": False}),
    _row("b", {"departures_before": [DEP], "departures": [], "flagged": [], "rewritten": True, "rewrite_failed": False}),
    _row("c", {"departures_before": [DEP], "departures": [DEP], "flagged": [], "rewritten": True, "rewrite_failed": False}),
    _row("d", {"departures_before": [DEP], "departures": [DEP], "flagged": [], "rewritten": True, "rewrite_failed": True}),
    _row("e"),                                          # no check (nothing asked of the rules)
    _row("f", error="ValueError: boom"),                # crashed: left out
]


def test_the_counts():
    out = count_checks(ROWS)
    assert out["cases"] == 5
    assert out["checked"] == 4
    assert out["followed_first_time"] == ["a"]
    assert out["rewritten"] == ["b", "c", "d"]
    assert out["followed_after_rewrite"] == ["b"]
    assert out["still_departing"] == ["c", "d"]
    assert out["rewrite_failed"] == ["d"]
    assert out["departures_by_kind"] == {"logsource": 3}   # b, c, d


def test_flagged_strings_are_counted_apart():
    rows = [_row("a", {"departures_before": [], "departures": [], "rewritten": False, "rewrite_failed": False,
                       "flagged": [{"rule": 2, "title": "t", "kind": "value", "message": "m"}]})]
    out = count_checks(rows)
    assert out["followed_first_time"] == ["a"] and out["flagged"] == ["a"]


def _rules(*logsources):
    return ["title: r\nlogsource:\n" + "".join(f"    {k}: {v}\n" for k, v in ls.items()) + "detection:\n    s:\n        a: b\n    condition: s\n"
            for ls in logsources]


def test_a_later_rule_on_the_analysts_log_source_is_counted():
    # Post-hoc question (plan 5.3): when the first rule departs, is the analyst's log source
    # used further down (the model changed the order), or nowhere?
    choice = {"category": "file_event", "product": "windows", "service": None}
    rows = [
        dict(_row("x", {"departures_before": [DEP], "departures": [DEP], "flagged": [], "rewritten": True,
                        "rewrite_failed": False}),
             oracle_review={"logsource": choice},
             rules_yaml=_rules({"category": "webserver"}, {"category": "file_event", "product": "Windows"})),
        dict(_row("y", {"departures_before": [DEP], "departures": [DEP], "flagged": [], "rewritten": True,
                        "rewrite_failed": False}),
             oracle_review={"logsource": choice},
             rules_yaml=_rules({"category": "webserver"})),
    ]
    out = count_checks(rows)
    assert out["still_departing"] == ["x", "y"]
    assert out["choice_in_a_later_rule"] == ["x"]
