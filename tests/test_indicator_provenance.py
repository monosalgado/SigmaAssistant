"""Tests for `eval/indicator_provenance.py` (user 2026-10-17, before Change 53's run: does "only what the text shows"
lose the expert's outside knowledge?): an indicator is "in the report" when its value - defanging, case, whitespace
and doubled backslashes ignored - appears in the text the pipeline read; per group: listed, used by a rule, and used
AND matching one of the gold rule's values (`scorers.value_matches`). Offline."""

from __future__ import annotations

from eval.indicator_provenance import group_counts, in_report

TEXT = "The actor contacted evil[.]example and ran C:\\Windows\\Temp\\x.exe"


def test_defanged_and_doubled_backslashes_count_as_in_the_report():
    assert in_report("evil.example", TEXT) and in_report("C:\\\\Windows\\\\Temp\\\\x.exe", TEXT)
    assert not in_report("other.example", TEXT)


def test_groups_listed_used_and_matching_the_expert():
    indicators = [{"value": "evil.example"}, {"value": "other.example"}, {"value": "x.exe"}]
    c = group_counts(indicators, used={"evil.example", "other.example"}, text=TEXT,
                     gold_values=["evil.example", "other.example"])
    assert c["in the report"] == {"listed": 2, "used": 1, "used_matching_expert": 1}
    assert c["not in the report"] == {"listed": 1, "used": 1, "used_matching_expert": 1}
