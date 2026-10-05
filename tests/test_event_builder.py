"""Tests for the synthetic replay's event builder (R9.2; design fixed in the log 2026-10-05 before this code).

For a rule (parsed by pySigma), the condition is put in disjunctive normal form with NOT pushed down to the atoms;
each conjunction is one way the rule can fire and becomes one event. Values are minimal - nothing is invented: a
wildcard string becomes its literal parts (`*` -> nothing, `?` -> `x`); several strings on one field are joined by
one space, starts-with parts first and ends-with parts last. A negated atom is satisfied by leaving its field out.
A regex, a placeholder or two different exact values for one field -> "cannot build". The builder does not check its
own events; validation V1 does (`event_builder.verified_events` keeps only events the source rule fires on).
Offline.
"""

from __future__ import annotations

from eval.event_builder import CAP, build_events, dnf, verified_events
from eval.rule_matcher import parse_rule, rule_matches


def _rule(detection: str, logsource="{category: process_creation, product: windows}") -> str:
    return f"title: t\nlogsource: {logsource}\ndetection:\n{detection}"


def _events(detection):
    built = build_events(parse_rule(_rule(detection)))
    return built["events"], built["cannot_build"]


# --- the normal form ------------------------------------------------------------------------------

def test_each_way_the_rule_can_fire_is_one_conjunction():
    parsed = parse_rule(_rule("  a:\n    Image|endswith: ['\\\\x.exe', '\\\\y.exe']\n  b:\n    User: bob\n"
                              "  condition: a and b\n"))
    terms = dnf(parsed.tree)
    assert len(terms) == 2 and all(len(t) == 2 for t in terms)


def test_not_is_pushed_down_to_the_atoms():
    parsed = parse_rule(_rule("  a:\n    Image|endswith: '\\\\x.exe'\n  f:\n    User: bob\n    Host: h1\n"
                              "  condition: a and not f\n"))
    terms = dnf(parsed.tree)                       # not (User and Host) = not User or not Host
    assert len(terms) == 2
    assert all(sorted(neg for _, neg in t) == [False, True] for t in terms)


def test_the_number_of_events_is_capped():
    values = ", ".join(f"'v{i}'" for i in range(30))
    events, _ = _events(f"  a:\n    Image: [{values}]\n  condition: a\n")
    assert len(events) == CAP == 20


# --- minimal values -------------------------------------------------------------------------------

def test_wildcards_become_the_literal_parts_and_nothing_is_invented():
    events, _ = _events("  sel:\n    Image|endswith: '\\\\powershell.exe'\n    CommandLine|contains: '-enc'\n"
                        "  condition: sel\n")
    assert events == [{"Image": "\\powershell.exe", "CommandLine": "-enc"}]
    events, _ = _events("  sel:\n    A: 'a?b'\n  condition: sel\n")
    assert events == [{"A": "axb"}]


def test_several_strings_on_one_field_are_joined_starts_first_ends_last():
    events, _ = _events("  sel:\n    CommandLine|endswith: '.ps1'\n    CommandLine|contains|all: ['-nop', 'hidden']\n"
                        "  condition: sel\n")
    assert events == [{"CommandLine": "-nop hidden .ps1"}]
    events, _ = _events("  sel:\n    CommandLine|startswith: 'cmd'\n    CommandLine|endswith: '.bat'\n"
                        "  condition: sel\n")
    assert events == [{"CommandLine": "cmd .bat"}]


def test_numbers_comparisons_cidr_exists_and_keywords():
    events, _ = _events("  sel:\n    EventID: 4698\n    Size|gt: 100\n    DestinationIp|cidr: '10.0.0.0/8'\n"
                        "    User|exists: true\n  condition: sel\n")
    assert events == [{"EventID": 4698, "Size": 101, "DestinationIp": "10.0.0.1", "User": "x"}]
    events, _ = _events("  keywords:\n    - 'mimikatz'\n  condition: keywords\n")
    assert events == [{"Message": "mimikatz"}]


def test_a_negated_atom_leaves_its_field_out():
    events, _ = _events("  sel:\n    Image|endswith: '\\\\x.exe'\n  filter:\n    ParentImage|endswith: '\\\\y.exe'\n"
                        "  condition: sel and not filter\n")
    assert events == [{"Image": "\\x.exe"}]


# --- what cannot be built is said, never patched --------------------------------------------------

def test_a_regex_or_a_contradiction_cannot_be_built():
    events, cannot = _events("  sel:\n    CommandLine|re: 'a+b'\n  condition: sel\n")
    assert events == [] and cannot == ["regex"]
    events, cannot = _events("  a:\n    User: alice\n  b:\n    User: bob\n  condition: a and b\n")
    assert events == [] and cannot == ["contradiction"]


# --- the source rule must fire on its own events (V1) ----------------------------------------------

def test_verified_events_are_those_the_source_rule_fires_on():
    parsed = parse_rule(_rule("  sel:\n    Image|endswith: '\\\\x.exe'\n  filter:\n    Image|contains: 'x'\n"
                              "  condition: sel and not filter\n"))
    built = build_events(parsed)
    assert built["events"] == [{"Image": "\\x.exe"}]                 # built, but the filter excludes it
    assert verified_events(parsed, built["events"]) == []
    good = parse_rule(_rule("  sel:\n    Image|endswith: '\\\\x.exe'\n  condition: sel\n"))
    assert all(rule_matches(good, e) for e in verified_events(good, build_events(good)["events"]))


def test_a_numeric_keyword_is_built_as_its_text():
    # Found by the first validation pass (it crashed on a corpus gold rule whose keywords include a number).
    events, cannot = _events("  keywords:\n    - 4698\n  condition: keywords\n")
    assert events == [{"Message": "4698"}] and cannot == []
