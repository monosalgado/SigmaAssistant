"""Tests for Change 53 (user 2026-10-17: "Do we really need so much indicators?"): the analysis asks for the indicators
a detection rule could match on, not ALL of them.

`c51_tuning60`: 1,690 indicators listed, 28% used by any rule; hashes 149 -> 9 used, IPs 68 -> 3; the experts' rules
match a hash in 0 of 60 reports and an IP in 1. The new wording: what a rule could match on, only what the text shows,
each value once, behaviour first, hashes and IPs only when the text gives nothing else. No cap. Only part 1 changes.
"""

from __future__ import annotations

from backend.pipeline import prompts

P = prompts.COMBINED_ANALYSIS
PART1 = " ".join(P.split("## PART 1: Entity/Indicator Extraction")[1].split("## PART 2")[0].split())


def test_part_1_asks_for_what_a_rule_could_match_on():
    assert "Extract ALL threat indicators" not in P
    assert "implicitly referenced" not in P
    assert "a detection rule could match on" in PART1
    assert "only what the text shows" in PART1 and "each distinct value once" in PART1


def test_behaviour_first_and_hashes_and_ips_only_when_nothing_else():
    assert "behaviour first" in PART1.lower()
    assert "File hashes and IP addresses" in PART1 and "nothing else" in PART1


def test_no_cap_and_the_rest_unchanged():
    assert "at most" not in PART1.lower()
    for kept in ("- **hash**:", "- **ip_address**:", "Each indicator needs: value, type, context (brief quote), "
                 "confidence (high/medium/low).", "Strings to EXCLUDE", "## PART 2: MITRE ATT&CK TTP Mapping",
                 "## PART 3: Log Source Recommendation"):
        assert kept in P
