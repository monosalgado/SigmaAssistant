"""Offline tests for Change 32 (plan 2.8; user, 2026-09-24/25): the analysis stage lists
at most the 10 most relevant techniques, most relevant first.

Why (Change 25 run): gold rules carry 1 technique in 28 of 40 cases and at most 5; the
analysis listed a median of 6, more than 10 in 14 of 58 cases, 108 in one; of the gold
techniques it found (24), 21 were in its first 10. Every answer cut at the output limit
(defect 19) was in this stage, looping through invented technique IDs. A prompt change:
the model still chooses which techniques.
"""

from __future__ import annotations

from backend.pipeline import prompts

PART2 = prompts.COMBINED_ANALYSIS.split("## PART 2")[1].split("## PART 3")[0]


def test_the_list_has_an_end():
    # Change 43 (2026-10-05) reworded this limit; removed 2026-10-06 (failed its gate), so Change 32's wording is back.
    assert "at most the 10 most relevant techniques" in PART2


def test_the_most_relevant_come_first():
    assert "most relevant first" in PART2


def test_the_evidence_rule_is_kept():
    assert "Only map techniques directly evidenced by indicators" in PART2
