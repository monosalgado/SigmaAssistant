"""Tests for #2 (pipeline quality, user 2026-10-05): the analysis's limit of 10 techniques is a limit, not a target.

Why: Change 32's "List at most the 10 most relevant techniques" became a quota - techniques listed per case, median
5 and exactly 10 in 5 of 60 before it (`p2f_product60`), median 10 and exactly 10 in 41-44 of 60 in every run since
(`p2g_shared60`, `c36_yaml60`, `c41A_tuning60`); gold rules tag 1 technique in 28 of 40. The wording now asks for the
techniques the text gives evidence for, with 10 as a ceiling. No typical number is suggested (the model decides).
Offline.
"""

from __future__ import annotations

import re

from backend.pipeline import prompts


def _part2() -> str:
    t = prompts.COMBINED_ANALYSIS
    return " ".join(t[t.index("## PART 2: MITRE ATT&CK TTP Mapping"):t.index("Each mapping needs:")].split())


def test_ten_stays_the_ceiling_but_is_not_a_target():
    part = _part2().lower()
    assert "never more than 10" in part
    assert "not a target" in part
    assert "at most the 10 most relevant" not in part


def test_the_list_follows_the_evidence_and_suggests_no_typical_count():
    part = _part2().lower()
    assert "as many as the text gives evidence for" in part
    assert not re.search(r"\b(usually|typically|about|around)\s+\d", part)
