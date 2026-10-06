"""Change 43 is removed (user 2026-10-06: "remove change 43"): its tuning run failed the gate fixed before it - S4
C - B -0.035 [-0.102, +0.030]; exactly-10 lists fell only 40 -> 35 of 60, and the shorter lists dropped right
techniques too (a gold technique by parent 26 -> 21 of 42). The analysis's ATT&CK part returns to Change 32's wording.

The ceiling of 10 stays (user: without a limit the list "got stuck kinda on a loop" - defect 19: 336 invented
`T1562.xxx` sub-techniques until the answer was cut). Offline.
"""

from __future__ import annotations

from backend.pipeline import prompts

PART2 = " ".join(prompts.COMBINED_ANALYSIS.split("## PART 2")[1].split("## PART 3")[0].split())


def test_change_32s_wording_is_back():
    assert "List at most the 10 most relevant techniques, most relevant first" in PART2


def test_change_43s_wording_is_gone():
    assert "not a target" not in PART2
    assert "as many as the text gives evidence for" not in PART2
