"""Tests for Change 44 (#3; user 2026-10-05: "bundle the fix"): the review prompt's illustration of a placeholder path
uses placeholders, not the Citrix demo report's value.

Why: `COMBINED_REVIEW` item 8 used `/metadata/samlidp/asdf` -> `|startswith: '/metadata/samlidp/'`. It was never copied
(0 of 2,540 saved reports, log 2026-10-05), so this is done on principle - realistic values in prompts get copied
(Changes 27, 30, 39) - and it is measured together with the next review-prompt change. As in Change 30, the new
placeholders become counted markers, so a copied placeholder would show. Offline.
"""

from __future__ import annotations

import re

from backend.pipeline import prompts
from eval.count_example_copies import REVIEW_EXAMPLES

ITEM8 = prompts.COMBINED_REVIEW[prompts.COMBINED_REVIEW.index("8. **PoC placeholder leakage**"):
                                prompts.COMBINED_REVIEW.index("## PART 2")]


def test_the_citrix_value_is_gone():
    assert "samlidp" not in prompts.COMBINED_REVIEW.lower() and "/metadata/" not in prompts.COMBINED_REVIEW


def test_the_stable_prefix_idea_is_still_illustrated_with_placeholders():
    assert "|startswith:" in ITEM8
    assert re.findall(r"<[a-z][a-z ]*>", ITEM8)


def test_every_placeholder_in_the_illustration_is_a_counted_marker():
    for placeholder in set(re.findall(r"<[a-z][a-z ]*>", ITEM8)):
        assert placeholder in REVIEW_EXAMPLES, placeholder
    assert "samlidp" in REVIEW_EXAMPLES                          # the old value stays counted
