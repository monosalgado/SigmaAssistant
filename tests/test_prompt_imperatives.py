"""Tests for #6's inventory (the prompt review's P3, user 2026-10-07): the capitalised orders in each prompt and in the
blocks code adds at run time (the kill-chain block, the coverage retry's block). Counted words: MUST, NEVER, MANDATORY,
REQUIRED, ALWAYS, ONLY, DO NOT, NOT, AT LEAST, CRITICAL, IMPORTANT - in capitals only (a lower-case "must" is not counted).
Offline.
"""

from __future__ import annotations

from eval.prompt_imperatives import count_orders, runtime_blocks


def test_capitalised_orders_are_counted_and_lower_case_is_not():
    text = "You MUST do this. NEVER that. It must be fine. Do NOT copy. AT LEAST one rule, MANDATORY. REQUIRED field."
    assert count_orders(text) == {"MUST": 1, "NEVER": 1, "NOT": 1, "AT LEAST": 1, "MANDATORY": 1, "REQUIRED": 1}


def test_the_runtime_blocks_are_the_ones_code_adds():
    blocks = runtime_blocks()
    assert set(blocks) == {"kill-chain block (2+ stages)", "coverage retry block (all gaps)"}
    assert "MANDATORY" in blocks["kill-chain block (2+ stages)"]
    assert "leave out" in blocks["coverage retry block (all gaps)"]   # Change 48 replaced "MUST literally contain"
