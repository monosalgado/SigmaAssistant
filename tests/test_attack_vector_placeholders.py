"""Offline tests for Change 30 (defect 15 at its cause; user, 2026-09-26: options a + b).

With this model a concrete worked example is copied into reports that resemble it:
replacing the web example with an email one (Change 27) moved the copying — the new
example's invented `qx7loader.dll` / `QxUpdate` reached two cases' rules. So the examples
keep their structure (what to put in each field, attacker activity vs researcher workflow)
but their invented values become placeholders (b), and the prompt says the examples are
invented and nothing in them may be reused (a). The placeholders are fixed in the copy
counter's markers (`eval/probe_attack_vector.py`), so a copied placeholder is counted.
"""

from __future__ import annotations

import re

from backend.pipeline import prompts
from eval.probe_attack_vector import EXAMPLE_MARKERS

AV = prompts.ATTACK_VECTOR_EXTRACTION
EXAMPLES = AV.split("### Few-shot Examples", 1)[1]
PLACEHOLDERS = set(EXAMPLE_MARKERS["placeholders"])


def test_no_invented_example_value_is_left_anywhere_in_the_prompt():
    for group, markers in EXAMPLE_MARKERS.items():
        if group == "placeholders":
            continue
        for m in markers:
            assert m not in AV.lower(), (group, m)


def test_the_examples_use_only_placeholders_the_counter_knows():
    found = set(re.findall(r"<[a-z][a-z -]*>", EXAMPLES))
    assert found, "the examples should use placeholders"
    assert found <= PLACEHOLDERS, found - PLACEHOLDERS


def test_every_counted_placeholder_is_in_the_prompt():
    assert all(p in AV for p in PLACEHOLDERS), [p for p in PLACEHOLDERS if p not in AV]


def test_the_model_is_told_the_examples_are_invented_and_never_to_reuse_them():
    note = EXAMPLES.split("**Example A")[0].lower()
    assert "invented" in note and "placeholder" in note
    assert "never reuse" in note
    assert "from the input text" in note


def test_the_structure_the_examples_teach_is_kept():
    """Generic, real tool names stay: they show the kind of evidence, not a case's facts."""
    assert "rundll32.exe" in EXAMPLES and "Upgrade: websocket" in EXAMPLES
    assert EXAMPLES.count("**Example ") == 3


# --- Change 39 (2026-10-03, user: "remove the copied prompt examples") --------------------------------
# The description of a payload signature's `pattern` gave six literal attack strings as examples. They reach
# rules in 1-4 of 60 reports per run without being in the report (`count_example_copies.py`, nine runs), e.g.
# `$(nslookup` in a rule for a deserialization flaw. The list is deleted, not replaced by placeholders
# (placeholders are copied too, Change 30); the worked examples below still show what a pattern looks like.

from eval.count_example_copies import INLINE_EXAMPLES  # noqa: E402


def test_no_inline_example_string_is_left_in_the_prompt():
    for example in INLINE_EXAMPLES:
        assert example not in AV.lower(), example


def test_the_pattern_field_is_still_described():
    instructions = AV.split("### Few-shot Examples", 1)[0]
    line = next(l for l in instructions.splitlines() if l.strip().startswith("- `pattern`"))
    assert "literal string or simple regex" in line


def test_the_worked_examples_still_show_patterns():
    assert '"pattern": "' in EXAMPLES
