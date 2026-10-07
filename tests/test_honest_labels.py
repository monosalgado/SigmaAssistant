"""Tests for Change 48 (#6 A, user 2026-10-07: "A alone first"): honest labels for the payload signatures.

Measured before (log 2026-10-07, `signature_grounding.py`, six runs): 15-18% of the attack-vector stage's signatures are
not in the report, almost none marked `inferred_from_class`, and the rule writer uses them as readily as the supported
ones (61-83% vs 72-84%) - the prompts present every signature as what "a real attacker MUST produce", require 1-8 of
them, and the coverage retry orders that each missed one "MUST literally" appear. The new wording says where each
candidate comes from and lets the writer leave out what the report does not support. Wording only. Offline.
"""

from __future__ import annotations

from backend.pipeline import prompts
from backend.pipeline.domain_knowledge import format_coverage_feedback


def _squash(text: str) -> str:
    return " ".join(text.split())


AV3 = _squash(prompts.ATTACK_VECTOR_EXTRACTION.split("### 3. Payload signatures")[1].split("### 4.")[0])


def test_the_attack_vector_stage_may_give_none_and_marks_what_the_text_does_not_show():
    assert "0-8" in AV3 and "1-8" not in AV3
    assert "REQUIRED" not in prompts.ATTACK_VECTOR_EXTRACTION.split("### 3. Payload signatures")[1].split("\n")[0]
    assert "only patterns the text or the PoC shows" in AV3
    assert "inferred_from_class" in AV3 and "an empty list is right" in AV3.lower()
    assert "MUST produce" not in AV3


def test_the_rule_writer_gets_candidates_with_where_they_come_from():
    gen = _squash(prompts.RULE_GENERATION)
    assert "MUST produce" not in gen and "### Payload Signatures" not in prompts.RULE_GENERATION
    assert "### Candidate patterns (proposed by the attack-vector stage" in prompts.RULE_GENERATION
    assert "use those the report supports" in gen
    assert "not something this report shows" in gen


def test_instruction_3_prefers_the_candidates_the_report_supports():
    instr = _squash(prompts.RULE_GENERATION.split("### Instructions")[1])
    third = instr.split(" 3. ")[1].split(" 4. ")[0]
    assert "whose quote shows they come from the report" in third
    assert "cannot avoid" not in third


def test_the_coverage_retry_lets_the_writer_leave_out_an_unsupported_candidate():
    text = format_coverage_feedback({"warnings": ["w"], "payload_signatures_missed": ["cmd /c"],
                                     "initial_access_covered": True})
    assert "MUST literally" not in text
    assert "use each one the report supports" in text.lower() and "leave out" in text and "`cmd /c`" in text
