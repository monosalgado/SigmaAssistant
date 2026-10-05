"""Tests for M1 (prompt review §5; user 2026-10-05: "go in that order"): every run records the rules as the rule
writer wrote them, before the review stage changed them, and the review's list of changes. Measurement only - the
rules a user gets are unchanged.

Why: today only the reviewed rules are saved, so whether review improves or harms a rule cannot be measured (it once
merged three generated rules into one, 2026-09-27). Offline.
"""

from __future__ import annotations

from backend.pipeline.orchestrator import PipelineOrchestrator

WRITTEN = "title: written\ndetection:\n  sel: {Image: a}\n  condition: sel\n"
REVIEWED = "title: reviewed\ndetection:\n  sel: {Image: b}\n  condition: sel\n"


def _context():
    return {"generation": {"rules": [{"yaml_content": WRITTEN, "explanation": "x"}]},
            "optimization": {"rules": [{"yaml_content": REVIEWED, "changes_made": ["changed Image"]}],
                             "all_changes": ["changed Image"]}}


def test_the_rules_before_review_and_the_reviews_changes_are_in_the_metadata():
    meta = PipelineOrchestrator._pipeline_metadata(_context())
    assert meta["pre_review_rules"] == [WRITTEN]
    assert meta["review_changes"] == ["changed Image"]


def test_without_a_generation_the_record_is_empty():
    meta = PipelineOrchestrator._pipeline_metadata({})
    assert meta["pre_review_rules"] == [] and meta["review_changes"] == []


def test_the_harness_saves_both_in_every_row():
    from eval.run_eval import DIAGNOSIS_FIELDS
    assert "pre_review_rules" in DIAGNOSIS_FIELDS and "review_changes" in DIAGNOSIS_FIELDS
