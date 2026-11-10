"""Offline tests for Change 55 (plan approved by the user 2026-11-09; log "Change 55 planned"): every rule must run.

The review stage checked the rules it received but never the rules the model returned: in the 12 runs that saved both,
review broke 382 rules (mostly `all of selection_*` rewritten as `all of selection_ *`) and fixed none. Now code checks
each returned rule with the same `validate_rule_text`; a rule review broke is kept as it was before review, and the
revert is recorded. No new model call. Offline: a stand-in client.
"""

from __future__ import annotations

import json

from backend.pipeline.orchestrator import PipelineOrchestrator
from backend.pipeline.stage_review import ReviewStage, keep_runnable

GOOD = """title: Good
id: 11111111-2222-3333-4444-555555555555
status: experimental
description: d
author: a
date: 2026-11-09
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\\\\node.exe'
    selection_child:
        Image|endswith: '\\\\cmd.exe'
    condition: all of selection_*
level: high
"""
BROKEN = GOOD.replace("all of selection_*", "all of selection_ *")
IMPROVED = GOOD.replace("level: high", "level: medium")


def _r(text, changes=()):
    return {"yaml_content": text, "changes_made": list(changes)}


def test_a_rule_review_broke_is_kept_as_before_review():
    final, reverted = keep_runnable([_r(GOOD), _r(GOOD)], [_r(BROKEN, ["tidied"]), _r(IMPROVED, ["level"])])
    assert [f["yaml_content"] for f in final] == [GOOD, IMPROVED]
    assert final[0]["changes_made"] == [] and final[1]["changes_made"] == ["level"]
    assert len(reverted) == 1 and reverted[0]["rule"] == 1 and reverted[0]["reason"] == "review broke a rule that passed"
    assert "Condition could not be resolved" in reverted[0]["error"]


def test_a_returned_rule_that_fails_where_the_rule_before_review_failed_too_is_left_as_review_wrote_it():
    final, reverted = keep_runnable([_r(BROKEN)], [_r(BROKEN, ["x"])])
    assert final == [_r(BROKEN, ["x"])] and reverted == []


def test_when_review_changes_the_number_of_rules_and_one_fails_every_rule_before_review_is_kept():
    final, reverted = keep_runnable([_r(GOOD), _r(GOOD)], [_r(IMPROVED), _r(GOOD), _r(BROKEN)])
    assert [f["yaml_content"] for f in final] == [GOOD, GOOD]
    assert reverted == [{"rule": None, "reason": "review changed the number of rules and returned a rule that fails",
                         "failed": [3]}]


def test_when_review_changes_the_number_of_rules_and_all_run_reviews_rules_stay():
    final, reverted = keep_runnable([_r(GOOD)], [_r(IMPROVED), _r(GOOD)])
    assert [f["yaml_content"] for f in final] == [IMPROVED, GOOD] and reverted == []


def test_no_rules_returned_changes_nothing():
    assert keep_runnable([_r(GOOD)], []) == ([], [])


class _Client:
    model_name = "fake"

    def __init__(self, answer):
        self.answer = answer

    def generate(self, prompt, **kwargs):
        return json.dumps(self.answer)


def test_the_review_stage_keeps_the_rule_before_review_and_records_the_revert():
    answer = {"is_valid": True, "issues": [], "review_summary": "s",
              "optimized_rules": [{"yaml_content": BROKEN, "changes_made": ["tidied"]},
                                  {"yaml_content": IMPROVED, "changes_made": ["level"]}]}
    context = {"generation": {"rules": [{"yaml_content": GOOD}, {"yaml_content": GOOD}]},
               "extraction": {"attack_summary": "a", "indicators": []}}
    out = ReviewStage(_Client(answer), "fake", None).run(context)
    assert [r["yaml_content"] for r in out["optimization"]["rules"]] == [GOOD, IMPROVED]
    assert out["optimization"]["all_changes"] == ["level"]
    assert out["optimization"]["reverted"][0]["rule"] == 1
    assert out["validation"]["corrected_rules"] == [GOOD, IMPROVED]


def test_the_analysis_record_carries_the_reverts():
    meta = PipelineOrchestrator._pipeline_metadata({"optimization": {"reverted": [{"rule": 1}]}})
    assert meta["review_reverted"] == [{"rule": 1}]
    assert PipelineOrchestrator._pipeline_metadata({})["review_reverted"] == []
