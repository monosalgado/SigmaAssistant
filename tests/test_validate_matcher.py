"""Tests for validating the rule evaluator on SigmaHQ's regression recordings (definition fixed in the log
2026-10-04): each recording's rule, found by id, runs over the recording's JSON events; it agrees when the number of
matching events equals `match_count` (at least 1 when absent). No JSON, no rule, or "cannot evaluate" is listed
apart with its reason. Offline; a made-up recording.
"""

from __future__ import annotations

import json

import yaml

from eval.validate_matcher import check_recording, off_target, rule_index

RULE_ID = "11111111-2222-3333-4444-555555555555"
RULE = {"title": "Evil child", "id": RULE_ID, "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"sel": {"Image|endswith": "\\evil.exe"}, "condition": "sel"}}


def _event(image):
    return {"Event": {"System": {"EventID": 1}, "EventData": {"Image": image}}}


def _setup(tmp_path, events, match_count=1, rule=RULE, with_json=True):
    rules = tmp_path / "rules"
    rules.mkdir(exist_ok=True)
    (rules / "r.yml").write_text(yaml.safe_dump(rule))
    rec = tmp_path / "regression_data" / "r"
    rec.mkdir(parents=True, exist_ok=True)
    test = {"name": "Positive Detection Test", "type": "evtx", "path": "x.evtx"}
    if match_count is not None:
        test["match_count"] = match_count
    (rec / "info.yml").write_text(yaml.safe_dump({"rule_metadata": [{"id": RULE_ID}],
                                                 "regression_tests_info": [test]}))
    if with_json:
        (rec / f"{RULE_ID}.json").write_text("\n".join(json.dumps(e, indent=2) for e in events))
    return rec / "info.yml", rule_index([rules])


def test_the_rule_is_found_by_its_id(tmp_path):
    _, index = _setup(tmp_path, [_event("C:\\evil.exe")])
    assert RULE_ID in index


def test_a_recording_agrees_when_the_count_is_the_expected_one(tmp_path):
    info, index = _setup(tmp_path, [_event("C:\\evil.exe")])
    assert check_recording(info, index)["verdict"] == "agree"


def test_a_wrong_count_disagrees(tmp_path):
    info, index = _setup(tmp_path, [_event("C:\\evil.exe"), _event("D:\\evil.exe")])
    r = check_recording(info, index)
    assert r["verdict"] == "disagree" and (r["matched"], r["expected"]) == (2, 1)


def test_without_a_count_at_least_one_match_agrees(tmp_path):
    info, index = _setup(tmp_path, [_event("C:\\evil.exe"), _event("D:\\evil.exe")], match_count=None)
    assert check_recording(info, index)["verdict"] == "agree"
    info, index = _setup(tmp_path, [_event("C:\\good.exe")], match_count=None)
    assert check_recording(info, index)["verdict"] == "disagree"


def test_no_json_or_a_rule_that_cannot_be_evaluated_is_listed_apart(tmp_path):
    info, index = _setup(tmp_path, [], with_json=False)
    assert check_recording(info, index)["verdict"] == "no JSON"
    bad = dict(RULE, detection={"sel": {"Image": "x"}, "condition": "sel | count() > 5"})
    info, index = _setup(tmp_path, [_event("x")], rule=bad)
    r = check_recording(info, index)
    assert r["verdict"] == "cannot evaluate" and "SigmaConditionError" in r["reason"]


def test_off_target_matches_are_listed(tmp_path):
    info, index = _setup(tmp_path, [_event("C:\\evil.exe")])
    other = [{"rule_id": "other", "events": [{"Image": "X:\\evil.exe"}, {"Image": "X:\\fine.exe"}]}]
    assert off_target(RULE_ID, index, other) == [("other", 1)]
