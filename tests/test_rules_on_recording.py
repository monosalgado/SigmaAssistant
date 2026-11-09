"""Offline tests for eval/rules_on_recording.py - the Change 54 real-attack check `[DEMO]` (plan in the log
2026-11-09): each arm's rules for a report run on the report's SigmaHQ recording, each rule on its own, with Zircolite
and Hayabusa, and the expert rule too. Caught = a rule matches an event the expert rule matches (Zircolite; Hayabusa
as a cross-check). A rule that does not parse or that an engine cannot run is shown as such, never as 0 matches.
The engines are never run here."""

from __future__ import annotations

import json

import pytest
import yaml

from eval.rules_on_recording import case_row, caught, judge, recording, write_rules

RULE = """title: A
id: 11111111-1111-1111-1111-111111111111
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        ParentImage|endswith: '\\\\node.exe'
    condition: sel
"""


def test_each_rule_gets_its_own_file_and_a_fresh_id_and_nothing_else_changes(tmp_path):
    written = write_rules([RULE, RULE.replace("title: A", "title: B")], tmp_path, "B-271de298")
    docs = [yaml.safe_load(open(w["path"], encoding="utf-8")) for w in written]
    assert docs[0]["id"] != docs[1]["id"] and docs[0]["id"] != "11111111-1111-1111-1111-111111111111"
    assert docs[0]["detection"] == yaml.safe_load(RULE)["detection"]  # values exactly as written
    assert [d["title"] for d in docs] == ["A", "B"] and [w["index"] for w in written] == [1, 2]


def test_the_fresh_ids_are_the_same_on_every_run(tmp_path):
    first = yaml.safe_load(open(write_rules([RULE], tmp_path / "1", "A-x")[0]["path"]))["id"]
    again = yaml.safe_load(open(write_rules([RULE], tmp_path / "2", "A-x")[0]["path"]))["id"]
    assert first == again


def test_a_rule_that_does_not_parse_or_is_not_a_rule_is_noted_not_written(tmp_path):
    written = write_rules(["title: [unclosed", "just: text"], tmp_path, "A-x")
    assert [w["path"] for w in written] == [None, None]
    assert written[0]["note"].startswith("does not parse") and written[1]["note"] == "not a rule (no detection)"


def _result(z_status="ran", z_ids=(), h_status="ran", h_ids=(), same=None):
    return {"zircolite": {"status": z_status, "record_ids": list(z_ids) if z_status == "ran" else None},
            "hayabusa": {"status": h_status, "record_ids": list(h_ids) if h_status == "ran" else None},
            "same_events": same}


def test_matches_are_split_into_the_expert_rules_events_and_others():
    j = judge(_result(z_ids=[3, 5, 9], h_ids=[3, 5, 9], same=True), {3, 4})
    assert j["on_expert_zircolite"] == [3] and j["other_zircolite"] == 2
    assert j["on_expert_hayabusa"] == [3] and j["same_events"] is True


def test_an_engine_that_could_not_run_the_rule_is_never_zero():
    j = judge(_result(z_status="not converted", h_status="not loaded"), {3})
    assert j["on_expert_zircolite"] is None and j["other_zircolite"] is None and j["on_expert_hayabusa"] is None
    assert j["zircolite_status"] == "not converted" and j["hayabusa_status"] == "not loaded"


def test_caught_needs_a_zircolite_match_on_an_expert_event():
    assert caught([judge(_result(z_ids=[9]), {3}), judge(_result(z_ids=[3]), {3})]) is True
    assert caught([judge(_result(z_ids=[9], h_ids=[3]), {3})]) is False
    assert caught([judge(_result(z_status="tool error"), {3})]) is False


def test_the_case_row_is_found_by_its_rule_id(tmp_path):
    path = tmp_path / "rows.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in [{"rule_id": "a1", "rules_yaml": ["x"]},
                                                            {"rule_id": "b2", "rules_yaml": ["y"]}]), encoding="utf-8")
    assert case_row(path, "b2")["rules_yaml"] == ["y"] and case_row(path, "c3") is None


def test_the_recording_is_the_one_evtx_file_in_the_folder(tmp_path):
    (tmp_path / "x.evtx").write_bytes(b"")
    (tmp_path / "info.yml").write_text("id: 1\n", encoding="utf-8")
    assert recording(tmp_path) == tmp_path / "x.evtx"
    (tmp_path / "y.evtx").write_bytes(b"")
    with pytest.raises(ValueError):
        recording(tmp_path)
