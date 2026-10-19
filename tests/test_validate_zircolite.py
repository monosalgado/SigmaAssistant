"""Offline tests for eval/validate_zircolite.py — R11.3, Zircolite on SigmaHQ's known-answer recordings.

The plan was fixed in the log before this tool was written (2026-10-19, "Zircolite validation on SigmaHQ's
recordings: the plan"): each recording is run on its own with its own rule and fixed settings; **agree** = the rule
converted and the number of matching events equals `match_count` (at least 1 when absent); **disagree** = converted,
any other number; listed apart: **not converted**, **tool error**, **rule not found**. Cross-checks: the same events
as our matcher (`eval/rule_matcher.py`, by EventRecordID), and off-target matches (every rule against each
recording). Zircolite is never run here: a fake runner writes the files Zircolite would write.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from eval.validate_zircolite import (
    SETTINGS,
    check_recording,
    command,
    environment,
    matcher_events,
    off_target_pairs,
    parse_conversion,
    read_detections,
    verdict,
)

RULE_ID = "11111111-1111-1111-1111-111111111111"


# --- the command ------------------------------------------------------------------------------

def test_the_command_uses_zircolites_own_python_and_the_fixed_settings(tmp_path):
    cmd = command(tmp_path / "Z", ["a.evtx"], ["r1.yml", "r2.yml"], tmp_path / "o.json", tmp_path / "o.log")
    assert cmd[:3] == [str(tmp_path / "Z" / ".venv/bin/python"), "-m", "zircolite"]
    assert cmd[cmd.index("--events") + 1] == "a.evtx"
    assert cmd[cmd.index("--ruleset") + 1:cmd.index("--ruleset") + 3] == ["r1.yml", "r2.yml"]
    assert cmd[cmd.index("--outfile") + 1] == str(tmp_path / "o.json")
    assert cmd[cmd.index("--logfile") + 1] == str(tmp_path / "o.log")
    for setting in SETTINGS:
        assert setting in cmd
    joined = " ".join(SETTINGS)
    assert "--pipeline sysmon" in joined and "--pipeline windows-logsources" in joined
    assert "--flatten-backend cython" in joined and "--limit -1" in joined


# --- reading what Zircolite wrote --------------------------------------------------------------

def test_the_conversion_line_is_read_through_the_colour_markup():
    log = ("2026-10-19 18:54:39 INFO     [green]\\[✓][/] Converted [cyan]1[/] rules\n"
           "2026-10-19 18:54:39 INFO     [+] 1 rules loaded\n")
    assert parse_conversion(log) == {"converted": 1, "skipped": 0, "failed": 0, "loaded": 1}
    log = "INFO [✓] Converted 245 rules (3 invalid skipped, 2 failed)\nINFO [+] 240 rules loaded\n"
    assert parse_conversion(log) == {"converted": 245, "skipped": 3, "failed": 2, "loaded": 240}


def test_no_conversion_line_is_unknown_not_zero():
    assert parse_conversion("ERROR something else\n") == {"converted": None, "skipped": 0, "failed": 0,
                                                         "loaded": None}


def test_detections_are_read_by_rule_id_with_their_record_ids(tmp_path):
    out = tmp_path / "d.json"
    out.write_text(json.dumps([{"id": RULE_ID, "title": "t", "count": 2,
                                "matches": [{"EventRecordID": 9}, {"EventRecordID": 4}]}]), encoding="utf-8")
    assert read_detections(out) == {RULE_ID: {"count": 2, "record_ids": [4, 9]}}
    out.write_text("[]", encoding="utf-8")
    assert read_detections(out) == {}
    assert read_detections(tmp_path / "missing.json") is None


def test_the_verdict_is_the_matchers_definition():
    assert verdict(1, 1) == "agree"
    assert verdict(1, 3) == "disagree"
    assert verdict(1, 0) == "disagree"
    assert verdict(None, 2) == "agree"
    assert verdict(None, 0) == "disagree"


def test_off_target_pairs_leave_out_the_recordings_own_rule():
    detections = {RULE_ID: {"count": 1, "record_ids": [1]}, "b": {"count": 3, "record_ids": [1, 2, 3]},
                  "a": {"count": 1, "record_ids": [2]}}
    assert off_target_pairs(detections, RULE_ID) == [["a", 1], ["b", 3]]


# --- one recording, end to end, with a fake Zircolite ------------------------------------------

def _recording(root, match_count=1, json_events=None):
    rec = root / "regression_data/rules/windows/process_creation/some_rule"
    rec.mkdir(parents=True)
    info = {"rule_metadata": [{"id": RULE_ID}],
            "regression_tests_info": [{"name": "p", "type": "evtx", "match_count": match_count}]}
    if match_count is None:
        del info["regression_tests_info"][0]["match_count"]
    import yaml
    (rec / "info.yml").write_text(yaml.safe_dump(info), encoding="utf-8")
    (rec / f"{RULE_ID}.evtx").write_bytes(b"ElfFile\x00")
    if json_events is not None:
        (rec / f"{RULE_ID}.json").write_text(json.dumps(json_events), encoding="utf-8")
    rule = root / "rules/some_rule.yml"
    rule.parent.mkdir(parents=True, exist_ok=True)
    rule.write_text(RULE_YAML, encoding="utf-8")
    return rec / "info.yml", {RULE_ID: rule}


RULE_YAML = f"""
title: Test rule
id: {RULE_ID}
logsource: {{category: process_creation, product: windows}}
detection:
  selection:
    Image|endswith: '\\\\tool.exe'
  condition: selection
"""


def _fake(detections=None, converted=1, exit_code=0, write_out=True):
    calls = []

    def runner(cmd, **kwargs):
        calls.append((cmd, kwargs))
        out = Path(cmd[cmd.index("--outfile") + 1])
        log = Path(cmd[cmd.index("--logfile") + 1])
        log.write_text(f"INFO [✓] Converted {converted} rules\nINFO [+] {converted} rules loaded\n", encoding="utf-8")
        if write_out:
            out.write_text(json.dumps(detections or []), encoding="utf-8")
        return SimpleNamespace(returncode=exit_code, stdout="", stderr="")

    return runner, calls


def _det(n, ids):
    return [{"id": RULE_ID, "title": "t", "count": n, "matches": [{"EventRecordID": i} for i in ids]}]


def test_an_expected_match_agrees_and_zircolite_runs_without_its_cache(tmp_path):
    info, index = _recording(tmp_path)
    runner, calls = _fake(_det(1, [7]))
    row = check_recording(info, index, tmp_path / "Z", tmp_path / "work", runner)
    assert row["verdict"] == "agree" and row["matched"] == 1 and row["record_ids"] == [7]
    assert calls[0][1]["env"]["ZIRCOLITE_NO_CACHE"] == "1"
    assert calls[0][1]["cwd"] == str(tmp_path / "Z")


def test_zero_matches_from_a_converted_rule_is_a_disagreement(tmp_path):
    info, index = _recording(tmp_path)
    runner, _ = _fake([])
    row = check_recording(info, index, tmp_path / "Z", tmp_path / "work", runner)
    assert row["verdict"] == "disagree" and row["matched"] == 0


def test_a_rule_that_does_not_convert_is_listed_apart_never_as_no_match(tmp_path):
    info, index = _recording(tmp_path)
    runner, _ = _fake(None, converted=0, exit_code=1, write_out=False)
    row = check_recording(info, index, tmp_path / "Z", tmp_path / "work", runner)
    assert row["verdict"] == "not converted" and row["matched"] is None


def test_a_failed_run_is_a_tool_error(tmp_path):
    info, index = _recording(tmp_path)
    runner, _ = _fake(None, converted=1, exit_code=2, write_out=False)
    row = check_recording(info, index, tmp_path / "Z", tmp_path / "work", runner)
    assert row["verdict"] == "tool error" and row["exit_code"] == 2


def test_a_missing_rule_is_listed_and_zircolite_is_not_run(tmp_path):
    info, _ = _recording(tmp_path)
    runner, calls = _fake(_det(1, [7]))
    row = check_recording(info, {}, tmp_path / "Z", tmp_path / "work", runner)
    assert row["verdict"] == "rule not found" and not calls


def test_no_match_count_means_at_least_one(tmp_path):
    info, index = _recording(tmp_path, match_count=None)
    runner, _ = _fake(_det(2, [1, 2]))
    assert check_recording(info, index, tmp_path / "Z", tmp_path / "work", runner)["verdict"] == "agree"


# --- the cross-check with our matcher ----------------------------------------------------------

def _raw(record_id, image):
    return {"Event": {"System": {"EventID": 1, "EventRecordID": record_id, "Channel": "x"},
                      "EventData": {"Image": image}}}


def test_our_matcher_reports_the_record_ids_it_matches(tmp_path):
    info, index = _recording(tmp_path, json_events=[_raw(5, "C:\\a\\tool.exe"), _raw(7, "C:\\a\\other.exe")])
    count, ids = matcher_events(index[RULE_ID], sorted(info.parent.glob("*.json")))
    assert (count, ids) == (1, [5])


def test_the_row_says_whether_both_tools_matched_the_same_events(tmp_path):
    info, index = _recording(tmp_path, json_events=[_raw(5, "C:\\a\\tool.exe"), _raw(7, "C:\\a\\other.exe")])
    runner, _ = _fake(_det(1, [5]))
    row = check_recording(info, index, tmp_path / "Z", tmp_path / "work", runner)
    assert row["matcher_record_ids"] == [5] and row["same_events_as_matcher"] is True
    runner, _ = _fake(_det(1, [7]))
    row = check_recording(info, index, tmp_path / "Z", tmp_path / "work2", runner)
    assert row["same_count_as_matcher"] is True and row["same_events_as_matcher"] is False


def test_without_json_the_matcher_columns_are_empty(tmp_path):
    info, index = _recording(tmp_path)
    runner, _ = _fake(_det(1, [5]))
    row = check_recording(info, index, tmp_path / "Z", tmp_path / "work", runner)
    assert row["matcher_count"] is None and row["same_events_as_matcher"] is None


# --- what the results record about the tool ----------------------------------------------------

def test_the_environment_records_the_lock_files_hash(tmp_path):
    z = tmp_path / "Z"
    z.mkdir()
    (z / "uv.lock").write_bytes(b"lock")
    env = environment(z, tmp_path, version_runner=lambda cmd, **kw: SimpleNamespace(returncode=0,
                                                                                   stdout="Zircolite - v4.6.0\n",
                                                                                   stderr=""))
    assert env["uv_lock_sha256"] == hashlib.sha256(b"lock").hexdigest()
    assert env["zircolite_version"] == "v4.6.0"
    assert env["settings"] == list(SETTINGS)
    assert env["zircolite_commit"] is None  # not a git checkout here
