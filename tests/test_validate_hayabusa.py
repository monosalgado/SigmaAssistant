"""Offline tests for eval/validate_hayabusa.py — R12.2, Hayabusa on SigmaHQ's known-answer recordings.

The plan was fixed in the log before this tool was written (2026-11-03, "Plan R12"): each recording is run on its own
with the converter's Sysmon copy of its rule and the settings pinned in R12.1; **agree** = Hayabusa's count equals
`match_count` (at least 1 when absent); a rule the converter skips is **not converted**, never a disagreement; the
events are compared with Zircolite's (R11.3, by Windows event record number). Found while building the tool: Hayabusa
can skip a converted rule silently (its own `exclude_rules.txt` lists one of the 138), so a rule Hayabusa does not load
is **not loaded**, listed apart with the reason. Hayabusa and the converter are never run here: fake runners write the
files they would write.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import yaml

from eval.validate_hayabusa import (
    SETTINGS,
    check_recording,
    command,
    convert_rules,
    converted_index,
    environment,
    parse_load,
    read_detections,
    summarise,
)

RULE_ID = "11111111-1111-1111-1111-111111111111"
CONVERTED_ID = "22222222-2222-2222-2222-222222222222"

LOADED = ("Loading detection rules. Please wait.\nExperimental rules: 1 (100.00%)\nSigma rules: 1\n"
          "Total detection rules: 1\nCreating the channel filter. Please wait.\n"
          "Evtx files loaded after channel filter: 1\nDetection rules enabled after channel filter: 1\n")
EXCLUDED = ("Loading detection rules. Please wait.\nExcluded rules: 1\nTotal detection rules: 0\n"
            "[ERROR] No rules were loaded. Please download the latest rules with the update-rules command.\n")
FILTERED = ("Total detection rules: 1\nCreating the channel filter. Please wait.\n"
            "Detection rules enabled after channel filter: 0\n")


# --- the command ------------------------------------------------------------------------------

def test_the_command_runs_one_rule_on_one_recording_with_the_pinned_settings(tmp_path):
    cmd = command(tmp_path / "H", "hayabusa-4.3.1-mac-aarch64", "a.evtx", "r.yml", tmp_path / "o.jsonl")
    assert cmd[:2] == [str(tmp_path / "H" / "hayabusa-4.3.1-mac-aarch64"), "dfir-timeline"]
    assert cmd[cmd.index("-f") + 1] == "a.evtx"
    assert cmd[cmd.index("-r") + 1] == "r.yml"
    assert cmd[cmd.index("-o") + 1] == str(tmp_path / "o.jsonl")
    joined = " ".join(SETTINGS)
    for setting in ("-w", "-p verbose", "-t jsonl", "-C", "-U"):
        assert setting in joined
    assert "-A" not in SETTINGS and "-D" not in SETTINGS  # pinned in R12.1: no channel-filter or status overrides


# --- reading what Hayabusa printed and wrote ----------------------------------------------------

def test_the_load_report_is_read_through_the_colour_codes():
    coloured = "\x1b[38;2;0;255;0mTotal detection rules: \x1b[0m1\n\x1b[0mDetection rules enabled after channel filter: 1\n"
    assert parse_load(coloured)["total_rules"] == 1
    assert parse_load(LOADED) == {"total_rules": 1, "enabled_after_channel_filter": 1, "excluded": 0, "noisy": 0,
                                  "no_rules_loaded": False}


def test_an_excluded_rule_is_seen_in_the_load_report():
    load = parse_load(EXCLUDED)
    assert load["excluded"] == 1 and load["total_rules"] == 0 and load["no_rules_loaded"] is True


def test_a_missing_load_report_is_unknown_not_zero():
    assert parse_load("something else\n") == {"total_rules": None, "enabled_after_channel_filter": None,
                                              "excluded": 0, "noisy": 0, "no_rules_loaded": False}


def test_detections_are_read_by_rule_id_with_their_record_numbers(tmp_path):
    out = tmp_path / "d.jsonl"
    out.write_text(json.dumps({"RuleID": CONVERTED_ID, "RecordID": 9}) + "\n"
                   + json.dumps({"RuleID": CONVERTED_ID, "RecordID": 4}) + "\n", encoding="utf-8")
    assert read_detections(out) == {CONVERTED_ID: {"count": 2, "record_ids": [4, 9]}}
    out.write_text("\n", encoding="utf-8")  # what Hayabusa writes when nothing matched
    assert read_detections(out) == {}
    assert read_detections(tmp_path / "missing.jsonl") is None


# --- the conversion ---------------------------------------------------------------------------

def _sysmon_copy(folder: Path, original_id: str, converted_id: str):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{original_id}.yml").write_text(yaml.safe_dump(
        {"title": "t", "id": converted_id, "related": [{"id": original_id, "type": "derived"}],
         "detection": {"selection": {"Image|endswith": "\\tool.exe"}, "condition": "selection"}}), encoding="utf-8")


def test_the_converted_index_maps_each_original_rule_to_its_sysmon_copy(tmp_path):
    _sysmon_copy(tmp_path / "out/sysmon", RULE_ID, CONVERTED_ID)
    _sysmon_copy(tmp_path / "out/builtin", RULE_ID, "33333333-3333-3333-3333-333333333333")
    index = converted_index(tmp_path / "out")
    assert set(index) == {RULE_ID}
    assert index[RULE_ID]["converted_id"] == CONVERTED_ID
    assert Path(index[RULE_ID]["path"]).parent.name == "sysmon"


def test_the_converter_runs_from_its_own_folder_on_a_folder_named_for_rules(tmp_path):
    rule = tmp_path / "sigma/some_rule.yml"
    rule.parent.mkdir(parents=True)
    rule.write_text(RULE_YAML, encoding="utf-8")
    calls = []

    def runner(cmd, **kwargs):
        calls.append((cmd, kwargs))
        _sysmon_copy(Path(cmd[cmd.index("-o") + 1]) / "sysmon", RULE_ID, CONVERTED_ID)
        return SimpleNamespace(returncode=0, stdout="", stderr="[INFO] [1] files created successfully.")

    index, report = convert_rules(tmp_path / "C", [rule], tmp_path / "work", runner)
    cmd, kwargs = calls[0]
    assert cmd[0] == str(tmp_path / "C" / ".venv/bin/python") and cmd[1] == "sigma-to-hayabusa-converter.py"
    assert kwargs["cwd"] == str(tmp_path / "C")  # it reads ignore-uuid-list.txt from its working folder
    source = Path(cmd[cmd.index("-r") + 1])
    assert "rule" in str(source)  # the converter only collects files under a folder path containing "rule"
    assert (source / "some_rule.yml").exists()
    assert index[RULE_ID]["converted_id"] == CONVERTED_ID and "files created" in report


# --- one recording, end to end, with a fake Hayabusa -------------------------------------------

RULE_YAML = f"""
title: Test rule
id: {RULE_ID}
logsource: {{category: process_creation, product: windows}}
detection:
  selection:
    Image|endswith: '\\\\tool.exe'
  condition: selection
"""


def _recording(root, match_count=1, evtx=1):
    rec = root / "regression_data/rules/windows/process_creation/some_rule"
    rec.mkdir(parents=True)
    info = {"rule_metadata": [{"id": RULE_ID}],
            "regression_tests_info": [{"name": "p", "type": "evtx", "match_count": match_count}]}
    if match_count is None:
        del info["regression_tests_info"][0]["match_count"]
    (rec / "info.yml").write_text(yaml.safe_dump(info), encoding="utf-8")
    for i in range(evtx):
        (rec / f"{RULE_ID}_{i}.evtx").write_bytes(b"ElfFile\x00")
    _sysmon_copy(root / "converted/sysmon", RULE_ID, CONVERTED_ID)
    return rec / "info.yml", converted_index(root / "converted")


def _fake(record_ids=None, stdout=LOADED, exit_code=0, write_out=True):
    calls = []

    def runner(cmd, **kwargs):
        calls.append((cmd, kwargs))
        out = Path(cmd[cmd.index("-o") + 1])
        if write_out:
            out.write_text("".join(json.dumps({"RuleID": CONVERTED_ID, "RecordID": i}) + "\n"
                                   for i in record_ids or []) or "\n", encoding="utf-8")
        return SimpleNamespace(returncode=exit_code, stdout=stdout, stderr="")

    return runner, calls


ZIRCOLITE = {RULE_ID: {"matched": 1, "record_ids": [7], "verdict": "agree"}}


def _check(info, converted, runner, zircolite=ZIRCOLITE, work="work", root=None):
    return check_recording(info, converted, root / "H", "hb", root / work, zircolite, runner)


def test_an_expected_match_agrees_and_hayabusa_runs_from_its_own_folder(tmp_path):
    info, converted = _recording(tmp_path)
    runner, calls = _fake([7])
    row = _check(info, converted, runner, root=tmp_path)
    assert row["verdict"] == "agree" and row["matched"] == 1 and row["record_ids"] == [7]
    assert row["converted_id"] == CONVERTED_ID
    assert calls[0][1]["cwd"] == str(tmp_path / "H")  # ./rules/config is found from there
    assert row["same_events_as_zircolite"] is True and row["zircolite_record_ids"] == [7]


def test_zero_matches_from_a_loaded_rule_is_a_disagreement(tmp_path):
    info, converted = _recording(tmp_path)
    runner, _ = _fake([])
    row = _check(info, converted, runner, root=tmp_path)
    assert row["verdict"] == "disagree" and row["matched"] == 0 and row["same_events_as_zircolite"] is False


def test_a_rule_hayabusa_excludes_is_not_loaded_never_a_disagreement(tmp_path):
    info, converted = _recording(tmp_path)
    runner, _ = _fake(None, stdout=EXCLUDED, exit_code=1, write_out=False)
    row = _check(info, converted, runner, root=tmp_path)
    assert row["verdict"] == "not loaded" and row["matched"] is None
    assert "exclude" in row["reason"]
    assert row["same_events_as_zircolite"] is None


def test_a_rule_dropped_by_the_channel_filter_is_not_loaded(tmp_path):
    info, converted = _recording(tmp_path)
    runner, _ = _fake([], stdout=FILTERED)
    row = _check(info, converted, runner, root=tmp_path)
    assert row["verdict"] == "not loaded" and "channel filter" in row["reason"]


def test_a_rule_without_a_sysmon_copy_is_not_converted_and_hayabusa_is_not_run(tmp_path):
    info, _ = _recording(tmp_path)
    runner, calls = _fake([7])
    row = _check(info, {}, runner, root=tmp_path)
    assert row["verdict"] == "not converted" and not calls


def test_a_failed_run_after_loading_is_a_tool_error(tmp_path):
    info, converted = _recording(tmp_path)
    runner, _ = _fake(None, exit_code=2, write_out=False)
    row = _check(info, converted, runner, root=tmp_path)
    assert row["verdict"] == "tool error" and row["exit_code"] == 2


def test_no_match_count_means_at_least_one(tmp_path):
    info, converted = _recording(tmp_path, match_count=None)
    runner, _ = _fake([1, 2])
    assert _check(info, converted, runner, root=tmp_path)["verdict"] == "agree"


def test_a_recording_with_several_evtx_files_is_listed_apart(tmp_path):
    info, converted = _recording(tmp_path, evtx=2)
    runner, calls = _fake([7])
    assert _check(info, converted, runner, root=tmp_path)["verdict"] == "several EVTX" and not calls


def test_without_a_zircolite_row_the_comparison_is_empty(tmp_path):
    info, converted = _recording(tmp_path)
    runner, _ = _fake([7])
    row = _check(info, converted, runner, zircolite={}, root=tmp_path)
    assert row["zircolite_matched"] is None and row["same_events_as_zircolite"] is None


# --- the pass rule fixed in the plan -----------------------------------------------------------

def _row(rid, verdict, hb_ids, z_ids, z_verdict="agree"):
    return {"rule_id": rid, "verdict": verdict, "record_ids": hb_ids,
            "matched": None if hb_ids is None else len(hb_ids),
            "zircolite_record_ids": z_ids, "zircolite_verdict": z_verdict,
            "same_events_as_zircolite": None if hb_ids is None or z_ids is None else hb_ids == z_ids}


def test_the_pass_rule_needs_the_same_events_and_no_fewer_agreements():
    rows = [_row("a", "agree", [1], [1]), _row("b", "disagree", [2, 3], [2, 3], "disagree"),
            _row("c", "not loaded", None, [5])]
    s = summarise(rows)
    assert s["same_events"] == 2 and s["compared"] == 2
    assert s["hayabusa_agree"] == 1 and s["zircolite_agree_on_evaluated"] == 1
    assert s["passed"] is True
    assert s["verdicts"]["not loaded"] == 1


def test_one_different_event_set_fails_the_pass_rule():
    s = summarise([_row("a", "agree", [1], [1]), _row("b", "agree", [2], [3])])
    assert s["same_events"] == 1 and s["passed"] is False


def test_fewer_agreements_than_zircolite_fails_the_pass_rule():
    s = summarise([_row("a", "disagree", [], [], "agree")])
    assert s["hayabusa_agree"] == 0 and s["zircolite_agree_on_evaluated"] == 1 and s["passed"] is False


# --- what the results record about the tools ---------------------------------------------------

def test_the_environment_records_versions_and_the_binarys_hash(tmp_path):
    h = tmp_path / "H"
    h.mkdir()
    (h / "hb").write_bytes(b"binary")

    def runner(cmd, **kwargs):
        if cmd[1:2] == ["help"]:
            return SimpleNamespace(returncode=0, stdout="Hayabusa v4.3.1 - Vulnpocalypse Release\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="0.18.5\n", stderr="")

    env = environment(h, "hb", tmp_path / "C", tmp_path, runner)
    assert env["hayabusa_version"] == "v4.3.1"
    assert env["hayabusa_sha256"] == hashlib.sha256(b"binary").hexdigest()
    assert env["ruamel_yaml"] == "0.18.5"
    assert env["settings"] == list(SETTINGS)
    assert env["hayabusa_rules_commit"] is None and env["converter_commit"] is None  # not git checkouts here
