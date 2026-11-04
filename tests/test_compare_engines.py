"""Offline tests for eval/compare_engines.py — R12.3 `[DEMO]`: the same rule through Hayabusa and Zircolite on the
same recording (plan in the log 2026-11-03, "Plan R12", step 3; both engines validated first, R11.3 and R12.2).

Each rule runs on its own in each engine; Hayabusa runs the converter's Sysmon copy. The row keeps each engine's count
and the events it matched (Windows event record numbers), and says whether the two found the same events. A rule one
engine could not run (not converted, not loaded, tool error) is shown as such, never as 0 matches. The engines are
never run here: fake runners write the files they would write.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from eval.compare_engines import compare_rule, summarise

RULE_ID = "11111111-1111-1111-1111-111111111111"
CONVERTED_ID = "22222222-2222-2222-2222-222222222222"
LOADED = "Total detection rules: 1\nDetection rules enabled after channel filter: 1\n"
EXCLUDED = "Excluded rules: 1\nTotal detection rules: 0\n[ERROR] No rules were loaded.\n"

RULE_YAML = f"""
title: Test rule
id: {RULE_ID}
logsource: {{category: process_creation, product: windows}}
detection:
  selection:
    Image|endswith: '\\\\tool.exe'
  condition: selection
"""


def _rule(tmp_path):
    rule = tmp_path / "rules/some_rule.yml"
    rule.parent.mkdir(parents=True)
    rule.write_text(RULE_YAML, encoding="utf-8")
    return rule


CONVERTED = {RULE_ID: {"path": "converted/sysmon/some_rule.yml", "converted_id": CONVERTED_ID}}


def _zircolite(record_ids=None, converted=1, exit_code=0, write_out=True):
    def runner(cmd, **kwargs):
        out = Path(cmd[cmd.index("--outfile") + 1])
        log = Path(cmd[cmd.index("--logfile") + 1])
        log.write_text(f"INFO [✓] Converted {converted} rules\nINFO [+] {converted} rules loaded\n", encoding="utf-8")
        if write_out:
            dets = ([{"id": RULE_ID, "title": "Test rule", "count": len(record_ids),
                      "matches": [{"EventRecordID": i} for i in record_ids]}] if record_ids else [])
            out.write_text(json.dumps(dets), encoding="utf-8")
        return SimpleNamespace(returncode=exit_code, stdout="", stderr="")
    return runner


def _hayabusa(record_ids=None, stdout=LOADED, exit_code=0, write_out=True):
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        out = Path(cmd[cmd.index("-o") + 1])
        if write_out:
            out.write_text("".join(json.dumps({"RuleID": CONVERTED_ID, "RecordID": i}) + "\n"
                                   for i in record_ids or []) or "\n", encoding="utf-8")
        return SimpleNamespace(returncode=exit_code, stdout=stdout, stderr="")
    runner.calls = calls
    return runner


def _compare(tmp_path, zrunner, hrunner, converted=CONVERTED):
    return compare_rule(_rule(tmp_path), tmp_path / "rec.evtx", converted, tmp_path / "Z", tmp_path / "H", "hb",
                        tmp_path / "work", zrunner, hrunner)


def test_both_engines_finding_the_same_events_is_recorded(tmp_path):
    row = _compare(tmp_path, _zircolite([5, 7]), _hayabusa([7, 5]))
    assert row["rule_id"] == RULE_ID and row["title"] == "Test rule" and row["converted_id"] == CONVERTED_ID
    assert row["zircolite"] == {"status": "ran", "matched": 2, "record_ids": [5, 7], "reason": ""}
    assert row["hayabusa"]["status"] == "ran" and row["hayabusa"]["record_ids"] == [5, 7]
    assert row["same_events"] is True


def test_zero_in_both_is_the_same_events(tmp_path):
    row = _compare(tmp_path, _zircolite([]), _hayabusa([]))
    assert row["zircolite"]["matched"] == 0 and row["hayabusa"]["matched"] == 0 and row["same_events"] is True


def test_different_events_are_recorded_as_a_difference(tmp_path):
    row = _compare(tmp_path, _zircolite([5]), _hayabusa([6]))
    assert row["same_events"] is False


def test_a_rule_hayabusa_does_not_load_is_shown_never_as_zero(tmp_path):
    row = _compare(tmp_path, _zircolite([5]), _hayabusa(None, stdout=EXCLUDED, exit_code=1, write_out=False))
    assert row["hayabusa"]["status"] == "not loaded" and row["hayabusa"]["matched"] is None
    assert "exclude" in row["hayabusa"]["reason"] and row["same_events"] is None


def test_a_rule_without_a_sysmon_copy_is_not_run_in_hayabusa(tmp_path):
    hrunner = _hayabusa([5])
    row = _compare(tmp_path, _zircolite([5]), hrunner, converted={})
    assert row["hayabusa"]["status"] == "not converted" and not hrunner.calls and row["same_events"] is None


def test_a_rule_zircolite_cannot_convert_is_shown_never_as_zero(tmp_path):
    row = _compare(tmp_path, _zircolite(None, converted=0, exit_code=1, write_out=False), _hayabusa([5]))
    assert row["zircolite"]["status"] == "not converted" and row["zircolite"]["matched"] is None
    assert row["same_events"] is None


def test_a_failed_zircolite_run_is_a_tool_error(tmp_path):
    row = _compare(tmp_path, _zircolite(None, exit_code=2, write_out=False), _hayabusa([5]))
    assert row["zircolite"]["status"] == "tool error"


def test_the_summary_counts_rules_both_ran_and_agreements():
    rows = [{"same_events": True, "zircolite": {"matched": 2}, "hayabusa": {"matched": 2}},
            {"same_events": False, "zircolite": {"matched": 1}, "hayabusa": {"matched": 0}},
            {"same_events": None, "zircolite": {"matched": 1}, "hayabusa": {"matched": None}}]
    s = summarise(rows)
    assert s == {"rules": 3, "both_ran": 2, "same_events": 1, "same_count": 1, "differ": 1}
