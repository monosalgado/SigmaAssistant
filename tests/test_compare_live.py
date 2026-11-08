"""Offline tests for eval/compare_live.py - R12.4 `[DEMO]`, the same-system test (Plan R12 step 4, 2026-11-03; package
and reading updated before the run, 2026-11-08).

The user's live analyses on the VM are compared with the same rule folders, configuration and settings run here on the
exported recording. Sysmon detections up to the export's last record are compared by record number and time stamp;
detections after the export, rows without a record number and other logs are reported apart, never as a disagreement.
The engines are never run here: fake runners write the files they would write.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from eval.compare_live import (
    attack_processes,
    attack_window,
    caught_live,
    compare,
    other_logs_on_attack,
    read_log_state,
    read_rows,
    reproduce_r123,
    reproduce_r125,
    rule_names,
    run_here,
    split,
    summarise,
)

LAST = 100  # the export's last record in these tests
T = "2026-10-23 23:35:0{}.000 +00:00"


def _row(rule, record, channel="Sysmon", level="high", ts=None, title=None, event_id=1, pid=None):
    second = record % 60 if isinstance(record, int) else 0
    row = {"RuleID": rule, "RuleTitle": title or f"title {rule}", "Level": level, "Channel": channel,
           "EventID": event_id, "Timestamp": ts or f"2026-01-01 00:00:{second:02d}.000 +00:00"}
    if pid is not None:
        row["Details"] = {"PID": pid}
    if record is not None:
        row["RecordID"] = record
    return row


def _file(tmp_path, name, rows):
    path = tmp_path / name
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


def _rows(tmp_path, name, rows):
    return read_rows(_file(tmp_path, name, rows))


def test_rows_keep_channel_record_time_and_full_level_names(tmp_path):
    rows = _rows(tmp_path, "a.jsonl", [_row("r1", 5, level="med", ts=T.format(1)), _row("r2", "-", channel="Sec")])
    assert rows[0] == {"rule_id": "r1", "title": "title r1", "level": "medium", "channel": "Sysmon", "event_id": 1,
                       "record_id": 5, "timestamp": T.format(1), "pid": None}
    assert rows[1]["record_id"] is None and rows[1]["channel"] == "Sec"


def test_rows_are_split_at_the_export_and_by_log(tmp_path):
    rows = _rows(tmp_path, "a.jsonl", [_row("r1", 100), _row("r1", 101), _row("r1", 5, channel="Sec"),
                                       _row("r1", None)])
    parts = split(rows, LAST)
    assert [r["record_id"] for r in parts["before"]] == [100] and [r["record_id"] for r in parts["after"]] == [101]
    assert [r["channel"] for r in parts["other_logs"]] == ["Sec"] and len(parts["no_record"]) == 1


def test_the_same_records_at_the_same_times_are_the_same_events(tmp_path):
    here = _rows(tmp_path, "h.jsonl", [_row("r1", 5), _row("r1", 7)])
    live = _rows(tmp_path, "l.jsonl", [_row("r1", 7), _row("r1", 5), _row("r1", 150), _row("r1", 9, channel="Sec")])
    [row] = compare(here, live, LAST)
    assert row["same_events"] is True and row["recording"] == 2 and row["live_before_export"] == 2
    assert row["live_after_export"] == 1 and row["other_logs"] == {"Sec": 1}


def test_a_live_match_before_the_export_that_the_recording_lacks_is_a_difference(tmp_path):
    here = _rows(tmp_path, "h.jsonl", [_row("r1", 5)])
    live = _rows(tmp_path, "l.jsonl", [_row("r1", 5), _row("r1", 6)])
    [row] = compare(here, live, LAST)
    assert row["same_events"] is False and row["only_live"] == [6] and row["only_recording"] == []


def test_the_same_number_at_another_time_is_another_event(tmp_path):
    here = _rows(tmp_path, "h.jsonl", [_row("r1", 5, ts=T.format(1))])
    live = _rows(tmp_path, "l.jsonl", [_row("r1", 5, ts=T.format(2))])
    [row] = compare(here, live, LAST)
    assert row["same_events"] is False and row["other_time"] == [5]


def test_matches_after_the_export_or_in_other_logs_are_never_a_difference(tmp_path):
    here = _rows(tmp_path, "h.jsonl", [])
    live = _rows(tmp_path, "l.jsonl", [_row("r1", 150), _row("r2", 3, channel="Sec")])
    rows = compare(here, live, LAST)
    assert all(r["same_events"] for r in rows)
    summary = summarise(rows)
    assert summary["compared"] == 0 and summary["differ"] == [] and summary["live_after_export"] == 1
    assert summary["other_logs"] == {"Sec": 1}


def test_the_summary_counts_only_rules_with_sysmon_matches_up_to_the_export(tmp_path):
    here = _rows(tmp_path, "h.jsonl", [_row("r1", 5), _row("r2", 6)])
    live = _rows(tmp_path, "l.jsonl", [_row("r1", 5), _row("r3", 150)])
    summary = summarise(compare(here, live, LAST))
    assert summary["rules"] == 3 and summary["compared"] == 2 and summary["same_events"] == 1
    assert summary["differ"] == ["r2"]


def test_the_log_state_is_read_from_powershells_utf16_file(tmp_path):
    text = ("LogName            : Microsoft-Windows-Sysmon/Operational\r\nRecordCount        : 23920\r\n"
            "FileSize           : 31526912\r\nMaximumSizeInBytes : 67108864\r\nLogMode            : Circular\r\n"
            "IsLogFull          : False\r\n\r\nRecordId    : 1\r\nTimeCreated : 12/15/2025 7:39:30 AM\r\n\r\n"
            "RecordId    : 23920\r\nTimeCreated : 11/8/2026 2:38:14 PM\r\n\r\nSystem audit policy\r\n"
            "Detailed Tracking\r\n  Process Creation                        Success and Failure\r\n")
    path = tmp_path / "state.txt"
    path.write_bytes(text.encode("utf-16"))
    state = read_log_state(path)
    assert state == {"record_count": 23920, "oldest_record": 1, "newest_record": 23920, "log_mode": "Circular",
                     "is_full": "False", "max_size_bytes": 67108864, "process_creation_audit": "Success and Failure"}


def test_rule_names_come_from_the_package_folder(tmp_path):
    rule = tmp_path / "rules-ours/sysmon/set-a/rule_1.yml"
    rule.parent.mkdir(parents=True)
    rule.write_text("title: One\nid: abc\n", encoding="utf-8")
    assert rule_names(tmp_path / "rules-ours") == {"abc": "sysmon/set-a/rule_1.yml"}


LOADED = "Total detection rules: 30\nDetection rules enabled after channel filter: 30\n"
NOTHING = "Total detection rules: 0\n[ERROR] No rules were loaded.\n"


def _hayabusa(rows=(), stdout=LOADED, exit_code=0, write_out=True):
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        if write_out:
            Path(cmd[cmd.index("-o") + 1]).write_text("".join(json.dumps(r) + "\n" for r in rows) or "\n",
                                                      encoding="utf-8")
        return SimpleNamespace(returncode=exit_code, stdout=stdout, stderr="")
    runner.calls = calls
    return runner


def test_the_run_here_uses_the_same_rules_and_configuration_as_the_vm(tmp_path):
    runner = _hayabusa([_row("r1", 5)])
    run = run_here(tmp_path / "H", "hb", Path("rec.evtx"), Path("pkg/rules-ours"), Path("pkg/rules-mac/config"),
                   tmp_path / "w/out.jsonl", runner)
    cmd = runner.calls[0]
    assert cmd[cmd.index("-f") + 1] == str(Path("rec.evtx").resolve())
    assert cmd[cmd.index("-r") + 1] == str(Path("pkg/rules-ours").resolve())
    assert cmd[cmd.index("-c") + 1] == str(Path("pkg/rules-mac/config").resolve())
    assert run["status"] == "ran" and run["rows"][0]["record_id"] == 5


def test_a_run_here_that_did_not_load_is_shown_never_as_no_matches(tmp_path):
    run = run_here(tmp_path / "H", "hb", "rec.evtx", "rules", "config", tmp_path / "w/out.jsonl",
                   _hayabusa(stdout=NOTHING, exit_code=1, write_out=False))
    assert run["status"] == "not loaded" and run["rows"] is None


def _r123(tmp_path, rows):
    return _file(tmp_path, "r123.jsonl", [{"environment": {}, "summary": {}}] + rows)


def test_reproducing_r123_compares_each_copys_events(tmp_path):
    ref = _r123(tmp_path, [{"converted_id": "c1", "hayabusa": {"status": "ran", "record_ids": [5, 7]}},
                           {"converted_id": "c2", "hayabusa": {"status": "ran", "record_ids": []}},
                           {"converted_id": "c3", "hayabusa": {"status": "ran", "record_ids": [9]}},
                           {"converted_id": "c4", "hayabusa": {"status": "not loaded", "record_ids": None}}])
    here = _rows(tmp_path, "h.jsonl", [_row("c1", 7), _row("c1", 5), _row("c3", 8)])
    result = reproduce_r123(here, ref)
    assert result == {"rules": 3, "same": 2, "differ": ["c3"]}


def test_reproducing_r125_compares_each_rules_count(tmp_path):
    ref = _file(tmp_path, "r125.jsonl", [{"attack": {}}, {"run": "defaults", "rule_id": "p1", "matched": 2},
                                         {"run": "everything on", "rule_id": "p9", "matched": 4},
                                         {"run": "ours", "rule_id": "o1", "matched": 1}])
    assert reproduce_r125(_rows(tmp_path, "h.jsonl", [_row("p1", 5), _row("p1", 6)]), ref) == \
        {"rules": 1, "same": 1, "differ": []}
    assert reproduce_r125(_rows(tmp_path, "h2.jsonl", [_row("p1", 5), _row("p2", 6)]), ref)["differ"] == ["p1", "p2"]


ATTACK = {"counted": [20, 22], "conhost": [21]}


def test_the_attack_window_runs_from_the_first_to_the_last_attack_event(tmp_path):
    rows = _rows(tmp_path, "l.jsonl", [_row("info", 20, ts=T.format(3)), _row("info", 22, ts=T.format(7)),
                                       _row("info", 21, ts=T.format(5)), _row("info", 30, ts=T.format(9))])
    assert attack_window(rows, ATTACK) == {"start": T.format(3), "end": T.format(7), "events_with_a_time": 3,
                                           "attack_events": 3}


def test_the_attacks_processes_come_from_its_sysmon_process_starts(tmp_path):
    rows = _rows(tmp_path, "l.jsonl", [_row("info", 20, ts=T.format(3), pid="11"), _row("x", 20, ts=T.format(3), pid="11"),
                                       _row("info", 21, ts=T.format(4), pid="12"),
                                       _row("info", 22, ts=T.format(5), event_id=5, pid="11"),
                                       _row("info", 30, ts=T.format(6), pid="13")])
    assert attack_processes(rows, ATTACK) == [{"record_id": 20, "pid": "11", "timestamp": T.format(3), "counts": True},
                                              {"record_id": 21, "pid": "12", "timestamp": T.format(4), "counts": False}]


def test_other_logs_are_linked_to_an_attack_process_by_its_id_within_a_second(tmp_path):
    # Found in the first R12.4 run (2026-11-08): Windows wrote its own process-start event (Security 4688) 25 ms before
    # Sysmon's for the same process, so a time window opening at Sysmon's first time stamp left it out.
    processes = [{"record_id": 20, "pid": "11", "timestamp": "2026-10-23 23:35:03.162 +00:00", "counts": True},
                 {"record_id": 21, "pid": "12", "timestamp": "2026-10-23 23:35:03.176 +00:00", "counts": False}]
    rows = _rows(tmp_path, "l.jsonl", [
        _row("a", 1, channel="Sec", level="med", event_id=4688, pid="11", ts="2026-10-23 23:35:03.137 +00:00"),
        _row("b", 2, channel="Sec", level="low", event_id=4688, pid="11", ts="2026-10-23 23:35:03.137 +00:00"),
        _row("c", 3, channel="Sec", level="high", event_id=4688, pid="11", ts="2026-10-23 23:35:09.000 +00:00"),
        _row("d", 4, channel="Sec", level="high", event_id=4688, pid="99", ts="2026-10-23 23:35:03.140 +00:00"),
        _row("e", 5, channel="Sec", level="high", event_id=4688, pid="12", ts="2026-10-23 23:35:03.170 +00:00"),
        _row("f", 20, channel="Sysmon", level="high", pid="11", ts="2026-10-23 23:35:03.162 +00:00")])
    found = other_logs_on_attack(rows, processes)
    assert [(r["rule_id"], r["counts"]) for r in found] == [("a", True), ("e", False)]
    assert [r["rule_id"] for r in other_logs_on_attack(rows, processes, levels=("medium", "low"))] == ["a", "b"]


def test_caught_live_needs_medium_or_higher_on_a_counted_sysmon_attack_event(tmp_path):
    assert caught_live(_rows(tmp_path, "a.jsonl", [_row("x", 20, level="med")]), ATTACK) is True
    assert caught_live(_rows(tmp_path, "b.jsonl", [_row("x", 21, level="crit"), _row("y", 22, level="low")]),
                       ATTACK) is False
    assert caught_live(_rows(tmp_path, "c.jsonl", [_row("x", 20, channel="Sec", level="high")]), ATTACK) is False
