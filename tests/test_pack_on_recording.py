"""Offline tests for eval/pack_on_recording.py — R12.5 `[DEMO]`: Hayabusa's own rule pack on the ActiveMQ recording
(plan and definitions fixed in the log 2026-11-05, before the run).

Attack events come from the recording alone: the processes descending from the ActiveMQ server through
`ParentProcessGuid`. `conhost.exe` stays listed but does not count. Caught = a rule of level medium or higher matches a
counted attack event. Other events are never called false positives, rows without a record number are never counted
as either, and a pack that did not load is never "not caught". The engines are never run here.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from eval.pack_on_recording import (
    attack_events,
    caught,
    level_counts,
    ours_rows,
    read_events,
    read_pack,
    run_pack,
    score,
)

LOADED = ("Excluded rules: 26\nNoisy rules: 12 (Disabled)\nDeprecated rules: 232 (4.95%) (Disabled)\n"
          "Unsupported rules: 42 (0.90%) (Disabled)\nTotal detection rules: 4,689\n"
          "Detection rules enabled after channel filter: 2,307\n")
NOTHING = "Total detection rules: 0\n[ERROR] No rules were loaded.\n"


def _start(record, guid, parent, image, command=""):
    return {"EventID": 1, "EventRecordID": record, "ProcessGuid": guid, "ParentProcessGuid": parent, "Image": image,
            "CommandLine": command}


def _exit(record, guid, image):
    return {"EventID": 5, "EventRecordID": record, "ProcessGuid": guid, "Image": image}


SERVER = _start(10, "S", "P", r"C:\jdk\bin\java.exe", '"java.exe" -Dactivemq.home=C:\\ActiveMQ -jar run.jar')
EVENTS = [
    _start(1, "E", "P", r"C:\Elastic\jdk\bin\java.exe", "java -Des.path=elastic"),
    _start(2, "EC", "E", r"C:\Windows\System32\cmd.exe", "cmd /c elastic-child"),
    SERVER,
    _start(20, "A", "S", r"C:\Windows\System32\cmd.exe", "cmd /c payload"),
    _start(21, "B", "A", r"C:\Windows\System32\conhost.exe", "conhost.exe 0xffffffff -ForceV1"),
    _start(22, "C", "A", r"C:\Windows\System32\whoami.exe", "whoami"),
    _exit(23, "C", r"C:\Windows\System32\whoami.exe"),
    _start(30, "X", "P", r"C:\Windows\System32\svchost.exe", "svchost -k netsvcs"),
    _exit(31, "S", r"C:\jdk\bin\java.exe"),
]


def test_attack_events_are_the_descendants_of_the_server_only():
    attack = attack_events(EVENTS)
    assert attack["servers"] == [10]
    assert [e["record_id"] for e in attack["events"]] == [20, 21, 22, 23]
    assert attack["processes"] == 3


def test_a_grandchild_listed_before_its_parent_still_belongs_to_the_tree():
    events = [_start(5, "G", "K", r"C:\tool.exe"), SERVER, _start(20, "K", "S", r"C:\Windows\System32\cmd.exe")]
    assert [e["record_id"] for e in attack_events(events)["events"]] == [5, 20]


def test_another_java_program_is_not_the_server():
    attack = attack_events([e for e in EVENTS if e is not SERVER])
    assert attack["servers"] == [] and attack["events"] == []


def test_every_server_start_is_a_root():
    second = _start(11, "S2", "P", r"C:\jdk\bin\java.exe", "java -Dactivemq.base=x")
    events = EVENTS + [second, _start(40, "D", "S2", r"C:\Windows\System32\cmd.exe")]
    attack = attack_events(events)
    assert attack["servers"] == [10, 11] and 40 in [e["record_id"] for e in attack["events"]]


def test_conhost_is_listed_but_does_not_count():
    attack = attack_events(EVENTS)
    assert [e["record_id"] for e in attack["events"] if not e["counts"]] == [21]
    assert attack["counted"] == [20, 22, 23] and attack["conhost"] == [21]


def _pack_file(tmp_path, rows):
    path = tmp_path / "pack.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


def _row(rule_id, record, level="med", title="Rule", rule_file="a.yml"):
    row = {"RuleID": rule_id, "RuleTitle": title, "Level": level, "RuleFile": rule_file}
    if record is not None:
        row["RecordID"] = record
    return row


def test_the_pack_file_is_read_per_rule_with_full_level_names(tmp_path):
    path = _pack_file(tmp_path, [_row("r1", 20, "crit", "One", "one.yml"), _row("r1", 30, "crit", "One", "one.yml"),
                                 _row("r2", 22, "info", "Two", "two.yml")])
    rules = read_pack(path)
    assert rules["r1"] == {"title": "One", "level": "critical", "rule_file": "one.yml", "count": 2,
                           "record_ids": [20, 30], "no_record_id": 0}
    assert rules["r2"]["level"] == "informational"


def test_an_unknown_level_is_kept_as_written_not_guessed(tmp_path):
    assert read_pack(_pack_file(tmp_path, [_row("r1", 20, "weird")]))["r1"]["level"] == "weird"


def test_a_row_without_a_record_number_is_counted_apart(tmp_path):
    rules = read_pack(_pack_file(tmp_path, [_row("r1", None), _row("r1", "-"), _row("r1", 20)]))
    assert rules["r1"]["count"] == 3 and rules["r1"]["record_ids"] == [20] and rules["r1"]["no_record_id"] == 2


def test_no_pack_file_is_unknown_not_empty(tmp_path):
    assert read_pack(tmp_path / "missing.jsonl") is None


ATTACK = attack_events(EVENTS)


def _rule(level, record_ids, no_record_id=0):
    return {"title": "Rule", "level": level, "rule_file": "a.yml", "count": len(record_ids) + no_record_id,
            "record_ids": record_ids, "no_record_id": no_record_id}


def test_a_rule_is_split_into_counted_conhost_and_other_events():
    row = score("r1", _rule("high", [20, 21, 30, 31]), ATTACK)
    assert row["on_attack"] == [20] and row["on_conhost"] == [21] and row["other_events"] == 2
    assert row["no_record_id"] == 0 and "false_positives" not in row


def test_rows_without_a_record_number_are_neither_attack_nor_other():
    row = score("r1", _rule("high", [20], no_record_id=3), ATTACK)
    assert row["on_attack"] == [20] and row["other_events"] == 0 and row["no_record_id"] == 3


@pytest.mark.parametrize("level,expected", [("critical", True), ("high", True), ("medium", True), ("low", False),
                                            ("informational", False)])
def test_caught_needs_level_medium_or_higher(level, expected):
    assert caught([score("r1", _rule(level, [20]), ATTACK)]) is expected


def test_matching_only_conhost_or_other_events_is_not_caught():
    assert caught([score("r1", _rule("critical", [21, 30]), ATTACK)]) is False


def test_level_counts_cover_rules_that_matched_and_rules_on_the_attack():
    rows = [score("r1", _rule("high", [20]), ATTACK), score("r2", _rule("high", [30]), ATTACK),
            score("r3", _rule("low", [22]), ATTACK)]
    counts = level_counts(rows)
    assert counts["high"] == {"matched": 2, "on_attack": 1} and counts["low"] == {"matched": 1, "on_attack": 1}
    assert counts["critical"] == {"matched": 0, "on_attack": 0}


def _hayabusa(stdout=LOADED, rows=(), exit_code=0, write_out=True):
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        if write_out:
            out = Path(cmd[cmd.index("-o") + 1])
            out.write_text("".join(json.dumps(r) + "\n" for r in rows) or "\n", encoding="utf-8")
        return SimpleNamespace(returncode=exit_code, stdout=stdout, stderr="")
    runner.calls = calls
    return runner


def test_the_pack_run_reads_the_whole_rules_folder_and_reports_what_loaded(tmp_path):
    runner = _hayabusa(rows=[_row("r1", 20)])
    run = run_pack(tmp_path / "H", "hb", tmp_path / "rec.evtx", tmp_path / "w/pack.jsonl", runner=runner)
    cmd = runner.calls[0]
    assert cmd[cmd.index("-r") + 1] == str(tmp_path / "H/rules")
    assert not {"-D", "-u", "-n"} & set(cmd)
    assert run["status"] == "ran" and run["rules"]["r1"]["count"] == 1
    assert run["load"]["total_rules"] == 4689 and run["load"]["enabled_after_channel_filter"] == 2307
    assert run["load"]["deprecated"] == 232 and run["load"]["unsupported"] == 42 and run["load"]["excluded"] == 26


def test_the_everything_on_run_adds_the_flags(tmp_path):
    runner = _hayabusa()
    run_pack(tmp_path / "H", "hb", tmp_path / "rec.evtx", tmp_path / "w/pack.jsonl", extra=("-D", "-u", "-n"),
             runner=runner)
    assert {"-D", "-u", "-n"} <= set(runner.calls[0])


def test_a_pack_that_did_not_load_is_shown_never_as_not_caught(tmp_path):
    runner = _hayabusa(stdout=NOTHING, exit_code=1, write_out=False)
    run = run_pack(tmp_path / "H", "hb", tmp_path / "rec.evtx", tmp_path / "w/pack.jsonl", runner=runner)
    assert run["status"] == "not loaded" and run["rules"] is None


def test_a_failed_run_is_a_tool_error(tmp_path):
    runner = _hayabusa(exit_code=2, write_out=False)
    run = run_pack(tmp_path / "H", "hb", tmp_path / "rec.evtx", tmp_path / "w/pack.jsonl", runner=runner)
    assert run["status"] == "tool error" and run["rules"] is None


def _database(folder, rows):
    db = folder / "census.db"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE logs (EventID TEXT, EventRecordID TEXT, ProcessGuid TEXT, ParentProcessGuid TEXT, "
                "Image TEXT, CommandLine TEXT)")
    con.executemany("INSERT INTO logs VALUES (?,?,?,?,?,?)", rows)
    con.commit()
    con.close()


def _zircolite(rows, exit_code=0):
    calls = []

    def runner(cmd, **kwargs):
        calls.append((cmd, kwargs))
        if rows is not None:
            _database(Path(cmd[cmd.index("--dbfile") + 1]).parent, rows)
        return SimpleNamespace(returncode=exit_code, stdout="", stderr="")
    runner.calls = calls
    return runner


def test_events_come_from_zircolite_with_no_event_filter_and_numbers_are_numbers(tmp_path):
    runner = _zircolite([("1", "20", "A", "S", r"C:\cmd.exe", "cmd /c x"), ("5", "23", "C", None, r"C:\w.exe", None)])
    events = read_events(tmp_path / "Z", tmp_path / "rec.evtx", tmp_path / "w", runner)
    cmd, kwargs = runner.calls[0]
    assert "--no-event-filter" in cmd and kwargs["env"]["ZIRCOLITE_NO_CACHE"] == "1"
    assert events[0]["EventID"] == 1 and events[0]["EventRecordID"] == 20 and events[1]["EventRecordID"] == 23
    assert events[1]["ParentProcessGuid"] is None


def test_no_database_stops_the_tool_rather_than_giving_no_attack_events(tmp_path):
    with pytest.raises(RuntimeError):
        read_events(tmp_path / "Z", tmp_path / "rec.evtx", tmp_path / "w", _zircolite(None, exit_code=1))


def _ours_file(tmp_path, rules_root):
    rule_dir = rules_root / "set-one"
    rule_dir.mkdir(parents=True)
    (rule_dir / "rule_1.yml").write_text("title: One\nlevel: high\n", encoding="utf-8")
    (rule_dir / "rule_2.yml").write_text("title: Two\n", encoding="utf-8")
    rows = [{"environment": {}, "summary": {}},
            {"set": "set-one", "recording": "rec.evtx", "rule_file": "rule_1.yml", "rule_id": "a", "title": "One",
             "hayabusa": {"status": "ran", "matched": 2, "record_ids": [20, 30], "reason": ""}},
            {"set": "set-one", "recording": "rec.evtx", "rule_file": "rule_2.yml", "rule_id": "b", "title": "Two",
             "hayabusa": {"status": "not loaded", "matched": None, "record_ids": None, "reason": "x"}},
            {"set": "fodhelper", "recording": "other.evtx", "rule_file": "f.yml", "rule_id": "c", "title": "F",
             "hayabusa": {"status": "ran", "matched": 12, "record_ids": [1], "reason": ""}}]
    path = tmp_path / "r123.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


def test_our_rules_get_the_same_measure_on_this_recording_only(tmp_path):
    rows = ours_rows(_ours_file(tmp_path, tmp_path / "rules"), tmp_path / "rules", "rec.evtx", ATTACK)
    assert [r["rule_file"] for r in rows] == ["rule_1.yml", "rule_2.yml"]
    assert rows[0]["set"] == "set-one" and rows[0]["level"] == "high"
    assert rows[0]["on_attack"] == [20] and rows[0]["other_events"] == 1


def test_our_rule_that_did_not_run_is_shown_never_as_zero_and_no_level_stays_unknown(tmp_path):
    rows = ours_rows(_ours_file(tmp_path, tmp_path / "rules"), tmp_path / "rules", "rec.evtx", ATTACK)
    assert rows[1]["status"] == "not loaded" and rows[1]["on_attack"] is None and rows[1]["level"] is None
