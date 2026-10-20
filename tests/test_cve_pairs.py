"""Offline tests for eval/cve_pairs.py — R11.4 Step A: the expert's rule on each CVE pair.

Plan fixed in the log 2026-10-19 ("R11.4 the CVE pairs: the plan") before this tool. Per (report, recording) pair
in scope: the expert's rule run by Zircolite with exactly the validated settings (one rule, cwd = Zircolite's folder);
a second, census run (`--no-event-filter --dbfile -sr`, in a scratch folder) gives the recording's event counts per
channel and the channels/event IDs the converted rule reads. Each pair is **usable** (the rule fires), **silent,
channel present**, **silent, channel absent**, **not converted** or **tool error**; a rule reading any channel other
than Sysmon's is flagged as outside the validated scope. Rows name the report as `report`, not `rule_id`: Step A runs
only the expert's rule, so it must not mark a never-run case as run for the held-out draw.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

from eval.cve_pairs import SYSMON, census_command, check_pair, classify, outside_validated, pairs, read_census
from eval.draw_heldout import used_rule_ids
from eval.validate_zircolite import SETTINGS


def _case(rid, product="windows", category="process_creation"):
    return {"rule_id": rid, "rule_path": f"rules/{rid}.yml", "product": product, "category": category}


def test_pairs_are_the_in_scope_reports_same_cve_recordings_in_order():
    inventory = {
        "recordings": [{"file": "c/b.evtx", "cves": ["CVE-2021-1"]}, {"file": "c/a.evtx", "cves": ["CVE-2021-1"]},
                       {"file": "c/z.evtx", "cves": ["CVE-2020-2"]}],
        "matches": {"r1": {"same_cve": ["c/b.evtx", "c/a.evtx"], "same_technique": []},
                    "r2": {"same_cve": ["c/z.evtx"], "same_technique": []},
                    "r3": {"same_cve": [], "same_technique": ["c/a.evtx"]}},
    }
    cases = {"r1": _case("r1"), "r2": _case("r2", product="zeek", category="none"), "r3": _case("r3")}
    out = pairs(inventory, cases, "windows-linux")
    assert [(p["report"], p["recording"]) for p in out] == [("r1", "c/a.evtx"), ("r1", "c/b.evtx")]
    assert out[0]["rule_path"] == "rules/r1.yml" and out[0]["cves"] == ["CVE-2021-1"]


def test_the_labels():
    assert classify(converted=1, matched=2, rule_channels=[SYSMON], channels={SYSMON: 5}) == "usable"
    assert classify(1, 0, [SYSMON], {SYSMON: 5, "Security": 3}) == "silent, channel present"
    assert classify(1, 0, [SYSMON], {"Security": 3}) == "silent, channel absent"
    assert classify(0, None, [], {"Security": 3}) == "not converted"
    # A rule that names no channel can match any event: silent on a non-empty recording = channel present.
    assert classify(1, 0, [], {"Security": 3}) == "silent, channel present"


def test_only_sysmon_is_inside_the_validated_scope():
    assert not outside_validated([SYSMON])
    assert outside_validated(["System"])
    assert outside_validated([SYSMON, "Security"])
    assert outside_validated([])  # no channel named: not what the validation exercised


def _census_files(folder, rows, channel=SYSMON, eventid=1):
    folder.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(folder / "census_x.evtx.db")
    con.execute("CREATE TABLE logs (row_id INTEGER, Channel TEXT, EventID INTEGER)")
    con.executemany("INSERT INTO logs VALUES (?, ?, ?)", [(i, c, e) for i, (c, e) in enumerate(rows)])
    con.commit()
    con.close()
    (folder / "ruleset-x-ABC.json").write_text(json.dumps([{"id": "g", "channel": [channel], "eventid": [eventid]}]),
                                              encoding="utf-8")


def test_the_census_counts_channels_and_the_rules_own_events(tmp_path):
    _census_files(tmp_path, [(SYSMON, 1), (SYSMON, 11), ("Security", 4688), (SYSMON, 1)])
    census = read_census(tmp_path)
    assert census["channels"] == {SYSMON: 3, "Security": 1}
    assert census["rule_channels"] == [SYSMON] and census["rule_eventids"] == [1]
    assert census["rule_events_present"] == 2


def test_the_census_command_adds_only_what_the_census_needs(tmp_path):
    cmd = census_command(tmp_path / "Z", "a.evtx", "g.yml", tmp_path / "c")
    for setting in SETTINGS:
        assert setting in cmd
    assert "--no-event-filter" in cmd and "-sr" in cmd
    assert cmd[cmd.index("--dbfile") + 1] == str(tmp_path / "c" / "census.db")


def _fake(matched_ids, converted=1, census_rows=((SYSMON, 1),), channel=SYSMON):
    calls = []

    def runner(cmd, **kwargs):
        calls.append((cmd, kwargs))
        out = Path(cmd[cmd.index("--outfile") + 1])
        log = Path(cmd[cmd.index("--logfile") + 1])
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(f"INFO Converted {converted} rules\nINFO {converted} rules loaded\n", encoding="utf-8")
        if converted:
            det = [{"id": "g", "count": len(matched_ids), "matches": [{"EventRecordID": i} for i in matched_ids]}]
            out.write_text(json.dumps(det if matched_ids else []), encoding="utf-8")
        if "--no-event-filter" in cmd and converted:
            _census_files(Path(kwargs["cwd"]), list(census_rows), channel=channel)
        return SimpleNamespace(returncode=0 if converted else 1, stdout="", stderr="")

    return runner, calls


PAIR = {"report": "g", "recording": "c/a.evtx", "rule_path": "rules/g.yml", "cves": ["CVE-2021-1"]}


def test_a_firing_expert_rule_makes_the_pair_usable_and_detection_runs_as_validated(tmp_path):
    runner, calls = _fake([3, 8])
    row = check_pair(PAIR, tmp_path / "evtx", tmp_path, tmp_path / "Z", tmp_path / "work", runner)
    assert row["label"] == "usable" and row["matched"] == 2 and row["record_ids"] == [3, 8]
    detection, census = calls[0], calls[1]
    assert "--no-event-filter" not in detection[0] and detection[1]["cwd"] == str(tmp_path / "Z")
    assert "--no-event-filter" in census[0] and census[1]["cwd"] != str(tmp_path / "Z")
    assert row["outside_validated_scope"] is False
    assert row["channels"] == {SYSMON: 1}


def test_a_silent_rule_is_sorted_by_whether_its_channel_is_there(tmp_path):
    runner, _ = _fake([], census_rows=((SYSMON, 11),))
    assert check_pair(PAIR, tmp_path / "evtx", tmp_path, tmp_path / "Z", tmp_path / "w1", runner)["label"] == \
        "silent, channel present"
    runner, _ = _fake([], census_rows=(("Security", 4688),))
    assert check_pair(PAIR, tmp_path / "evtx", tmp_path, tmp_path / "Z", tmp_path / "w2", runner)["label"] == \
        "silent, channel absent"


def test_a_service_rule_is_flagged_outside_the_validated_scope(tmp_path):
    runner, _ = _fake([5], census_rows=(("System", 7045),), channel="System")
    row = check_pair(PAIR, tmp_path / "evtx", tmp_path, tmp_path / "Z", tmp_path / "work", runner)
    assert row["label"] == "usable" and row["outside_validated_scope"] is True


def test_a_rule_that_does_not_convert(tmp_path):
    runner, _ = _fake([], converted=0)
    assert check_pair(PAIR, tmp_path / "evtx", tmp_path, tmp_path / "Z", tmp_path / "work", runner)["label"] == \
        "not converted"


def test_rows_do_not_mark_the_report_as_run(tmp_path):
    runner, _ = _fake([3])
    row = check_pair(PAIR, tmp_path / "evtx", tmp_path, tmp_path / "Z", tmp_path / "work", runner)
    results = tmp_path / "results"
    results.mkdir()
    (results / "cve_pairs_stepA.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    assert "rule_id" not in row and used_rule_ids(results) == set()
