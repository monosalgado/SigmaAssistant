#!/usr/bin/env python3
"""R12.4 `[DEMO]` - the same-system test: Hayabusa's live analysis on the VM the attack ran on, compared with the same
rule folders run here on the exported recording (Plan R12 step 4, 2026-11-03; package and reading updated before the
run, 2026-11-08).

The user ran two live analyses on the VM (`-l`) with the package's rule folders and the Mac's Hayabusa configuration:
our converted rules (`rules-ours`) and Hayabusa's own pack (`rules-mac`). This tool runs the same folders with the same
configuration and settings on the exported recording (`-f`) and compares them rule by rule.

- **Compared:** Sysmon detections up to the export's last record, by record number **and** time stamp (the same
  number at another time would be another event). Same events = the same set on both sides.
- **Reported apart, never as a disagreement:** Sysmon detections after the export (the live log kept growing), rows
  without a record number (correlation rules), and every other log (Security etc.: not in the export, descriptive).
- **Reproduction first:** the run here must give R12.3's events for our rules and R12.5's counts for the pack.
- **The attack, with R12.5's definitions:** whether a rule of level medium or higher matches a counted attack event in
  the live Sysmon log; and, descriptive (added after the run), the rules at medium or higher on other logs between
  the first and the last attack event.
- **The live Sysmon log's state** (`sysmon-log-state.txt`, written by PowerShell): if its oldest record is later than
  the export's first, the events before it are gone and are reported as missing for that reason.

Only counts, record numbers, time stamps, rule titles and log names are written (local results, gitignored folder).

Usage:
    .venv/bin/python eval/compare_live.py --live-dir <folder with the VM files> --package <hayabusa-vm-package>
        --evtx <recording.evtx> --r123 <R12.3 rows> --r125 <R12.5 rows> --out <file.jsonl>
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.pack_on_recording import CAUGHT_LEVELS, LEVEL_NAMES, read_events  # noqa: E402
from eval.validate_hayabusa import (  # noqa: E402
    CONVERTER_DIR,
    HAYABUSA_BINARY,
    HAYABUSA_DIR,
    environment as hayabusa_environment,
    record_id,
    run_hayabusa,
)
from eval.validate_zircolite import ZIRCOLITE_DIR, environment as zircolite_environment  # noqa: E402

SIGMA = REPO / "data/sigma"
SYSMON = "Sysmon"  # Hayabusa's name for the Sysmon log in its output


def _text(path) -> str:
    """A text file as PowerShell 5.1 writes it (UTF-16 with a byte-order mark) or as UTF-8."""
    raw = Path(path).read_bytes()
    return raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig")


def read_rows(path) -> list:
    """Hayabusa's JSON-lines detections: rule, full level name, log, event ID, record number (None when the row has
    none) and time stamp."""
    rows = []
    for line in _text(path).splitlines():
        if not line.strip():
            continue
        det = json.loads(line)
        level = str(det.get("Level"))
        rows.append({"rule_id": str(det.get("RuleID")), "title": det.get("RuleTitle"),
                     "level": LEVEL_NAMES.get(level, level), "channel": det.get("Channel"),
                     "event_id": det.get("EventID"), "record_id": record_id(det.get("RecordID")),
                     "timestamp": det.get("Timestamp")})
    return rows


def split(rows: list, last_record: int) -> dict:
    """Sysmon rows up to and after the export's last record; rows of other logs; rows without a record number."""
    parts = {"before": [], "after": [], "other_logs": [], "no_record": []}
    for row in rows:
        if row["record_id"] is None:
            parts["no_record"].append(row)
        elif row["channel"] != SYSMON:
            parts["other_logs"].append(row)
        elif row["record_id"] <= last_record:
            parts["before"].append(row)
        else:
            parts["after"].append(row)
    return parts


def _by_rule(rows: list) -> dict:
    out = defaultdict(list)
    for row in rows:
        out[row["rule_id"]].append(row)
    return out


def compare(here_rows: list, live_rows: list, last_record: int, names: dict = None) -> list:
    """One row per rule: the recording's Sysmon events against the live Sysmon events up to the export."""
    here, live = split(here_rows, last_record), split(live_rows, last_record)
    groups = {key: _by_rule(rows) for key, rows in (("here", here["before"]), ("live", live["before"]),
                                                    ("after", live["after"]), ("other", live["other_logs"]),
                                                    ("none", live["no_record"] + here["no_record"]))}
    first = {}
    for row in here_rows + live_rows:
        first.setdefault(row["rule_id"], row)
    out = []
    for rule_id in sorted(first):
        mine = {r["record_id"]: r["timestamp"] for r in groups["here"].get(rule_id, [])}
        theirs = {r["record_id"]: r["timestamp"] for r in groups["live"].get(rule_id, [])}
        only_here, only_live = sorted(set(mine) - set(theirs)), sorted(set(theirs) - set(mine))
        other_time = sorted(n for n in set(mine) & set(theirs) if mine[n] != theirs[n])
        out.append({"rule_id": rule_id, "name": (names or {}).get(rule_id), "title": first[rule_id]["title"],
                    "level": first[rule_id]["level"], "recording": len(mine), "live_before_export": len(theirs),
                    "same_events": not (only_here or only_live or other_time), "only_recording": only_here,
                    "only_live": only_live, "other_time": other_time,
                    "live_after_export": len(groups["after"].get(rule_id, [])),
                    "other_logs": dict(Counter(r["channel"] for r in groups["other"].get(rule_id, []))),
                    "no_record_id": len(groups["none"].get(rule_id, []))})
    return out


def summarise(rows: list) -> dict:
    compared = [r for r in rows if r["recording"] or r["live_before_export"]]
    other = Counter()
    for row in rows:
        other.update(row["other_logs"])
    return {"rules": len(rows), "compared": len(compared), "same_events": sum(r["same_events"] for r in compared),
            "differ": [r["rule_id"] for r in compared if not r["same_events"]],
            "events_recording": sum(r["recording"] for r in rows),
            "events_live_before_export": sum(r["live_before_export"] for r in rows),
            "live_after_export": sum(r["live_after_export"] for r in rows), "other_logs": dict(other),
            "no_record_id": sum(r["no_record_id"] for r in rows)}


def read_log_state(path) -> dict:
    """The user's `sysmon-log-state.txt`: the log's size and mode, its oldest and newest record (in that order), and
    the process-creation audit setting the built-in copies need."""
    text = _text(path)

    def field(name):
        m = re.search(rf"^{name}\s*:\s*(\S+)", text, re.M)
        return m.group(1) if m else None
    records = [int(n) for n in re.findall(r"^RecordId\s*:\s*(\d+)", text, re.M)]
    audit = re.search(r"Process Creation\s+(\S.*\S)", text)
    return {"record_count": int(field("RecordCount")) if field("RecordCount") else None,
            "oldest_record": records[0] if records else None,
            "newest_record": records[1] if len(records) > 1 else None, "log_mode": field("LogMode"),
            "is_full": field("IsLogFull"),
            "max_size_bytes": int(field("MaximumSizeInBytes")) if field("MaximumSizeInBytes") else None,
            "process_creation_audit": audit.group(1) if audit else None}


def rule_names(folder) -> dict:
    """{rule id: its path in the package folder}, e.g. `sysmon/<set>/rule_1.yml` (file names repeat across sets)."""
    folder, out = Path(folder), {}
    for path in sorted(folder.rglob("*.yml")):
        rule_id = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("id")
        if rule_id:
            out[str(rule_id)] = path.relative_to(folder).as_posix()
    return out


def run_here(hdir, binary: str, evtx, rules, config, outfile, runner=subprocess.run) -> dict:
    """The VM's command on the recording: the same rule folder and configuration, `-f` instead of `-l`."""
    run = run_hayabusa(hdir, binary, Path(evtx).resolve(), Path(rules).resolve(), outfile, runner,
                       extra=("-c", str(Path(config).resolve())))
    if not run["loaded"]:
        return {"status": "not loaded", "load": run["load"], "rows": None, "reason": run["reason"]}
    if run["exit_code"] != 0 or run["detections"] is None:
        return {"status": "tool error", "load": run["load"], "rows": None, "reason": run["printed_tail"]}
    return {"status": "ran", "load": run["load"], "rows": read_rows(outfile), "reason": ""}


def _jsonl(path) -> list:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def reproduce_r123(here_rows: list, path) -> dict:
    """Each converted Sysmon copy's events here against R12.3's (each rule on its own there)."""
    ref = {row["converted_id"]: sorted(row["hayabusa"]["record_ids"] or []) for row in _jsonl(path)
           if row.get("converted_id") and (row.get("hayabusa") or {}).get("status") == "ran"}
    mine = defaultdict(list)
    for row in here_rows:
        if row["channel"] == SYSMON and row["record_id"] is not None:
            mine[row["rule_id"]].append(row["record_id"])
    differ = sorted(cid for cid in ref if sorted(mine.get(cid, [])) != ref[cid])
    return {"rules": len(ref), "same": len(ref) - len(differ), "differ": differ}


def reproduce_r125(here_rows: list, path) -> dict:
    """Each pack rule's number of matches here against R12.5's run with the defaults."""
    ref = {row["rule_id"]: row["matched"] for row in _jsonl(path) if row.get("run") == "defaults"}
    mine = Counter(row["rule_id"] for row in here_rows)
    rules = set(ref) | set(mine)
    differ = sorted(r for r in rules if ref.get(r) != mine.get(r))
    return {"rules": len(rules), "same": len(rules) - len(differ), "differ": differ}


def _attack_records(attack: dict) -> set:
    return set(attack["counted"]) | set(attack["conhost"])


def caught_live(rows: list, attack: dict) -> bool:
    counted = set(attack["counted"])
    return any(r["channel"] == SYSMON and r["record_id"] in counted and r["level"] in CAUGHT_LEVELS for r in rows)


def on_attack(rows: list, attack: dict) -> list:
    """Live Sysmon rows on the attack's events, other than Hayabusa's informational event labels."""
    records = _attack_records(attack)
    return sorted(({"record_id": r["record_id"], "level": r["level"], "title": r["title"],
                    "counts": r["record_id"] in set(attack["counted"])}
                   for r in rows if r["channel"] == SYSMON and r["record_id"] in records
                   and r["level"] != "informational"), key=lambda r: (r["record_id"], str(r["title"])))


def attack_window(rows: list, attack: dict) -> dict:
    """From the first to the last attack event, by the live Sysmon rows' time stamps."""
    records = _attack_records(attack)
    times = {r["record_id"]: r["timestamp"] for r in rows if r["channel"] == SYSMON and r["record_id"] in records}
    return {"start": min(times.values()) if times else None, "end": max(times.values()) if times else None,
            "events_with_a_time": len(times), "attack_events": len(records)}


def other_logs_in_window(rows: list, window: dict, levels=CAUGHT_LEVELS) -> list:
    if not window.get("start"):
        return []
    return sorted(({"channel": r["channel"], "event_id": r["event_id"], "record_id": r["record_id"],
                    "timestamp": r["timestamp"], "level": r["level"], "title": r["title"], "rule_id": r["rule_id"]}
                   for r in rows if r["channel"] != SYSMON and r["level"] in levels
                   and window["start"] <= str(r["timestamp"]) <= window["end"]),
                  key=lambda r: (str(r["timestamp"]), str(r["title"])))


def sysmon_events(rows: list, event_id: int) -> dict:
    """First and last live Sysmon record of one event type, by any rule (descriptive)."""
    seen = sorted({(r["record_id"], r["timestamp"]) for r in rows
                   if r["channel"] == SYSMON and r["event_id"] == event_id and r["record_id"] is not None})
    return {"records": len(seen), "first": list(seen[0]) if seen else None, "last": list(seen[-1]) if seen else None}


def _print_rows(rows: list, show_all: bool) -> None:
    for row in rows:
        if show_all or not row["same_events"] or row["live_after_export"]:
            print(f"  {str(row['name'] or row['title'])[:58]:58} recording {row['recording']:5}  live before export "
                  f"{row['live_before_export']:5}  same {str(row['same_events']):5}  after export "
                  f"{row['live_after_export']:4}  other logs {row['other_logs']}")


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--live-dir", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True, help="the unzipped hayabusa-vm-package folder")
    parser.add_argument("--evtx", type=Path, required=True, help="the exported recording")
    parser.add_argument("--r123", type=Path, required=True)
    parser.add_argument("--r125", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--work", type=Path, default=None)
    parser.add_argument("--zircolite", type=Path, default=ZIRCOLITE_DIR)
    parser.add_argument("--hayabusa", type=Path, default=HAYABUSA_DIR)
    parser.add_argument("--binary", default=HAYABUSA_BINARY)
    parser.add_argument("--converter", type=Path, default=CONVERTER_DIR)
    args = parser.parse_args(argv)
    work = (args.work or Path(tempfile.mkdtemp(prefix="compare_live_"))).resolve()
    config = args.package / "rules-mac/config"
    env = {"zircolite": zircolite_environment(args.zircolite, SIGMA),
           "hayabusa": hayabusa_environment(args.hayabusa, args.binary, args.converter, SIGMA)}
    print(f"Hayabusa {env['hayabusa']['hayabusa_version']}; work folder {work}")

    state = read_log_state(args.live_dir / "sysmon-log-state.txt")
    events = read_events(args.zircolite.resolve(), args.evtx, work / "events")
    records = [e["EventRecordID"] for e in events]
    export = {"events": len(events), "first_record": min(records), "last_record": max(records)}
    print(f"live Sysmon log: {state}\nexport: {export}")
    if state["oldest_record"] and state["oldest_record"] > export["first_record"]:
        print(f"the live log starts at record {state['oldest_record']}: events before it are gone")

    runs = {name: run_here(args.hayabusa.resolve(), args.binary, args.evtx, args.package / folder, config,
                           work / f"{name}-recording.jsonl")
            for name, folder in (("ours", "rules-ours"), ("pack", "rules-mac"))}
    for name, run in runs.items():
        if run["status"] != "ran":
            print(f"{name} on the recording: {run['status']} - {run['reason']}")
            return 1
    reproduce = {"r123": reproduce_r123(runs["ours"]["rows"], args.r123),
                 "r125": reproduce_r125(runs["pack"]["rows"], args.r125)}
    print(f"reproduction: R12.3 {reproduce['r123']}; R12.5 {reproduce['r125']}")

    live = {name: read_rows(args.live_dir / f"{name}-live.jsonl") for name in ("ours", "pack")}
    names = rule_names(args.package / "rules-ours")
    compared = {"ours": compare(runs["ours"]["rows"], live["ours"], export["last_record"], names),
                "pack": compare(runs["pack"]["rows"], live["pack"], export["last_record"])}
    attack = _jsonl(args.r125)[0]["attack"]
    window = attack_window(live["pack"], attack)
    view = {"window": window,
            "pack_caught_live": caught_live(live["pack"], attack), "ours_caught_live": caught_live(live["ours"], attack),
            "pack_on_attack": on_attack(live["pack"], attack), "ours_on_attack": on_attack(live["ours"], attack),
            "pack_other_logs_in_window": other_logs_in_window(live["pack"], window),
            "ours_other_logs_in_window": other_logs_in_window(live["ours"], window, levels=("critical", "high",
                                                                                            "medium", "low"))}
    sysmon_types = {"network_3": sysmon_events(live["pack"], 3), "config_change_16": sysmon_events(live["pack"], 16)}
    report = {"environment": env, "log_state": state, "export": export, "reproduce": reproduce,
              "loads_here": {name: run["load"] for name, run in runs.items()},
              "summary": {name: summarise(rows) for name, rows in compared.items()}, "attack": view,
              "live_sysmon_event_types": sysmon_types}

    for name in ("ours", "pack"):
        print(f"\n{name}: {report['summary'][name]}")
        _print_rows(compared[name], show_all=(name == "ours"))
    print(f"\nattack window {window}")
    print(f"caught live (medium or higher on a counted attack event, Sysmon): pack {view['pack_caught_live']}, "
          f"ours {view['ours_caught_live']}")
    for row in view["pack_on_attack"] + view["ours_on_attack"]:
        print(f"  Sysmon {row['record_id']} {row['level']:6} counts {str(row['counts']):5} {row['title']}")
    print("other logs in the window, pack (medium or higher):")
    for row in view["pack_other_logs_in_window"]:
        print(f"  {row['timestamp']} {row['channel']} {row['event_id']} record {row['record_id']} {row['level']} "
              f"{row['title']}")
    print("other logs in the window, ours (any level):")
    for row in view["ours_other_logs_in_window"]:
        print(f"  {row['timestamp']} {row['channel']} {row['event_id']} record {row['record_id']} {row['level']} "
              f"{row['title']}")
    print(f"live Sysmon event types: {sysmon_types}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(json.dumps(report) + "\n")
        for name, rows in compared.items():
            for row in rows:
                f.write(json.dumps({"rules": name, **row}) + "\n")
    print(f"\nrows: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
