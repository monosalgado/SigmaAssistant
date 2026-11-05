#!/usr/bin/env python3
"""R12.5 `[DEMO]` - Hayabusa's own rule pack on the ActiveMQ recording: do the experts' rules catch the attack? A
reference point for the 0 of 11 of 2026-10-28. Plan and definitions fixed in the log 2026-11-05, before the first run.

**Attack events** come from the recording alone, before any rule: the ActiveMQ server is a Sysmon process start of
`java.exe` with `activemq` in the command line, and the attack events are the Sysmon events of every process descending
from it through `ParentProcessGuid` (the server is not one). Events are read through Zircolite (R11.3), no filter.
`conhost.exe` stays listed but does not count: Windows starts one for console programs, benign ones too.

**Caught** = a rule of level medium or higher matches a counted attack event, with Hayabusa's defaults and the settings
R12.2 validated. A second run switches on deprecated, unsupported and noisy rules and is reported apart. Other events a
rule matches are never called false positives: the recording is the VM's log over 9 days, with the user's own earlier
tests in it. Rows without a record number (correlation rules) are listed apart. A pack that did not load, or a failed
run, is shown as such, never as "not caught". Our ActiveMQ rules get the same measure from R12.3's record numbers.

Descriptive: the recording is the user's lab capture (local, gitignored); only counts, record numbers, process names
and rule titles are written.

Usage:
    .venv/bin/python eval/pack_on_recording.py --evtx <recording.evtx> --ours <R12.3 rows.jsonl>
                                               --ours-rules <folder of rule sets> --out <file.jsonl>
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.cve_pairs import census_command  # noqa: E402
from eval.validate_hayabusa import (  # noqa: E402
    CONVERTER_DIR,
    HAYABUSA_BINARY,
    HAYABUSA_DIR,
    environment as hayabusa_environment,
    record_id,
    run_hayabusa,
)
from eval.validate_zircolite import (  # noqa: E402
    ENV,
    RUN_TIMEOUT_S,
    ZIRCOLITE_DIR,
    environment as zircolite_environment,
)

SIGMA = REPO / "data/sigma"
SERVER_MARK = "activemq"
NOT_COUNTED = "conhost.exe"
LEVELS = ("critical", "high", "medium", "low", "informational")
CAUGHT_LEVELS = ("critical", "high", "medium")
LEVEL_NAMES = {"crit": "critical", "high": "high", "med": "medium", "low": "low", "info": "informational"}
RUNS = (("defaults", ()), ("everything on", ("-D", "-u", "-n")))
# Zircolite needs a rule to load the events; this one is never read for its matches.
STUB_RULE = """title: Loads the events only
id: 00000000-0000-0000-0000-000000000000
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\never-a-real-program.exe'
  condition: selection
level: low
"""


def read_events(zdir, evtx, workdir, runner=subprocess.run) -> list:
    """Every event of the recording, with the fields the attack definition needs, from Zircolite's database (no event
    filter). No database stops the tool: an empty list would read as "no attack events"."""
    workdir = Path(workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    stub = workdir / "stub.yml"
    stub.write_text(STUB_RULE, encoding="utf-8")
    runner(census_command(zdir, Path(evtx).resolve(), stub, workdir), cwd=str(workdir), env={**os.environ, **ENV},
           capture_output=True, text=True, timeout=RUN_TIMEOUT_S)
    databases = sorted(workdir.glob("*.db"))
    if not databases:
        raise RuntimeError("Zircolite wrote no database: the events could not be read")
    con = sqlite3.connect(str(databases[0]))
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute("SELECT EventID, EventRecordID, ProcessGuid, ParentProcessGuid, Image, CommandLine "
                           "FROM logs").fetchall()
    finally:
        con.close()
    return [{**dict(r), "EventID": int(r["EventID"]), "EventRecordID": int(r["EventRecordID"])} for r in rows]


def _program(event: dict) -> str:
    return str(event.get("Image") or "").rsplit("\\", 1)[-1]


def attack_events(events: list) -> dict:
    """The attack, from the recording alone: the server's process starts, and the events of its descendants."""
    starts = [e for e in events if e["EventID"] == 1]
    servers = [e for e in starts if _program(e).lower() == "java.exe"
               and SERVER_MARK in str(e.get("CommandLine") or "").lower()]
    roots = {e["ProcessGuid"] for e in servers}
    children = defaultdict(set)
    for event in starts:
        children[event.get("ParentProcessGuid")].add(event["ProcessGuid"])
    tree, waiting = set(), list(roots)
    while waiting:
        for child in children[waiting.pop()] - tree - roots:
            tree.add(child)
            waiting.append(child)
    picked = sorted((e for e in events if e.get("ProcessGuid") in tree), key=lambda e: e["EventRecordID"])
    rows = [{"record_id": e["EventRecordID"], "event_id": e["EventID"], "program": _program(e),
             "counts": _program(e).lower() != NOT_COUNTED} for e in picked]
    return {"servers": sorted(e["EventRecordID"] for e in servers), "processes": len(tree), "events": rows,
            "counted": [r["record_id"] for r in rows if r["counts"]],
            "conhost": [r["record_id"] for r in rows if not r["counts"]]}


def read_pack(path) -> dict:
    """{rule id: title, full level name, rule file, count, record numbers, rows without one} from Hayabusa's JSON-lines
    file; None when there is no file. A level this tool does not know is kept as written."""
    path = Path(path)
    if not path.exists():
        return None
    rules = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        det = json.loads(line)
        level = str(det.get("Level"))
        rule = rules.setdefault(str(det.get("RuleID")), {
            "title": det.get("RuleTitle"), "level": LEVEL_NAMES.get(level, level), "rule_file": det.get("RuleFile"),
            "count": 0, "record_ids": [], "no_record_id": 0})
        rule["count"] += 1
        number = record_id(det.get("RecordID"))
        if number is None:
            rule["no_record_id"] += 1
        else:
            rule["record_ids"].append(number)
    for rule in rules.values():
        rule["record_ids"].sort()
    return rules


def score(rule_id: str, rule: dict, attack: dict) -> dict:
    counted, conhost = set(attack["counted"]), set(attack["conhost"])
    ids = rule["record_ids"]
    return {"rule_id": rule_id, "title": rule["title"], "level": rule["level"], "rule_file": rule["rule_file"],
            "matched": rule["count"], "on_attack": sorted(counted.intersection(ids)),
            "on_conhost": sorted(conhost.intersection(ids)),
            "other_events": sum(i not in counted and i not in conhost for i in ids),
            "no_record_id": rule["no_record_id"]}


def caught(rows: list) -> bool:
    return any(r["level"] in CAUGHT_LEVELS and r["on_attack"] for r in rows)


def level_counts(rows: list) -> dict:
    counts = {level: {"matched": 0, "on_attack": 0} for level in LEVELS}
    for row in rows:
        entry = counts.setdefault(row["level"], {"matched": 0, "on_attack": 0})
        entry["matched"] += 1
        entry["on_attack"] += bool(row["on_attack"])
    return counts


def run_pack(hdir, binary: str, evtx, outfile, extra=(), runner=subprocess.run) -> dict:
    """The whole rules folder through Hayabusa with the validated settings, plus any extra flags."""
    run = run_hayabusa(hdir, binary, evtx, Path(hdir) / "rules", outfile, runner, extra=extra)
    if not run["loaded"]:
        return {"status": "not loaded", "load": run["load"], "rules": None, "reason": run["reason"]}
    if run["exit_code"] != 0 or run["detections"] is None:
        return {"status": "tool error", "load": run["load"], "rules": None, "reason": run["printed_tail"]}
    return {"status": "ran", "load": run["load"], "rules": read_pack(outfile), "reason": ""}


def ours_rows(path, rules_root, recording: str, attack: dict) -> list:
    """Our rules on this recording, from R12.3's Hayabusa results; the level comes from each rule's own file."""
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row.get("recording") != recording:
            continue
        rule_path = Path(rules_root) / row["set"] / row["rule_file"]
        level = (yaml.safe_load(rule_path.read_text(encoding="utf-8")) or {}).get("level")
        engine = row["hayabusa"]
        base = {"set": row["set"], "status": engine["status"]}
        if engine["status"] == "ran":
            rule = {"title": row["title"], "level": level, "rule_file": row["rule_file"], "count": engine["matched"],
                    "record_ids": engine["record_ids"], "no_record_id": 0}
            rows.append({**base, **score(row["rule_id"], rule, attack)})
        else:
            rows.append({**base, "rule_id": row["rule_id"], "title": row["title"], "level": level,
                         "rule_file": row["rule_file"], "matched": None, "on_attack": None, "on_conhost": None,
                         "other_events": None, "no_record_id": 0})
    return rows


def _show(row: dict) -> str:
    return (f"  {str(row['level']):13} attack {str(row['on_attack']):24} conhost {str(row['on_conhost']):16} "
            f"other {str(row['other_events']):>6}  | {str(row['title'])[:70]}")


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--evtx", type=Path, required=True)
    parser.add_argument("--ours", type=Path, required=True, help="R12.3's rows")
    parser.add_argument("--ours-rules", type=Path, required=True, help="folder holding our rule sets")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--work", type=Path, default=None, help="the engines' files")
    parser.add_argument("--zircolite", type=Path, default=ZIRCOLITE_DIR)
    parser.add_argument("--hayabusa", type=Path, default=HAYABUSA_DIR)
    parser.add_argument("--binary", default=HAYABUSA_BINARY)
    parser.add_argument("--converter", type=Path, default=CONVERTER_DIR)
    args = parser.parse_args(argv)
    evtx = args.evtx.resolve()
    work = (args.work or Path(tempfile.mkdtemp(prefix="pack_on_recording_"))).resolve()
    env = {"zircolite": zircolite_environment(args.zircolite, SIGMA),
           "hayabusa": hayabusa_environment(args.hayabusa, args.binary, args.converter, SIGMA)}
    print(f"Zircolite {env['zircolite']['zircolite_version']}; Hayabusa {env['hayabusa']['hayabusa_version']}, rules "
          f"{env['hayabusa']['hayabusa_rules_commit']}; work folder {work}")

    events = read_events(args.zircolite.resolve(), evtx, work / "events")
    attack = attack_events(events)
    kinds = dict(sorted(Counter(e["EventID"] for e in events).items()))
    print(f"{len(events)} events {kinds}; server starts {attack['servers']}; {attack['processes']} processes, "
          f"{len(attack['events'])} attack events, {len(attack['counted'])} counted, conhost {attack['conhost']}")
    for event in attack["events"]:
        print(f"  {event['record_id']} event {event['event_id']} {event['program']}"
              f"{'' if event['counts'] else ' (not counted)'}")
    if not attack["counted"]:
        print("No attack events found: nothing to measure.")
        return 1

    report = {"environment": env, "recording": evtx.name, "events": len(events), "event_ids": kinds, "attack": attack,
              "runs": {}}
    rows = []
    for name, extra in RUNS:
        run = run_pack(args.hayabusa.resolve(), args.binary, evtx, work / f"pack-{name.replace(' ', '-')}.jsonl", extra)
        summary = {"status": run["status"], "load": run["load"], "reason": run["reason"]}
        print(f"\n{name}: {run['status']}; loaded {run['load']['total_rules']}, after the channel filter "
              f"{run['load']['enabled_after_channel_filter']}; excluded {run['load']['excluded']}, noisy "
              f"{run['load']['noisy']}, deprecated {run['load']['deprecated']}, unsupported "
              f"{run['load']['unsupported']}")
        if run["status"] == "ran":
            scored = sorted((score(rule_id, rule, attack) for rule_id, rule in run["rules"].items()),
                            key=lambda r: (LEVELS.index(r["level"]) if r["level"] in LEVELS else len(LEVELS),
                                           -len(r["on_attack"]), str(r["title"])))
            rows += [{"run": name, **row} for row in scored]
            summary.update(rules_matched=len(scored), levels=level_counts(scored), caught=caught(scored),
                           no_record_id=sum(r["no_record_id"] for r in scored))
            print(f"rules that matched something: {len(scored)}; caught: {summary['caught']}")
            for level, counts in summary["levels"].items():
                print(f"  {level:13} matched {counts['matched']:4}  on the attack {counts['on_attack']}")
            for row in scored:
                if row["on_attack"] or row["on_conhost"]:
                    print(_show(row))
        report["runs"][name] = summary

    ours = ours_rows(args.ours, args.ours_rules, evtx.name, attack)
    ran = [r for r in ours if r["status"] == "ran"]
    report["ours"] = {"rules": len(ours), "ran": len(ran), "levels": level_counts(ran), "caught": caught(ran)}
    print(f"\nours: {len(ours)} rules, ran {len(ran)}; caught: {report['ours']['caught']}")
    for row in ours:
        print(f"  {row['set'][:36]:36} {row['rule_file']:14}{_show(row)}")
    rows += [{"run": "ours", **row} for row in ours]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(json.dumps(report) + "\n")
        for row in rows:
            f.write(json.dumps(row) + "\n")
    print(f"\nrows: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
