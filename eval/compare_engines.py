#!/usr/bin/env python3
"""R12.3 `[DEMO]` - the same rules through Hayabusa and Zircolite on the same recording (plan in the log 2026-11-03,
"Plan R12", step 3; both engines validated first: Zircolite R11.3, Hayabusa R12.2).

For each pair (a folder of Sigma rules, a recording): every rule runs **on its own** in each engine - Zircolite on the
rule as written (`validate_zircolite.run_zircolite`, its validated settings), Hayabusa on the converter's Sysmon copy
(`validate_hayabusa.convert_rules` + `run_hayabusa`, its validated settings; each rule converted on its own). A row
keeps each engine's count and the events it matched (Windows event record numbers) and says whether the two found the
same events. A rule an engine could not run is shown as **not converted**, **not loaded** or **tool error**, never as
0 matches. Descriptive: the recordings are the user's lab captures (local, gitignored); only counts, record numbers
and rule titles are written.

Usage:
    .venv/bin/python eval/compare_engines.py --pair <rules folder> <recording.evtx> [--pair ...] --out <file.jsonl>
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.validate_hayabusa import (  # noqa: E402
    CONVERTER_DIR,
    HAYABUSA_BINARY,
    HAYABUSA_DIR,
    convert_rules,
    environment as hayabusa_environment,
    run_hayabusa,
)
from eval.validate_zircolite import ZIRCOLITE_DIR, environment as zircolite_environment, run_zircolite  # noqa: E402

SIGMA = REPO / "data/sigma"


def _zircolite_result(run: dict, rule_id: str) -> dict:
    conv = run["conversion"]
    if conv["converted"] == 0 or conv["loaded"] == 0:
        return {"status": "not converted", "matched": None, "record_ids": None,
                "reason": f"converted {conv['converted']}, skipped {conv['skipped']}, failed {conv['failed']}"}
    if run["exit_code"] != 0 or run["detections"] is None:
        return {"status": "tool error", "matched": None, "record_ids": None, "reason": run["stderr_tail"]}
    det = run["detections"].get(rule_id) or {"count": 0, "record_ids": []}
    return {"status": "ran", "matched": det["count"], "record_ids": det["record_ids"], "reason": ""}


def _hayabusa_result(run: dict, converted_id: str) -> dict:
    if not run["loaded"]:
        return {"status": "not loaded", "matched": None, "record_ids": None, "reason": run["reason"]}
    if run["exit_code"] != 0 or run["detections"] is None:
        return {"status": "tool error", "matched": None, "record_ids": None, "reason": run["printed_tail"]}
    det = run["detections"].get(converted_id) or {"count": 0, "record_ids": []}
    return {"status": "ran", "matched": det["count"], "record_ids": det["record_ids"], "reason": ""}


def compare_rule(rule_path, evtx, converted: dict, zdir, hdir, binary: str, workdir,
                 zrunner=subprocess.run, hrunner=subprocess.run) -> dict:
    rule = yaml.safe_load(Path(rule_path).read_text(encoding="utf-8")) or {}
    rule_id = str(rule.get("id"))
    workdir = Path(workdir)
    (workdir / "zircolite").mkdir(parents=True, exist_ok=True)
    zrun = run_zircolite(zdir, [evtx], [rule_path], workdir / "zircolite" / f"{rule_id}.json",
                         workdir / "zircolite" / f"{rule_id}.log", zrunner)
    zircolite = _zircolite_result(zrun, rule_id)
    copy = converted.get(rule_id)
    if copy is None:
        hayabusa = {"status": "not converted", "matched": None, "record_ids": None,
                    "reason": "the converter made no Sysmon copy"}
    else:
        hrun = run_hayabusa(hdir, binary, evtx, copy["path"], workdir / "hayabusa" / f"{rule_id}.jsonl", hrunner)
        hayabusa = _hayabusa_result(hrun, copy["converted_id"])
    both = zircolite["status"] == "ran" and hayabusa["status"] == "ran"
    return {"rule_file": Path(rule_path).name, "rule_id": rule_id, "title": rule.get("title"),
            "converted_id": copy["converted_id"] if copy else None, "zircolite": zircolite, "hayabusa": hayabusa,
            "same_events": zircolite["record_ids"] == hayabusa["record_ids"] if both else None}


def summarise(rows: list) -> dict:
    both = [r for r in rows if r["zircolite"]["matched"] is not None and r["hayabusa"]["matched"] is not None]
    return {"rules": len(rows), "both_ran": len(both), "same_events": sum(r["same_events"] is True for r in rows),
            "same_count": sum(r["zircolite"]["matched"] == r["hayabusa"]["matched"] for r in both),
            "differ": sum(r["same_events"] is False for r in rows)}


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pair", nargs=2, action="append", required=True, metavar=("RULES_FOLDER", "EVTX"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--work", type=Path, default=None, help="converted rules and the engines' files")
    parser.add_argument("--zircolite", type=Path, default=ZIRCOLITE_DIR)
    parser.add_argument("--hayabusa", type=Path, default=HAYABUSA_DIR)
    parser.add_argument("--binary", default=HAYABUSA_BINARY)
    parser.add_argument("--converter", type=Path, default=CONVERTER_DIR)
    args = parser.parse_args(argv)
    work = args.work or Path(tempfile.mkdtemp(prefix="compare_engines_"))
    env = {"zircolite": zircolite_environment(args.zircolite, SIGMA),
           "hayabusa": hayabusa_environment(args.hayabusa, args.binary, args.converter, SIGMA)}
    print(f"Zircolite {env['zircolite']['zircolite_version']}; Hayabusa {env['hayabusa']['hayabusa_version']} "
          f"(converter {env['hayabusa']['converter_commit']}); work folder {work}")

    rows = []
    for rules_folder, evtx in args.pair:
        label = Path(rules_folder).name
        rules = sorted(Path(rules_folder).glob("*.yml"))
        converted, _ = convert_rules(args.converter, rules, work / "convert" / label)
        print(f"\n{label} on {Path(evtx).name}: {len(rules)} rules, {len(converted)} with a Sysmon copy")
        for rule in rules:
            row = compare_rule(rule, evtx, converted, args.zircolite, args.hayabusa, args.binary, work / "runs" / label)
            row.update(set=label, recording=Path(evtx).name)
            rows.append(row)
            z, h = row["zircolite"], row["hayabusa"]
            show = lambda e: e["matched"] if e["status"] == "ran" else e["status"]  # noqa: E731
            print(f"  {row['rule_file']:14} Zircolite {str(show(z)):>13}  Hayabusa {str(show(h)):>13}  "
                  f"same events: {row['same_events']}  | {str(row['title'])[:60]}")

    summary = summarise(rows)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(json.dumps({"environment": env, "pairs": [[Path(r).name, Path(e).name] for r, e in args.pair],
                            "summary": summary}) + "\n")
        for row in rows:
            f.write(json.dumps(row) + "\n")
    print(f"\n{summary['rules']} rules; both engines ran {summary['both_ran']}; same events {summary['same_events']}; "
          f"same count {summary['same_count']}; differ {summary['differ']}")
    print(f"rows: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
