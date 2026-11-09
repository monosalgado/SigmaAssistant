#!/usr/bin/env python3
"""Change 54 real-attack check `[DEMO]` (plan in the log 2026-11-09): each arm's rules for a report run on the
report's SigmaHQ recording, each rule on its own, with Zircolite and Hayabusa (both validated: R11.3, R12.2), and the
expert rule too.

**Caught** = at least one of the arm's rules matches at least one event the expert rule matches (Zircolite; Hayabusa
as a cross-check). Each rule's other matched events are shown. A rule that does not parse, or that an engine cannot
run, is shown as such, never as 0 matches. Each rule is written to its own file with a fresh id (two generated rules
can share one, and the converter maps copies by id); nothing else in the rule changes.

Usage:
    .venv/bin/python eval/rules_on_recording.py --case <rule id> <regression folder> [--case ...]
        --arm <label> <rows.jsonl> [--arm ...] --out <file.jsonl>
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import uuid
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.compare_engines import compare_rule  # noqa: E402
from eval.validate_hayabusa import CONVERTER_DIR, HAYABUSA_BINARY, HAYABUSA_DIR, convert_rules  # noqa: E402
from eval.validate_zircolite import ZIRCOLITE_DIR  # noqa: E402

NAMESPACE = uuid.UUID("2a4c6f00-54c5-4b1e-9d0a-000000000054")


def case_row(path, rule_id: str):
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            if row.get("rule_id") == rule_id:
                return row
    return None


def write_rules(yamls: list, folder, label: str) -> list:
    """One file per generated rule, with a fresh id that is the same on every run; a text that does not parse or is
    not a rule is noted and not written."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    out = []
    for i, text in enumerate(yamls or [], 1):
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as e:
            out.append({"index": i, "path": None, "note": f"does not parse: {type(e).__name__}"})
            continue
        if not isinstance(doc, dict) or "detection" not in doc:
            out.append({"index": i, "path": None, "note": "not a rule (no detection)"})
            continue
        doc["id"] = str(uuid.uuid5(NAMESPACE, f"{label}-{i}"))
        path = folder / f"{label}-rule{i}.yml"
        path.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
        out.append({"index": i, "path": str(path), "note": ""})
    return out


def recording(folder) -> Path:
    found = sorted(Path(folder).glob("*.evtx"))
    if len(found) != 1:
        raise ValueError(f"{folder}: {len(found)} recordings, expected 1")
    return found[0]


def judge(result: dict, expert_ids: set) -> dict:
    z, h = result["zircolite"], result["hayabusa"]
    zi = set(z["record_ids"] or []) if z["status"] == "ran" else None
    hi = set(h["record_ids"] or []) if h["status"] == "ran" else None
    return {"zircolite_status": z["status"], "hayabusa_status": h["status"],
            "on_expert_zircolite": sorted(zi & expert_ids) if zi is not None else None,
            "other_zircolite": len(zi - expert_ids) if zi is not None else None,
            "on_expert_hayabusa": sorted(hi & expert_ids) if hi is not None else None,
            "same_events": result.get("same_events")}


def caught(judged: list) -> bool:
    return any(j["on_expert_zircolite"] for j in judged)


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--case", nargs=2, action="append", required=True, metavar=("RULE_ID", "REGRESSION_FOLDER"))
    parser.add_argument("--arm", nargs=2, action="append", required=True, metavar=("LABEL", "ROWS"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--work", type=Path, default=None)
    parser.add_argument("--zircolite", type=Path, default=ZIRCOLITE_DIR)
    parser.add_argument("--hayabusa", type=Path, default=HAYABUSA_DIR)
    parser.add_argument("--binary", default=HAYABUSA_BINARY)
    parser.add_argument("--converter", type=Path, default=CONVERTER_DIR)
    args = parser.parse_args(argv)
    work = (args.work or Path(tempfile.mkdtemp(prefix="rules_on_recording_"))).resolve()
    rows_out = []
    for rule_id, folder in args.case:
        evtx = recording(folder).resolve()
        arms = {}
        for label, rows_path in args.arm:
            row = case_row(rows_path, rule_id)
            if row is None:
                print(f"{rule_id[:8]}: no row in {label}")
                return 1
            arms[label] = row
        expert = (REPO / next(iter(arms.values()))["rule_path"]).resolve()
        written = {label: write_rules(row.get("rules_yaml") or [], work / rule_id[:8] / label, f"{label}-{rule_id[:8]}")
                   for label, row in arms.items()}
        paths = [expert] + [Path(w["path"]) for ws in written.values() for w in ws if w["path"]]
        converted, _ = convert_rules(args.converter, paths, work / rule_id[:8] / "convert")
        run = lambda p: compare_rule(p, evtx, converted, args.zircolite.resolve(), args.hayabusa.resolve(),  # noqa: E731
                                     args.binary, work / rule_id[:8] / "runs")
        expert_result = run(expert)
        expert_ids = set(expert_result["zircolite"]["record_ids"] or [])
        print(f"\n{rule_id[:8]} on {evtx.name}: expert rule '{expert_result['title']}' - Zircolite "
              f"{expert_result['zircolite']['matched']}, Hayabusa {expert_result['hayabusa']['matched']}")
        for label, ws in written.items():
            judged = []
            for w in ws:
                if not w["path"]:
                    judged.append({"index": w["index"], "title": None, "logsource": None, "note": w["note"],
                                   "on_expert_zircolite": None})
                    continue
                result = run(Path(w["path"]))
                doc = yaml.safe_load(Path(w["path"]).read_text(encoding="utf-8"))
                judged.append({"index": w["index"], "title": doc.get("title"), "logsource": doc.get("logsource"),
                               "note": "", **judge(result, expert_ids)})
            row = {"case": rule_id, "recording": evtx.name, "arm": label, "expert_title": expert_result["title"],
                   "expert_events": sorted(expert_ids), "caught": caught(judged), "rules": judged}
            rows_out.append(row)
            print(f"  {label}: caught {row['caught']} ({len(ws)} rules)")
            for j in judged:
                print(f"    rule {j['index']}: {str(j.get('logsource'))[:60]:60} on expert events "
                      f"{j.get('on_expert_zircolite')} other {j.get('other_zircolite')} hayabusa "
                      f"{j.get('on_expert_hayabusa')} {j.get('note') or ''} | {str(j.get('title'))[:50]}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("".join(json.dumps(r) + "\n" for r in rows_out), encoding="utf-8")
    print(f"\nrows: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
