#!/usr/bin/env python3
"""R11.4 Step A - the expert's rule on each CVE pair (plan fixed in the log 2026-10-19, "R11.4 the CVE pairs: the
plan", before this tool was written).

A pair is one of our in-scope reports and a public recording of the same CVE (`eval/results/evtx_inventory.json`).
For each pair, two Zircolite runs:
- **detection** - the expert's (gold) rule alone, with exactly the settings validated in R11.3
  (`validate_zircolite.SETTINGS`, cwd = Zircolite's folder): converted or not, events matched, their EventRecordIDs;
- **census** - the same rule and settings plus `--no-event-filter --dbfile -sr`, run in a scratch folder: the
  recording's event counts per channel (from the saved database; only counts are kept) and the channels and event IDs
  the converted rule reads (from the saved ruleset).
Each pair is **usable** (the rule fires), **silent, channel present**, **silent, channel absent**, **not converted** or
**tool error**; a rule reading any channel other than Sysmon's is flagged **outside the validated scope**. A report is
usable when one of its pairs is. Rows name the report as `report` (not `rule_id`): Step A runs only the expert's rule,
so the held-out draw (`draw_heldout.used_rule_ids`) must not count these reports as run.

Usage:
    .venv/bin/python eval/cve_pairs.py [--zircolite ../Zircolite] [--out eval/results/cve_pairs_stepA.jsonl]
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.scope import in_scope  # noqa: E402
from eval.validate_zircolite import (  # noqa: E402
    ENV, RUN_TIMEOUT_S, SIGMA, ZIRCOLITE_DIR, command, environment, run_zircolite)

SCOPE = "windows-linux"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
CENSUS_OPTIONS = ("--no-event-filter", "-sr")


def pairs(inventory: dict, cases: dict, scope: str) -> list:
    """(report, recording) pairs: every in-scope report's same-CVE recordings, by report then recording."""
    cves_of = {r["file"]: r.get("cves") or [] for r in inventory.get("recordings") or []}
    out = []
    for rid in sorted(inventory.get("matches") or {}):
        files = (inventory["matches"][rid] or {}).get("same_cve") or []
        if not files or rid not in cases or not in_scope(cases[rid], scope):
            continue
        for f in sorted(files):
            out.append({"report": rid, "recording": f, "rule_path": cases[rid]["rule_path"],
                        "cves": sorted(cves_of.get(f, []))})
    return out


def classify(converted, matched, rule_channels: list, channels: dict) -> str:
    if converted == 0:
        return "not converted"
    if matched:
        return "usable"
    if not rule_channels:
        return "silent, channel present" if channels else "silent, channel absent"
    return "silent, channel present" if any(channels.get(c) for c in rule_channels) else "silent, channel absent"


def outside_validated(rule_channels: list) -> bool:
    """The R11.3 validation exercised Sysmon recordings only."""
    return not rule_channels or any(c != SYSMON for c in rule_channels)


def census_command(zdir, evtx, rule, census_dir) -> list:
    census_dir = Path(census_dir)
    return (command(zdir, [evtx], [rule], census_dir / "census.json", census_dir / "census.log")
            + ["--no-event-filter", "--dbfile", str(census_dir / "census.db"), "-sr"])


def read_census(folder) -> dict:
    folder = Path(folder)
    out = {"channels": {}, "rule_channels": [], "rule_eventids": [], "rule_events_present": None}
    saved = sorted(folder.glob("ruleset-*.json"))
    if saved:
        rules = json.loads(saved[0].read_text(encoding="utf-8")) or [{}]
        out["rule_channels"] = sorted({str(c) for r in rules for c in r.get("channel") or []})
        out["rule_eventids"] = sorted({int(e) for r in rules for e in r.get("eventid") or []})
    dbs = sorted(folder.glob("*.db"))
    if dbs:
        con = sqlite3.connect(str(dbs[0]))
        try:
            out["channels"] = {str(c): n for c, n in con.execute("SELECT Channel, COUNT(*) FROM logs GROUP BY Channel")}
            where, args = [], []
            if out["rule_channels"]:
                where.append(f"Channel IN ({','.join('?' * len(out['rule_channels']))})")
                args += out["rule_channels"]
            if out["rule_eventids"]:
                where.append(f"CAST(EventID AS INTEGER) IN ({','.join('?' * len(out['rule_eventids']))})")
                args += out["rule_eventids"]
            sql = "SELECT COUNT(*) FROM logs" + (" WHERE " + " AND ".join(where) if where else "")
            out["rule_events_present"] = con.execute(sql, args).fetchone()[0]
        finally:
            con.close()
    return out


def check_pair(pair: dict, evtx_root, repo_root, zdir, workdir, runner=subprocess.run) -> dict:
    evtx = Path(evtx_root) / pair["recording"]
    rule = Path(repo_root) / pair["rule_path"]
    key = f"{pair['report'][:8]}_{hashlib.sha1(pair['recording'].encode('utf-8')).hexdigest()[:8]}"
    det_dir, census_dir = Path(workdir) / "detection", Path(workdir) / "census" / key
    det_dir.mkdir(parents=True, exist_ok=True)
    census_dir.mkdir(parents=True, exist_ok=True)
    run = run_zircolite(zdir, [evtx], [rule], det_dir / f"{key}.json", det_dir / f"{key}.log", runner)
    try:
        census_run = runner(census_command(zdir, evtx, rule, census_dir), cwd=str(census_dir), env={**os.environ, **ENV},
                            capture_output=True, text=True, timeout=RUN_TIMEOUT_S)
        census_exit = census_run.returncode
    except subprocess.TimeoutExpired:
        census_exit = None
    census = read_census(census_dir)
    conv = run["conversion"]
    row = {"report": pair["report"], "recording": pair["recording"], "cves": pair["cves"],
           "exit_code": run["exit_code"], "conversion": conv, "matched": None, "record_ids": None,
           **census, "census_exit_code": census_exit, "label": None,
           "outside_validated_scope": outside_validated(census["rule_channels"]), "reason": ""}
    if conv["converted"] == 0 or conv["loaded"] == 0:
        row["label"] = "not converted"
        return row
    if run["exit_code"] != 0 or run["detections"] is None:
        row.update(label="tool error", reason=run["stderr_tail"])
        return row
    dets = run["detections"].values()
    row["matched"] = sum(d["count"] for d in dets)
    row["record_ids"] = sorted({i for d in dets for i in d["record_ids"]})
    row["label"] = classify(conv["converted"], row["matched"], census["rule_channels"], census["channels"])
    return row


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--zircolite", type=Path, default=ZIRCOLITE_DIR)
    parser.add_argument("--inventory", type=Path, default=REPO / "eval/results/evtx_inventory.json")
    parser.add_argument("--evtx", type=Path, default=REPO / "data/evtx")
    parser.add_argument("--out", type=Path, default=REPO / "eval/results/cve_pairs_stepA.jsonl")
    parser.add_argument("--work", type=Path, default=None)
    args = parser.parse_args(argv)
    from eval.run_eval import load_cases

    with contextlib.redirect_stdout(io.StringIO()):
        cases = {c["rule_id"]: c for c in load_cases(REPO / "eval/manifest.jsonl", REPO, 2000)}
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    todo = pairs(inventory, cases, SCOPE)
    work = args.work or Path(tempfile.mkdtemp(prefix="cve_pairs_"))
    env = environment(args.zircolite, SIGMA)
    print(f"Zircolite {env['zircolite_version']} @ {env['zircolite_commit']}; {len(todo)} pairs, "
          f"{len({p['report'] for p in todo})} reports in scope {SCOPE}; work folder {work}")
    rows = []
    for i, pair in enumerate(todo, 1):
        row = check_pair(pair, args.evtx, REPO, args.zircolite, work)
        rows.append(row)
        print(f"  {i:2}/{len(todo)} {row['report'][:8]} {row['label']:24} matched {row['matched']}"
              f"{'  [outside validated scope]' if row['outside_validated_scope'] else ''}", flush=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(json.dumps({"environment": env, "scope": SCOPE, "pairs": len(rows)}) + "\n")
        for row in rows:
            f.write(json.dumps(row) + "\n")

    print(f"\npairs: {dict(Counter(r['label'] for r in rows))}")
    by_report = defaultdict(list)
    for r in rows:
        by_report[r["report"]].append(r)
    usable = sorted(rid for rid, rs in by_report.items() if any(r["label"] == "usable" for r in rs))
    print(f"usable reports: {len(usable)} of {len(by_report)}")
    for rid, rs in sorted(by_report.items()):
        labels = Counter(r["label"] for r in rs)
        flag = " [outside validated scope]" if any(r["outside_validated_scope"] for r in rs) else ""
        print(f"  {rid[:8]} {len(rs)} pair(s): {dict(labels)}{flag}")
    by_cve = defaultdict(set)
    for r in rows:
        if r["label"] == "usable":
            for cve in r["cves"]:
                by_cve[cve].add(r["report"][:8])
    print(f"usable by CVE: {dict((k, sorted(v)) for k, v in sorted(by_cve.items()))}")
    print(f"rows: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
