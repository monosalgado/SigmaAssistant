#!/usr/bin/env python3
"""R11.3 - validate Zircolite on SigmaHQ's recordings with known answers (plan fixed in the log 2026-10-19,
"Zircolite validation on SigmaHQ's recordings: the plan", before this tool was written).

Each recording (`data/sigma/regression_data/**/info.yml`, all Sysmon EVTX) names one rule by id and the number of
events it must match (`match_count`; absent = at least 1). Zircolite - installed outside this repository, in its own
environment - is run as a separate program on the recording's EVTX **with that rule only** and fixed settings
(`SETTINGS`: its documented Sysmon mappings; no result dropped; no cache). **agree** = the rule converted and the
number of matching events equals `match_count` (at least 1 when absent); **disagree** = converted, any other number,
0 included. Listed apart with the reason: **not converted** (Zircolite converted no rule), **tool error** (exit code
not 0 or no output), **rule not found**, **no EVTX**. Our rules using a construct that does not convert would be
"not evaluable", never "did not fire".
Cross-checks (descriptive): our matcher (`eval/rule_matcher.py`) on the recording's JSON - the same number of events,
and the same events (EventRecordID); and off-target matches - each recording run once with every recording's rule,
the (rule, recording) pairs with a match set against our matcher's (`matcher_validation.jsonl`).

Usage:
    .venv/bin/python eval/validate_zircolite.py [--zircolite ../Zircolite] [--out eval/results/zircolite_validation.jsonl]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.rule_matcher import CannotEvaluate, flatten_event, load_raw_events, parse_rule, rule_matches  # noqa: E402
from eval.validate_matcher import rule_index  # noqa: E402

SIGMA = REPO / "data/sigma"
ZIRCOLITE_DIR = REPO.parent / "Zircolite"
SETTINGS = ("--pipeline", "sysmon", "--pipeline", "windows-logsources", "--flatten-backend", "cython",
            "--limit", "-1")
ENV = {"ZIRCOLITE_NO_CACHE": "1"}
RUN_TIMEOUT_S = 900

_MARKUP = re.compile(r"\[/?[a-z ]*\]|\\\[")
_CONVERTED = re.compile(r"Converted\s+(\d+)\s+rules?(?:\s*\((\d+)\s+invalid skipped,\s*(\d+)\s+failed\))?")
_LOADED = re.compile(r"(\d+)\s+rules?\s+loaded")


def command(zdir, events: list, rules: list, outfile, logfile) -> list:
    return ([str(Path(zdir) / ".venv/bin/python"), "-m", "zircolite", "--events", *map(str, events),
             "--ruleset", *map(str, rules), *SETTINGS, "--outfile", str(outfile), "--logfile", str(logfile)])


def parse_conversion(log_text: str) -> dict:
    """Zircolite's own report of the conversion: rules converted, skipped as invalid, failed; rules loaded."""
    out = {"converted": None, "skipped": 0, "failed": 0, "loaded": None}
    for line in (log_text or "").splitlines():
        plain = _MARKUP.sub("", line)
        m = _CONVERTED.search(plain)
        if m:
            out["converted"] = (out["converted"] or 0) + int(m.group(1))
            out["skipped"] += int(m.group(2) or 0)
            out["failed"] += int(m.group(3) or 0)
        m = _LOADED.search(plain)
        if m:
            out["loaded"] = int(m.group(1))
    return out


def read_detections(path) -> dict:
    """{rule id: {"count", "record_ids"}} from Zircolite's detections file; None when there is no file."""
    path = Path(path)
    if not path.exists():
        return None
    out = {}
    for det in json.loads(path.read_text(encoding="utf-8") or "[]"):
        ids = sorted(int(m["EventRecordID"]) for m in det.get("matches") or [] if m.get("EventRecordID") is not None)
        out[str(det.get("id"))] = {"count": int(det.get("count") or 0), "record_ids": ids}
    return out


def verdict(expected, matched: int) -> str:
    return "agree" if (matched >= 1 if expected is None else matched == expected) else "disagree"


def off_target_pairs(detections: dict, own_rule_id: str) -> list:
    return sorted([rid, d["count"]] for rid, d in detections.items() if rid != own_rule_id and d["count"])


def _record_id(raw: dict):
    system = ((raw or {}).get("Event") or {}).get("System") or {}
    value = system.get("EventRecordID")
    if isinstance(value, dict):
        value = value.get("#text")
    return int(value) if value is not None else None


def matcher_events(rule_path, json_paths: list) -> tuple:
    """Our matcher on the recording's JSON: (matching events, their EventRecordIDs)."""
    parsed = parse_rule(Path(rule_path).read_text(encoding="utf-8"))
    ids = [_record_id(raw) for path in json_paths for raw in load_raw_events(path)
           if rule_matches(parsed, flatten_event(raw))]
    return len(ids), sorted(i for i in ids if i is not None)


def run_zircolite(zdir, events: list, rules: list, outfile, logfile, runner=subprocess.run) -> dict:
    for path in (Path(outfile), Path(logfile)):
        if path.exists():
            path.unlink()
    try:
        done = runner(command(zdir, events, rules, outfile, logfile), cwd=str(zdir), env={**os.environ, **ENV},
                      capture_output=True, text=True, timeout=RUN_TIMEOUT_S)
        exit_code, stderr = done.returncode, (done.stderr or "")
    except subprocess.TimeoutExpired:
        exit_code, stderr = None, f"timed out after {RUN_TIMEOUT_S} s"
    log = Path(logfile).read_text(encoding="utf-8", errors="replace") if Path(logfile).exists() else ""
    return {"exit_code": exit_code, "conversion": parse_conversion(log), "detections": read_detections(outfile),
            "stderr_tail": stderr[-300:]}


def _info(info_path: Path) -> tuple:
    info = yaml.safe_load(info_path.read_text(encoding="utf-8")) or {}
    rule_id = str(((info.get("rule_metadata") or [{}])[0]).get("id"))
    tests = [t for t in info.get("regression_tests_info") or [] if isinstance(t, dict)]
    return rule_id, (tests[0].get("match_count") if tests else None)


def check_recording(info_path, index: dict, zdir, workdir, runner=subprocess.run) -> dict:
    info_path = Path(info_path)
    rule_id, expected = _info(info_path)
    row = {"rule_id": rule_id,
           "recording": str(info_path.parent.relative_to(info_path.parents[2]) if len(info_path.parents) > 2
                            else info_path.parent),
           "expected": expected, "matched": None, "record_ids": None, "verdict": None, "reason": "",
           "exit_code": None, "conversion": None, "matcher_count": None, "matcher_record_ids": None,
           "same_count_as_matcher": None, "same_events_as_matcher": None}
    if rule_id not in index:
        row["verdict"] = "rule not found"
        return row
    evtx = sorted(info_path.parent.glob("*.evtx"))
    if not evtx:
        row["verdict"] = "no EVTX"
        return row
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    run = run_zircolite(zdir, evtx, [index[rule_id]], workdir / f"{rule_id}.json", workdir / f"{rule_id}.log",
                        runner)
    row.update(exit_code=run["exit_code"], conversion=run["conversion"])
    conv = run["conversion"]
    if conv["converted"] == 0 or conv["loaded"] == 0:
        row.update(verdict="not converted",
                   reason=f"converted {conv['converted']}, skipped {conv['skipped']}, failed {conv['failed']}")
        return row
    if run["exit_code"] != 0 or run["detections"] is None:
        row.update(verdict="tool error", reason=run["stderr_tail"])
        return row
    det = run["detections"].get(rule_id) or {"count": 0, "record_ids": []}
    row.update(matched=det["count"], record_ids=det["record_ids"], verdict=verdict(expected, det["count"]))
    jsons = sorted(info_path.parent.glob("*.json"))
    if jsons:
        try:
            count, ids = matcher_events(index[rule_id], jsons)
            row.update(matcher_count=count, matcher_record_ids=ids, same_count_as_matcher=count == det["count"],
                       same_events_as_matcher=ids == det["record_ids"])
        except CannotEvaluate as exc:
            row["reason"] = f"our matcher cannot evaluate: {str(exc)[:150]}"
    return row


def _git(path, *args):
    """A git answer for `path` only when `path` is itself the top of a checkout (never a parent's)."""
    try:
        top = subprocess.run(["git", "-C", str(path), "rev-parse", "--show-toplevel"], capture_output=True, text=True)
        if top.returncode != 0 or Path(top.stdout.strip()).resolve() != Path(path).resolve():
            return None
        out = subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True)
        return out.stdout.strip() if out.returncode == 0 else None
    except OSError:
        return None


def environment(zdir, sigma_dir, version_runner=subprocess.run) -> dict:
    zdir = Path(zdir)
    lock = zdir / "uv.lock"
    try:
        done = version_runner([str(zdir / ".venv/bin/python"), "-m", "zircolite", "--version"], cwd=str(zdir),
                              env={**os.environ, **ENV}, capture_output=True, text=True, timeout=120)
        m = re.search(r"v\d+\.\d+\.\d+", (done.stdout or "") + (done.stderr or ""))
        version = m.group(0) if m else None
    except (OSError, subprocess.TimeoutExpired):
        version = None
    return {"zircolite_commit": _git(zdir, "rev-parse", "HEAD"), "zircolite_version": version,
            "uv_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest() if lock.exists() else None,
            "settings": list(SETTINGS), "env": dict(ENV), "sigma_commit": _git(sigma_dir, "rev-parse", "--short", "HEAD")}


def _matcher_off_target(path: Path) -> set:
    """(rule, recording's rule) pairs our matcher's validation found, from its committed result file."""
    if not path.exists():
        return set()
    pairs = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            pairs |= {(row["rule_id"], other) for other, _ in row.get("off_target") or []}
    return pairs


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--zircolite", type=Path, default=ZIRCOLITE_DIR)
    parser.add_argument("--out", type=Path, default=REPO / "eval/results/zircolite_validation.jsonl")
    parser.add_argument("--work", type=Path, default=None, help="Zircolite's output files (default: a temp folder)")
    parser.add_argument("--limit", type=int, default=0, help="first N recordings only (a check, not the result)")
    parser.add_argument("--skip-off-target", action="store_true")
    args = parser.parse_args(argv)
    work = args.work or Path(tempfile.mkdtemp(prefix="zircolite_validation_"))
    index = rule_index([d for d in SIGMA.iterdir() if d.is_dir() and (d.name.startswith("rules") or d.name == "deprecated")])
    infos = sorted((SIGMA / "regression_data").rglob("info.yml"))
    if args.limit:
        infos = infos[:args.limit]
    env = environment(args.zircolite, SIGMA)
    print(f"Zircolite {env['zircolite_version']} @ {env['zircolite_commit']}; SigmaHQ @ {env['sigma_commit']}; "
          f"{len(infos)} recordings; work folder {work}")

    rows = []
    for i, info in enumerate(infos, 1):
        row = check_recording(info, index, args.zircolite, work / "own")
        rows.append(row)
        print(f"  {i:3}/{len(infos)} {row['verdict']:14} {row['rule_id'][:8]} matched {row['matched']} "
              f"(expected {row['expected']})", flush=True)

    all_rules = sorted({str(index[r["rule_id"]]) for r in rows if r["rule_id"] in index})
    if not args.skip_off_target:
        (work / "all").mkdir(parents=True, exist_ok=True)
        for i, (info, row) in enumerate(zip(infos, rows), 1):
            evtx = sorted(Path(info).parent.glob("*.evtx"))
            if not evtx:
                continue
            run = run_zircolite(args.zircolite, evtx, all_rules, work / "all" / f"{row['rule_id']}.json",
                                work / "all" / f"{row['rule_id']}.log")
            print(f"  off-target {i:3}/{len(infos)} {row['rule_id'][:8]}", flush=True)
            row["off_target"] = (off_target_pairs(run["detections"], row["rule_id"])
                                 if run["detections"] is not None else None)
            row["off_target_conversion"] = run["conversion"]
            row["off_target_exit_code"] = run["exit_code"]

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(json.dumps({"environment": env, "recordings": len(rows), "all_rules": len(all_rules)}) + "\n")
        for row in rows:
            f.write(json.dumps(row) + "\n")

    verdicts = Counter(r["verdict"] for r in rows)
    evaluable = verdicts["agree"] + verdicts["disagree"]
    print(f"\n{len(rows)} recordings: {dict(verdicts)}")
    print(f"agreement on the converted ones: {verdicts['agree']} of {evaluable} (first pass)")
    for r in rows:
        if r["verdict"] != "agree":
            print(f"  {r['verdict']:14} {r['rule_id'][:8]} {r['recording']} matched {r['matched']} (expected "
                  f"{r['expected']}) {r['reason'][:100]}")
    both = [r for r in rows if r["same_count_as_matcher"] is not None]
    print(f"our matcher, same number of events: {sum(r['same_count_as_matcher'] for r in both)} of {len(both)}; "
          f"same events: {sum(bool(r['same_events_as_matcher']) for r in both)} of {len(both)}")
    for r in both:
        if not r["same_events_as_matcher"]:
            print(f"  differ {r['rule_id'][:8]} Zircolite {r['record_ids']} ours {r['matcher_record_ids']}")
    predicted = [r for r in both if r["expected"] is not None and r["matcher_count"] > r["expected"]]
    print(f"prediction (our matcher found more than match_count -> Zircolite finds the same events): "
          f"{sum(bool(r['same_events_as_matcher']) for r in predicted)} of {len(predicted)}")
    if not args.skip_off_target:
        z_pairs = {(rid, r["rule_id"]) for r in rows for rid, _ in r.get("off_target") or []}
        ours = _matcher_off_target(REPO / "eval/results/matcher_validation.jsonl")
        print(f"off-target pairs: Zircolite {len(z_pairs)}, our matcher {len(ours)}; both {len(z_pairs & ours)}, "
              f"Zircolite only {len(z_pairs - ours)}, ours only {len(ours - z_pairs)}")
        merged = [r for r in rows if (r.get("off_target_conversion") or {}).get("loaded") is not None
                  and r["off_target_conversion"]["loaded"] < (r["off_target_conversion"]["converted"] or 0)]
        print(f"all-rules runs where fewer rules loaded than converted (merged or left out): {len(merged)}")
    print(f"rows: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
