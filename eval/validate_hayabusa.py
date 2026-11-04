#!/usr/bin/env python3
"""R12.2 - validate Hayabusa on SigmaHQ's recordings with known answers (plan fixed in the log 2026-11-03, "Plan R12",
before this tool was written; settings pinned in "R12.1 done").

Hayabusa does not translate a Sigma rule's abstract `logsource` itself, so every rule is first converted by Yamato
Security's `sigma-to-hayabusa-converter` (installed outside this repository, its own environment); the converter's
Sysmon copy of a rule names its channel and event ID, and its `related: derived` entry points back to the original rule.
The converter only collects files under a folder path containing "rule" and reads `ignore-uuid-list.txt` from its
working folder, so it runs from its own folder on a folder named `rules-in`.

Each recording (`data/sigma/regression_data/**/info.yml`, one Sysmon EVTX each) is then run through Hayabusa **with
its rule's Sysmon copy only** and the pinned settings (`SETTINGS`). **agree** = the number of matching events equals
`match_count` (at least 1 when absent); **disagree** = the rule loaded, any other number, 0 included. Listed apart with
the reason, never as "did not fire": **not converted** (no Sysmon copy), **not loaded** (Hayabusa did not load the
rule: its own `exclude_rules.txt` / `noisy_rules.txt`, or the channel filter - found while building this tool: one of
the 138 converted rules is on Hayabusa's exclude list), **tool error**, **rule not found**, **no EVTX**,
**several EVTX**.
Cross-check: the same events (Windows event record number) as Zircolite on the same recording (R11.3,
`zircolite_validation.jsonl`). **Pass** (the plan): the same events as Zircolite on every recording where both
produced output, and no fewer agreements than Zircolite on the recordings Hayabusa evaluated.

Usage:
    .venv/bin/python eval/validate_hayabusa.py [--hayabusa ../Hayabusa] [--converter ../sigma-to-hayabusa-converter]
                                              [--out eval/results/hayabusa_validation.jsonl]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.validate_matcher import rule_index  # noqa: E402
from eval.validate_zircolite import _git, _info as recording_info, verdict  # noqa: E402

SIGMA = REPO / "data/sigma"
HAYABUSA_DIR = REPO.parent / "Hayabusa"
HAYABUSA_BINARY = "hayabusa-4.3.1-mac-aarch64"
CONVERTER_DIR = REPO.parent / "sigma-to-hayabusa-converter"
# Pinned in R12.1: no wizard; rule title, rule ID and record number in the output; JSON lines; overwrite; UTC.
# `-K` (no colour) changes the screen only. No `-A`/`-D`/`-u`/`-n`: a rule Hayabusa leaves out is reported, not forced.
SETTINGS = ("-w", "-p", "verbose", "-t", "jsonl", "-C", "-U", "-K")
RUN_TIMEOUT_S = 900

_COLOUR = re.compile(r"\x1b\[[0-9;]*m")
_NUMBERS = {"total_rules": re.compile(r"Total detection rules:\s*([\d,]+)"),
            "enabled_after_channel_filter": re.compile(r"Detection rules enabled after channel filter:\s*([\d,]+)"),
            "excluded": re.compile(r"Excluded rules:\s*([\d,]+)"),
            "noisy": re.compile(r"Noisy rules:\s*([\d,]+)")}


def command(hdir, binary: str, evtx, rule, outfile) -> list:
    return [str(Path(hdir) / binary), "dfir-timeline", "-f", str(evtx), "-r", str(rule), *SETTINGS,
            "-o", str(outfile)]


def parse_load(text: str) -> dict:
    """Hayabusa's own report of the rules it loaded; a number it did not print is unknown (None), except the
    excluded and noisy counts, which it prints only when they are not 0."""
    plain = _COLOUR.sub("", text or "")
    out = {"total_rules": None, "enabled_after_channel_filter": None, "excluded": 0, "noisy": 0,
           "no_rules_loaded": "No rules were loaded" in plain}
    for key, pattern in _NUMBERS.items():
        m = pattern.search(plain)
        if m:
            out[key] = int(m.group(1).replace(",", ""))
    return out


def read_detections(path) -> dict:
    """{converted rule id: {"count", "record_ids"}} from Hayabusa's JSON-lines file; None when there is no file."""
    path = Path(path)
    if not path.exists():
        return None
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        det = json.loads(line)
        entry = out.setdefault(str(det.get("RuleID")), {"count": 0, "record_ids": []})
        entry["count"] += 1
        if det.get("RecordID") not in (None, ""):
            entry["record_ids"].append(int(det["RecordID"]))
    for entry in out.values():
        entry["record_ids"].sort()
    return out


def converted_index(out_dir) -> dict:
    """{original rule id: {"path", "converted_id"}} for the converter's Sysmon copies."""
    index = {}
    for path in sorted((Path(out_dir) / "sysmon").rglob("*.yml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        originals = [str(r.get("id")) for r in rule.get("related") or [] if r.get("type") == "derived"]
        for original in originals or [path.stem]:
            index[original] = {"path": str(path), "converted_id": str(rule.get("id"))}
    return index


def convert_rules(converter_dir, rule_paths: list, workdir, runner=subprocess.run) -> tuple:
    """Convert each rule on its own (`<workdir>/rules-in/NNN` -> `<workdir>/converted/NNN`) and return (converted
    index, the converter's output). One rule per run because a SigmaHQ rule's own `related: derived` entries survive
    conversion: converted together, rule B's copy also names rule A, and A could be mapped to B's copy (first R12.2
    run, 2026-11-03)."""
    workdir = Path(workdir)
    for folder in (workdir / "rules-in", workdir / "converted"):
        if folder.exists():
            shutil.rmtree(folder)
    index, report = {}, []
    for i, rule in enumerate(rule_paths):
        source, target = workdir / "rules-in" / f"{i:03d}", workdir / "converted" / f"{i:03d}"
        source.mkdir(parents=True)
        shutil.copy(rule, source / Path(rule).name)
        original = str((yaml.safe_load(Path(rule).read_text(encoding="utf-8")) or {}).get("id"))
        done = runner([str(Path(converter_dir) / ".venv/bin/python"), "sigma-to-hayabusa-converter.py",
                       "-r", str(source), "-o", str(target)], cwd=str(converter_dir), capture_output=True, text=True,
                      timeout=RUN_TIMEOUT_S)
        report.append((done.stdout or "") + (done.stderr or ""))
        own = converted_index(target).get(original)
        if own:
            index[original] = own
    return index, "".join(report)


def _not_loaded_reason(load: dict) -> str:
    if load["excluded"]:
        return "excluded by Hayabusa's own config (rules/config/exclude_rules.txt)"
    if load["noisy"]:
        return "set as noisy by Hayabusa's own config (rules/config/noisy_rules.txt)"
    if load["total_rules"] and load["enabled_after_channel_filter"] == 0:
        return "dropped by the channel filter"
    return "no rules loaded"


def check_recording(info_path, converted: dict, hdir, binary: str, workdir, zircolite: dict,
                    runner=subprocess.run) -> dict:
    info_path = Path(info_path)
    rule_id, expected = recording_info(info_path)
    z = zircolite.get(rule_id) or {}
    row = {"rule_id": rule_id,
           "recording": str(info_path.parent.relative_to(info_path.parents[2]) if len(info_path.parents) > 2
                            else info_path.parent),
           "expected": expected, "converted_id": None, "matched": None, "record_ids": None, "verdict": None,
           "reason": "", "exit_code": None, "load": None, "zircolite_verdict": z.get("verdict"),
           "zircolite_matched": z.get("matched"), "zircolite_record_ids": z.get("record_ids"),
           "same_events_as_zircolite": None}
    if rule_id not in converted:
        row["verdict"] = "not converted"
        return row
    row["converted_id"] = converted[rule_id]["converted_id"]
    evtx = sorted(info_path.parent.glob("*.evtx"))
    if len(evtx) != 1:
        row["verdict"] = "no EVTX" if not evtx else "several EVTX"
        return row
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    outfile = workdir / f"{rule_id}.jsonl"
    if outfile.exists():
        outfile.unlink()
    try:
        done = runner(command(hdir, binary, evtx[0], converted[rule_id]["path"], outfile), cwd=str(hdir),
                      capture_output=True, text=True, timeout=RUN_TIMEOUT_S)
        exit_code, printed = done.returncode, (done.stdout or "") + (done.stderr or "")
    except subprocess.TimeoutExpired:
        exit_code, printed = None, f"timed out after {RUN_TIMEOUT_S} s"
    load = parse_load(printed)
    row.update(exit_code=exit_code, load=load)
    if load["total_rules"] == 0 or load["enabled_after_channel_filter"] == 0 or load["no_rules_loaded"]:
        row.update(verdict="not loaded", reason=_not_loaded_reason(load))
        return row
    detections = read_detections(outfile)
    if exit_code != 0 or detections is None:
        row.update(verdict="tool error", reason=_COLOUR.sub("", printed)[-300:])
        return row
    det = detections.get(row["converted_id"]) or {"count": 0, "record_ids": []}
    row.update(matched=det["count"], record_ids=det["record_ids"], verdict=verdict(expected, det["count"]))
    if z.get("record_ids") is not None:
        row["same_events_as_zircolite"] = det["record_ids"] == sorted(z["record_ids"])
    return row


def summarise(rows: list) -> dict:
    """The plan's pass rule: the same events as Zircolite wherever both produced output, and no fewer agreements than
    Zircolite on the recordings Hayabusa evaluated (agree + disagree)."""
    compared = [r for r in rows if r["same_events_as_zircolite"] is not None]
    evaluated = [r for r in rows if r["verdict"] in ("agree", "disagree")]
    out = {"verdicts": dict(Counter(r["verdict"] for r in rows)), "recordings": len(rows),
           "compared": len(compared), "same_events": sum(bool(r["same_events_as_zircolite"]) for r in compared),
           "evaluated": len(evaluated), "hayabusa_agree": sum(r["verdict"] == "agree" for r in evaluated),
           "zircolite_agree_on_evaluated": sum(r.get("zircolite_verdict") == "agree" for r in evaluated),
           "zircolite_agree_all": sum(r.get("zircolite_verdict") == "agree" for r in rows)}
    out["passed"] = (out["same_events"] == out["compared"]
                     and out["hayabusa_agree"] >= out["zircolite_agree_on_evaluated"])
    return out


def environment(hdir, binary: str, converter_dir, sigma_dir, runner=subprocess.run) -> dict:
    hdir, converter_dir = Path(hdir), Path(converter_dir)
    try:
        done = runner([str(hdir / binary), "help"], cwd=str(hdir), capture_output=True, text=True, timeout=120)
        m = re.search(r"v\d+\.\d+\.\d+", _COLOUR.sub("", (done.stdout or "") + (done.stderr or "")))
        version = m.group(0) if m else None
    except (OSError, subprocess.TimeoutExpired):
        version = None
    try:
        done = runner([str(converter_dir / ".venv/bin/python"), "-c",
                       "import ruamel.yaml; print(ruamel.yaml.__version__)"], capture_output=True, text=True,
                      timeout=120)
        ruamel = (done.stdout or "").strip() or None
    except (OSError, subprocess.TimeoutExpired):
        ruamel = None
    binary_path = hdir / binary
    return {"hayabusa_version": version, "hayabusa_binary": binary,
            "hayabusa_sha256": hashlib.sha256(binary_path.read_bytes()).hexdigest() if binary_path.exists() else None,
            "hayabusa_rules_commit": _git(hdir / "rules", "rev-parse", "--short", "HEAD"),
            "converter_commit": _git(converter_dir, "rev-parse", "--short", "HEAD"), "ruamel_yaml": ruamel,
            "settings": list(SETTINGS), "sigma_commit": _git(sigma_dir, "rev-parse", "--short", "HEAD")}


def converter_errors(report: str, work) -> list:
    """The converter's ERROR lines, with the local work folder replaced by `<work>` (no local paths in results)."""
    return [line.replace(str(work), "<work>") for line in report.splitlines() if "ERROR" in line][:50]


def _zircolite_rows(path: Path) -> dict:
    rows = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line) if line.strip() else {}
            if "rule_id" in row:
                rows[row["rule_id"]] = row
    return rows


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hayabusa", type=Path, default=HAYABUSA_DIR)
    parser.add_argument("--binary", default=HAYABUSA_BINARY)
    parser.add_argument("--converter", type=Path, default=CONVERTER_DIR)
    parser.add_argument("--out", type=Path, default=REPO / "eval/results/hayabusa_validation.jsonl")
    parser.add_argument("--work", type=Path, default=None, help="converted rules and Hayabusa's files (default: temp)")
    parser.add_argument("--limit", type=int, default=0, help="first N recordings only (a check, not the result)")
    args = parser.parse_args(argv)
    work = args.work or Path(tempfile.mkdtemp(prefix="hayabusa_validation_"))
    index = rule_index([d for d in SIGMA.iterdir() if d.is_dir() and (d.name.startswith("rules") or d.name == "deprecated")])
    infos = sorted((SIGMA / "regression_data").rglob("info.yml"))
    if args.limit:
        infos = infos[:args.limit]
    env = environment(args.hayabusa, args.binary, args.converter, SIGMA)
    print(f"Hayabusa {env['hayabusa_version']} (rules {env['hayabusa_rules_commit']}); converter "
          f"{env['converter_commit']}, ruamel.yaml {env['ruamel_yaml']}; SigmaHQ @ {env['sigma_commit']}; "
          f"{len(infos)} recordings; work folder {work}")

    wanted = [recording_info(info)[0] for info in infos]
    converted, report = convert_rules(args.converter, sorted({str(index[r]) for r in wanted if r in index}), work)
    print(f"converter: a Sysmon copy for {len(converted)} of {len({r for r in wanted if r in index})} rules (each converted on its own)")
    zircolite = _zircolite_rows(REPO / "eval/results/zircolite_validation.jsonl")

    rows = []
    for i, info in enumerate(infos, 1):
        rule_id = recording_info(info)[0]
        if rule_id not in index:
            row = {"rule_id": rule_id, "recording": str(Path(info).parent.relative_to(SIGMA)), "verdict": "rule not found",
                   "matched": None, "record_ids": None, "expected": None, "reason": "",
                   "zircolite_verdict": (zircolite.get(rule_id) or {}).get("verdict"),
                   "same_events_as_zircolite": None}
        else:
            row = check_recording(info, converted, args.hayabusa, args.binary, work / "runs", zircolite)
        rows.append(row)
        print(f"  {i:3}/{len(infos)} {row['verdict']:13} {row['rule_id'][:8]} matched {row['matched']} "
              f"(expected {row['expected']})", flush=True)

    summary = summarise(rows)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(json.dumps({"environment": env, "recordings": len(rows), "summary": summary,
                            "converter_errors": converter_errors(report, work)}) + "\n")
        for row in rows:
            f.write(json.dumps(row) + "\n")

    print(f"\n{len(rows)} recordings: {summary['verdicts']}")
    print(f"agreement with SigmaHQ's counts: Hayabusa {summary['hayabusa_agree']} of {summary['evaluated']} evaluated; "
          f"Zircolite {summary['zircolite_agree_on_evaluated']} on the same recordings "
          f"({summary['zircolite_agree_all']} of {len(rows)} overall)")
    print(f"same events as Zircolite: {summary['same_events']} of {summary['compared']} recordings with output from both")
    for r in rows:
        if r["verdict"] != "agree":
            print(f"  {r['verdict']:13} {r['rule_id'][:8]} {r['recording']} matched {r['matched']} (expected "
                  f"{r['expected']}; Zircolite {r.get('zircolite_verdict')}) {r.get('reason', '')[:100]}")
    for r in rows:
        if r["same_events_as_zircolite"] is False:
            print(f"  events differ {r['rule_id'][:8]} Hayabusa {r['record_ids']} Zircolite {r['zircolite_record_ids']}")
    print(f"PASS RULE: {'PASSED' if summary['passed'] else 'NOT PASSED'}")
    print(f"rows: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
