#!/usr/bin/env python3
"""Recorded-log testing, step 1: which public EVTX recordings correspond to our reports? (offline; identifiers only)

For every .evtx under the collections' folder: the collection, its top folder, the CVE IDs and ATT&CK technique IDs
in the file path, and the CVE IDs that the collection's README table associates with a name that appears in the
file name (a row whose last cell reads "Name (CVE-… / CVE-…)"). Our reports' CVEs come from their gold rule's title,
tags and references, their techniques from its `attack.t…` tags. A report matches a recording **by CVE** (a report-
level candidate: the same vulnerability recorded - whether the recording holds what the gold rule targets is checked
later by running the gold rule on it) or **by technique** (the technique or its parent - technique-level only).
The per-recording details go to the output file; the summary prints counts only.

Usage:
    .venv/bin/python eval/evtx_inventory.py data/evtx --out eval/results/evtx_inventory.json
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

_CVE = re.compile(r"CVE[-_ ]?(\d{4})[-_ ](\d{4,7})", re.I)
_TECH = re.compile(r"(?<![A-Za-z0-9])T(\d{4})(?:\.(\d{3}))?(?![0-9])")


def ids_in(text: str) -> tuple:
    cves = {f"CVE-{a}-{b}" for a, b in _CVE.findall(text or "")}
    techniques = {f"T{a}" + (f".{b}" if b else "") for a, b in _TECH.findall(text or "")}
    return cves, techniques


def readme_aliases(text: str) -> dict:
    """{name (lower case): CVE IDs} from table rows whose last cell is "Name (CVE-… / CVE-…)"."""
    aliases = {}
    for line in (text or "").splitlines():
        cells = [c.strip() for c in line.split("|") if c.strip()]
        if not cells:
            continue
        cves, _ = ids_in(cells[-1])
        name = cells[-1].split("(")[0].strip()
        if cves and len(name) >= 4 and not _CVE.match(name):
            aliases.setdefault(name.lower(), set()).update(cves)
    return aliases


def inventory(root) -> list:
    root = Path(root)
    out = []
    for collection in sorted(p for p in root.iterdir() if p.is_dir()):
        readme = next((p for p in collection.iterdir() if p.name.lower() == "readme.md"), None)
        aliases = readme_aliases(readme.read_text(encoding="utf-8", errors="replace")) if readme else {}
        for path in sorted(collection.rglob("*")):
            if path.suffix.lower() != ".evtx" or not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            cves, techniques = ids_in(rel)
            for name, ids in aliases.items():
                if name in path.name.lower():
                    cves |= ids
            parts = path.relative_to(collection).parts
            out.append({"file": rel, "collection": collection.name, "folder": parts[0] if len(parts) > 1 else "",
                        "cves": sorted(cves), "techniques": sorted(techniques)})
    return out


def match(recordings: list, reports: list) -> dict:
    """{rule_id: {"same_cve": [files], "same_technique": [files]}} - technique: the same ID or the same parent."""
    parent = lambda t: t.split(".")[0]
    out = {}
    for rep in reports:
        rep_parents = {parent(t) for t in rep["techniques"]}
        out[rep["rule_id"]] = {
            "same_cve": [r["file"] for r in recordings if set(r["cves"]) & set(rep["cves"])],
            "same_technique": [r["file"] for r in recordings if {parent(t) for t in r["techniques"]} & rep_parents],
        }
    return out


def _our_reports() -> list:
    import yaml
    from eval.run_eval import load_cases, stratified_sample
    with contextlib.redirect_stdout(io.StringIO()):
        cases = load_cases(REPO / "eval/manifest.jsonl", REPO, 2000)
        tuning = {c["rule_id"] for c in stratified_sample(cases, 60, 0)}
    reports = []
    for case in cases:
        rule = yaml.safe_load(open(REPO / case["rule_path"], encoding="utf-8")) or {}
        text = " ".join([str(rule.get("title", "")), " ".join(map(str, rule.get("tags") or [])),
                         " ".join(map(str, rule.get("references") or []))])
        cves, _ = ids_in(text.replace(".", "-"))
        techniques = {t.split(".", 1)[1].upper() for t in rule.get("tags") or []
                      if re.match(r"attack\.t\d{4}", str(t), re.I)}
        reports.append({"rule_id": case["rule_id"], "tuning": case["rule_id"] in tuning, "cves": cves,
                        "techniques": techniques})
    return reports


def main(argv: list) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("root")
    p.add_argument("--out", required=True)
    args = p.parse_args(argv[1:])
    recordings = inventory(args.root)
    reports = _our_reports()
    matched = match(recordings, reports)
    Path(args.out).write_text(json.dumps({"recordings": recordings, "matches": matched}, indent=1), encoding="utf-8")
    for col in sorted({r["collection"] for r in recordings}):
        rs = [r for r in recordings if r["collection"] == col]
        print(f"{col}: {len(rs)} recordings; with a CVE {sum(1 for r in rs if r['cves'])}; with a technique ID "
              f"{sum(1 for r in rs if r['techniques'])}")
    by_cve = [r for r in reports if matched[r["rule_id"]]["same_cve"]]
    by_tech = [r for r in reports if matched[r["rule_id"]]["same_technique"]]
    print(f"our reports: {len(reports)} ({sum(r['tuning'] for r in reports)} in the tuning set); with a CVE "
          f"{sum(1 for r in reports if r['cves'])}; with a technique tag {sum(1 for r in reports if r['techniques'])}")
    print(f"  matched by CVE (report-level candidates): {len(by_cve)} ({sum(r['tuning'] for r in by_cve)} tuning); "
          f"distinct CVEs {len({c for r in by_cve for c in r['cves'] if any(c in rec['cves'] for rec in recordings)})}")
    print(f"  matched by technique (technique level):   {len(by_tech)} ({sum(r['tuning'] for r in by_tech)} tuning)")
    print(f"details: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
