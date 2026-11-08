#!/usr/bin/env python3
"""Diagnosis D1 (rule generation; plan in the log 2026-11-08) - each saved web-app run's stage outputs side by side,
in pipeline order, with the words for the attack's host behaviour marked: where does it get lost?

Stages: the input (saved only by the newer runs), the PoC step, the web step's kept findings, the attack-vector step's
fields, the analysis step (summary, indicators, techniques, log-source suggestions), the example rules retrieved for
the rule writer, the rules before review, and the final rules. Marked words, fixed with the plan: the parent (`java`,
`activemq`, `ProcessBuilder`, `Runtime.exec`, spawn, child or parent process, `ParentImage`), the child (`cmd`,
PowerShell, `pwsh`, `bash`, `/bin/sh`, shell, `jjs`, `whoami`, `hostname`) and the log (`process_creation`, process
creation, `Image`, `CommandLine`, event 4688). The marks help the reading; they are not a measure.

The trace holds the runs' own text (the user's saved sessions, local): it is written to a local folder.

Usage:
    .venv/bin/python eval/trace_stages.py --sessions data/sessions.json --run <id prefix> "<label>" [--run ...]
        --out <trace.md>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PATTERNS = {
    "parent": [r"\bjava(?:\.exe)?\b", r"\bactivemq\b", r"processbuilder", r"runtime\.(?:getruntime|exec)",
               r"\bspawn\w*", r"child process", r"parent process", r"\bparentimage\b", r"\bparentcommandline\b"],
    "child": [r"\bcmd(?:\.exe)?\b", r"\bpowershell(?:\.exe)?\b", r"\bpwsh\b", r"\bbash\b", r"/bin/sh\b", r"\bshell\b",
              r"\bjjs\b", r"\bwhoami\b", r"\bhostname\b"],
    "log": [r"\bprocess_creation\b", r"process creation", r"\bimage\b", r"\bcommandline\b", r"\b4688\b"],
}
_COMPILED = {group: [re.compile(p, re.I) for p in pats] for group, pats in PATTERNS.items()}
STAGES = ("input", "poc", "web", "attack_vector", "analysis", "examples", "rules_before_review", "rules")
_YAML = re.compile(r"```ya?ml\s*\n(.*?)```", re.S)


def marks(text: str) -> dict:
    """{group: the sorted distinct words found}, lower-cased."""
    text = text or ""
    return {group: sorted({m.group(0).lower() for pat in pats for m in pat.finditer(text)})
            for group, pats in _COMPILED.items()}


def final_message(session: list) -> dict:
    return [m for m in session if m.get("role") == "assistant" and m.get("pipeline_metadata")][-1]


def _state(session: list):
    states = [m["state"] for m in session if isinstance(m.get("state"), dict)]
    return states[-1] if states else None


def _lines(items) -> str:
    out = []
    for item in items or []:
        out.append("; ".join(f"{k}={v}" for k, v in item.items()) if isinstance(item, dict) else str(item))
    return "\n".join(out)


def stages(session: list) -> list:
    """[(stage, its text)] in pipeline order; the input is None when the run did not save it."""
    final, state = final_message(session), _state(session)
    meta = final.get("pipeline_metadata") or {}
    web = (meta.get("web_enrichment") or {}).get("additional_context") or ""
    vector = "\n".join(f"{k}: {json.dumps(v) if isinstance(v, (list, dict)) else v}"
                       for k, v in (meta.get("attack_vector") or {}).items())
    analysis = "\n".join(["attack_summary: " + str(meta.get("attack_summary") or ""),
                          "indicators:\n" + _lines(meta.get("indicators")),
                          "ttp_mappings:\n" + _lines(meta.get("ttp_mappings")),
                          "logsource_suggestions:\n" + _lines(meta.get("logsource_suggestions")),
                          "logsource_primary: " + str(meta.get("logsource_primary") or "")])
    text_in = (((state or {}).get("preprocessed") or {}).get("combined_text")) if state else None
    return [("input", text_in),
            ("poc", "\n".join([str(meta.get("poc_attack_flow") or ""), _lines(meta.get("poc_behavioral_indicators"))])),
            ("web", web), ("attack_vector", vector), ("analysis", analysis),
            ("examples", "\n---\n".join((final.get("context") or {}).get("sigma") or [])),
            ("rules_before_review", "\n---\n".join(meta.get("pre_review_rules") or [])),
            ("rules", "\n---\n".join(_YAML.findall(final.get("content") or "")))]


def input_lines(text: str, cap: int = 40) -> tuple:
    """The input's lines holding a parent or child mark (at most `cap`), and how many there are."""
    found = [line.strip() for line in (text or "").splitlines()
             if line.strip() and (marks(line)["parent"] or marks(line)["child"])]
    return found[:cap], len(found)


def summary_row(session: list) -> dict:
    return {name: (marks(text) if text is not None else None) for name, text in stages(session)}


def _cell(found) -> str:
    if found is None:
        return "not saved"
    return " / ".join(", ".join(found[g]) or "-" for g in ("parent", "child", "log"))


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sessions", type=Path, default=Path("data/sessions.json"))
    parser.add_argument("--run", nargs=2, action="append", required=True, metavar=("ID_PREFIX", "LABEL"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    data = json.loads(args.sessions.read_text(encoding="utf-8"))
    runs = []
    for prefix, label in args.run:
        ids = [k for k in data if k.startswith(prefix)]
        if len(ids) != 1:
            print(f"{prefix}: {len(ids)} sessions match")
            return 1
        runs.append((ids[0][:8], label, data[ids[0]]))

    out = ["# Diagnosis D1 trace (local; plan in the log 2026-11-08)", "",
           "Cells: marked words found, as parent / child / log (`-` none).", "",
           "| run | " + " | ".join(STAGES) + " |", "|---|" + "---|" * len(STAGES)]
    for rid, label, session in runs:
        row = summary_row(session)
        out.append(f"| {rid} {label} | " + " | ".join(_cell(row[s]) for s in STAGES) + " |")
    for rid, label, session in runs:
        out += ["", f"## {rid} - {label}"]
        for name, text in stages(session):
            out += ["", f"### {name}"]
            if text is None:
                out.append("(not saved by this run)")
                continue
            if name == "input":
                lines, total = input_lines(text)
                out.append(f"{len(text):,} characters; {total} lines with a parent or child mark"
                           + (f" (first {len(lines)} shown)" if total > len(lines) else "") + ":")
                out += [f"- {line[:400]}" for line in lines]
            else:
                out += ["```", text.strip() or "(empty)", "```"]
            out.append(f"marks: {_cell(marks(text))}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(out) + "\n", encoding="utf-8")
    for line in out[:6 + len(runs)]:
        print(line)
    print(f"\ntrace: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
