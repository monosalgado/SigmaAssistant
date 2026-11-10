#!/usr/bin/env python3
"""Does the PoC step read the code a report links to? (Change 57's offline measure, plan in the log 2026-11-10.)

The PoC step analyses at most five pieces of code. Linked GitHub files and gists are the only code no other step
reads. For each case this runs the page reader and the PoC step of a checkout on the saved pages and the saved
GitHub files, with a client that only records the prompt, and reads from the prompt's headings where its snippets
come from. No model, no network.

Usage:
    .venv/bin/python eval/poc_snippets.py --cases eval/results/RUN.jsonl --scope windows-linux [--code CHECKOUT]
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
_SNIPPET_RE = re.compile(r"^### Snippet \d+ \([^,]*, from (\w+)", re.MULTILINE)


def snippet_sources(prompt) -> list:
    """Where each snippet of a PoC prompt comes from ("inline", "github"), in the prompt's order."""
    return _SNIPPET_RE.findall(prompt or "")


def has_linked_code(targets: list, saved: dict) -> bool:
    """Is a file the text links to saved with a body (status 200)?"""
    return any((saved.get(t["fetch_url"]) or {}).get("status") == 200 and (saved.get(t["fetch_url"]) or {}).get("path")
               for t in targets)


def summary(cases: list) -> dict:
    linked = [c for c in cases if c["linked"]]
    return {"cases": len(cases), "with_code": sum(1 for c in cases if c["sources"]),
            "with_linked_code": len(linked), "linked_code_read": sum(1 for c in linked if "github" in c["sources"])}


class _Capture:
    """A client that records the prompt and answers that the code shows nothing."""
    model_name = "capture"

    def __init__(self):
        self.prompt = None

    def generate(self, prompt, **kwargs):
        self.prompt = prompt
        return json.dumps({"behavioral_indicators": [], "attack_flow": ""})


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cases", required=True, type=Path, help="a results file naming the cases")
    parser.add_argument("--scope", default=None)
    parser.add_argument("--code", type=Path, default=None, help="the checkout whose pipeline code to use (default: this one)")
    args = parser.parse_args(argv)

    sys.path.insert(0, str((args.code or REPO).resolve()))        # the pipeline code read; the saved data stay REPO's
    from backend.pipeline.stage_poc_analysis import PoCAnalysisStage, github_fetch_targets
    from backend.pipeline.stage_preprocess import PreprocessStage
    from eval.run_eval import load_cases, poc_snapshots_instead_of_network, snapshots_instead_of_network
    from eval.scope import in_scope

    rows = [json.loads(line) for line in args.cases.read_text(encoding="utf-8").splitlines() if line.strip()]
    wanted = [r["rule_id"] for r in rows if not args.scope or in_scope(r, args.scope)]
    saved = {}
    for line in (REPO / "eval" / "github_manifest.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            entry = json.loads(line)
            if entry.get("path") and not Path(entry["path"]).is_absolute():
                entry["path"] = str(REPO / entry["path"])
            saved[entry["fetch_url"]] = entry
    results = []
    with contextlib.redirect_stdout(io.StringIO()):
        by_id = {c["rule_id"]: c for c in load_cases(REPO / "eval" / "manifest.jsonl", REPO, 2000)}
        for rule_id in wanted:
            case = by_id.get(rule_id)
            if case is None:
                continue
            with snapshots_instead_of_network(case["url_to_path"]):
                context = PreprocessStage(None, "").run({"original_query": " ".join(case["urls"]), "history": [],
                                                         "media_file": None})
            text = context["preprocessed"]["combined_text"]
            files, gists = github_fetch_targets(text)
            client = _Capture()
            with poc_snapshots_instead_of_network(saved):
                PoCAnalysisStage(client, "capture").run(context)
            results.append({"rule_id": rule_id, "title": case["title"], "linked": has_linked_code(files + gists, saved),
                            "sources": snippet_sources(client.prompt)})
    s = summary(results)
    print(f"code: {args.code or REPO}")
    print(f"cases {s['cases']}; with code for the PoC step {s['with_code']}; with linked GitHub code saved "
          f"{s['with_linked_code']}; of those, the PoC step's prompt holds it: {s['linked_code_read']}")
    for c in results:
        if c["linked"]:
            print(f"  {'read  ' if 'github' in c['sources'] else 'UNREAD'}  {c['title'][:60]}  {c['sources']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
