#!/usr/bin/env python3
"""Write the committed contamination flag list, eval/contamination.jsonl (plan 1.3b).

One line per evaluation case — clean or flagged — with every reason and its
detail, so each flag can be checked by hand. Deterministic: computed from the page
snapshots and the PoC stage's own fetch targets, no network and no LLM. See
eval/contamination.py for the definition.

Usage:
    .venv/bin/python eval/flag_contamination.py
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from backend.pipeline.stage_poc_analysis import github_fetch_targets  # noqa: E402
from backend.pipeline.stage_preprocess import PreprocessStage  # noqa: E402
from eval.contamination import contamination_reasons  # noqa: E402
from eval.run_eval import load_cases, snapshots_instead_of_network  # noqa: E402


def main() -> int:
    out = REPO / "eval/contamination.jsonl"
    entries = []
    for case in load_cases(REPO / "eval/manifest.jsonl", REPO, 2000):
        with snapshots_instead_of_network(case["url_to_path"]), \
                contextlib.redirect_stdout(io.StringIO()):
            ctx = PreprocessStage(None, "").run(
                {"original_query": " ".join(case["urls"]), "history": [], "media_file": None})
        text = ctx["preprocessed"]["combined_text"]
        files, _ = github_fetch_targets(text)
        reasons = contamination_reasons(case["urls"], text, files)
        entries.append({"rule_id": case["rule_id"], "title": case["title"],
                        "flagged": bool(reasons), "reasons": reasons})

    out.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")
    by_reason = Counter(r["reason"] for e in entries for r in {x["reason"]: x for x in e["reasons"]}.values())
    print(f"{sum(e['flagged'] for e in entries)} of {len(entries)} cases flagged; "
          f"cases per reason: {dict(by_reason)}")
    print(f"written: {out.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
