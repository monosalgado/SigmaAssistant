#!/usr/bin/env python3
"""Freeze the corpus (log 2026-11-10, Change 61 point 4): every case of the manifests that `load_cases` judges by the
2,000-character threshold, and which of them pass it with this checkout's page reader. Written to
eval/corpus_frozen.json; `load_cases` then keeps these verdicts whatever the reader becomes.

Usage:
    .venv/bin/python eval/freeze_corpus.py            # writes eval/corpus_frozen.json
"""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.run_eval import FROZEN_CORPUS, load_cases  # noqa: E402

MIN_CHARS = 2000


def main() -> int:
    considered, selected = set(), set()
    with contextlib.redirect_stdout(io.StringIO()):
        for manifest in sorted((REPO / "eval").glob("manifest*.jsonl")):
            for case in load_cases(manifest, REPO, 0, frozen=None):
                considered.add(case["rule_id"])
                if case["text_chars"] >= MIN_CHARS:
                    selected.add(case["rule_id"])
    revision = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"], capture_output=True,
                              text=True).stdout.strip()
    FROZEN_CORPUS.write_text(json.dumps({"min_chars": MIN_CHARS, "made": date.today().isoformat(),
                                         "reader_revision": revision, "considered": sorted(considered),
                                         "selected": sorted(selected)}, indent=1) + "\n", encoding="utf-8")
    print(f"{FROZEN_CORPUS.name}: {len(considered)} cases judged, {len(selected)} pass {MIN_CHARS} characters "
          f"(reader of {revision})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
