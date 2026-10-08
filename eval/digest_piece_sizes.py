#!/usr/bin/env python3
"""How big would each web-digest request be? (Change 49; offline - no request is sent)

Runs the web stage's digest over every saved search in a snapshot file with a stand-in client that records the
prompts and answers nothing, and counts each prompt with Qwen's tokenizer (`backend.token_count`). The report is the
longest text in the evaluation corpus (the worst case: its opening fills the 6,000 tokens the digest shows); no page
is the case's own, so every result is read (the worst case again); rule pages are dropped, as in the evaluation.

Usage:
    .venv/bin/python eval/digest_piece_sizes.py eval/web_snapshots/tuning60.jsonl
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))


class _Recorder:
    model_name = "none"

    def __init__(self, results):
        self.results, self.prompts = results, []

    def web_search(self, query):
        return {"text": "", "sources": [], "results": self.results, "error": None, "limited": False}

    def generate(self, prompt, **kwargs):
        self.prompts.append(prompt)
        return '{"items": []}'


def main(argv: list) -> int:
    from backend.pipeline.stage_web_enrich import WEB_PIECE_MAX_TOKENS, WebEnrichStage
    from backend.token_count import TOKENIZER_PATH, count_tokens
    from eval.diagnose_detection import _case_text
    from eval.run_eval import load_cases, load_github_manifest
    if len(argv) < 2:
        print(__doc__)
        return 1
    if not TOKENIZER_PATH.exists():
        print(f"No tokenizer at {TOKENIZER_PATH}: the counts would be estimates. Stopping.")
        return 1
    with contextlib.redirect_stdout(io.StringIO()):
        cases = load_cases(REPO / "eval/manifest.jsonl", REPO, 2000)
    url_map = load_github_manifest(REPO / "eval/github_manifest.jsonl")
    report = max((_case_text(c, url_map) for c in cases), key=len)
    records = [json.loads(line) for line in open(argv[1], encoding="utf-8") if line.strip()]
    sizes, pieces_per_search = [], []
    for rec in records:
        client = _Recorder(rec.get("results") or [])
        stage = WebEnrichStage(client, "")
        stage.exclude_rule_pages = True
        query = "a report on an attack (any text: the stand-in client ignores the query)"
        context = {"original_query": query, "preprocessed": {"original_query": query, "combined_text": report,
                                                             "segments": [], "url_content": []}}
        with contextlib.redirect_stdout(io.StringIO()):
            stage.run(context)
        tokens = [count_tokens(p) for p in client.prompts]
        sizes.extend(tokens)
        pieces_per_search.append(len(tokens))
    with_pages = [n for n in pieces_per_search if n]
    print(f"{len(records)} saved searches ({len(with_pages)} with a page to read); report: the corpus's longest text "
          f"({len(report)} characters, {count_tokens(report)} tokens)")
    print(f"digest requests: {len(sizes)}; pieces per search: max {max(pieces_per_search)}, "
          f"mean {sum(with_pages) / max(len(with_pages), 1):.1f}")
    print(f"prompt tokens: max {max(sizes)}, median {sorted(sizes)[len(sizes) // 2]}; over {WEB_PIECE_MAX_TOKENS}: "
          f"{sum(t > WEB_PIECE_MAX_TOKENS for t in sizes)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
