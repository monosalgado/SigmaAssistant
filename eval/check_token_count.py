#!/usr/bin/env python3
"""Change 49's live check: does the laptop count a request the way the Spark does? (needs the tunnel)

The ceiling (`llm_client.request_token_count`) counts a request with Qwen's tokenizer plus a 64-token allowance for
the chat template. This sends 5 small requests through the pipeline's own client, ONE AT A TIME, each asking for a
two-token answer, and compares our count (without the allowance) with Ollama's `prompt_tokens`. It passes when
Ollama never counts more than ours plus the allowance - then the ceiling never lets through more than it says.
Texts: a plain sentence, a slice of a report from the corpus, and a slice of a dense saved web page (the kind with the
fewest characters per token), with and without the JSON system message. Each request is at most ~3,000 tokens.

Usage:
    .venv/bin/python eval/check_token_count.py
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

SLICE_CHARS = 6000
ASK = '\n\nReply with exactly {"ok": true} and nothing else.'


def verdict(rows: list, allowance: int) -> tuple:
    """(passed, names over): a request fails when Ollama counted more than ours + allowance, or gave no count."""
    over = [r["name"] for r in rows if r["ollama"] is None or r["ollama"] - r["ours"] > allowance]
    return not over, over


def _texts() -> list:
    from eval.diagnose_detection import _case_text
    from eval.run_eval import load_cases, load_github_manifest, stratified_sample
    with contextlib.redirect_stdout(io.StringIO()):
        cases = stratified_sample(load_cases(REPO / "eval/manifest.jsonl", REPO, 2000), 60, 0)
    report = _case_text(cases[0], load_github_manifest(REPO / "eval/github_manifest.jsonl"))[:SLICE_CHARS]
    pages = [r for line in open(REPO / "eval/web_snapshots/tuning60.jsonl", encoding="utf-8") if line.strip()
             for r in json.loads(line).get("results") or []]
    dense = min((p for p in pages if len(p.get("content") or "") >= SLICE_CHARS),
                key=lambda p: len((p["content"][:SLICE_CHARS]).split()))["content"][:SLICE_CHARS]
    return [("short sentence", "The loader runs rundll32.exe to load a DLL.", True),
            ("report slice", report, True),
            ("dense web page slice", dense, True),
            ("report slice, no system message", report, False),
            ("dense page, no system message", dense, False)]


def main() -> int:
    from backend.llm_client import TEMPLATE_ALLOWANCE_TOKENS, create_llm_client, request_token_count
    from backend.telemetry import TELEMETRY
    client = create_llm_client()
    rows = []
    for name, text, json_mode in _texts():
        prompt = text + ASK
        ours = request_token_count(prompt, json_mode) - TEMPLATE_ALLOWANCE_TOKENS
        TELEMETRY.reset()
        client.generate(prompt, json_mode=json_mode)            # one request, waited for before the next
        call = TELEMETRY.as_dicts()[-1]
        rows.append({"name": name, "ours": ours, "ollama": call.get("prompt_tokens"),
                     "answer_tokens": call.get("completion_tokens")})
        r = rows[-1]
        diff = None if r["ollama"] is None else r["ollama"] - ours
        print(f"  {name:32} ours {ours:6}   Ollama {r['ollama']}   Ollama - ours {diff}   answer {r['answer_tokens']}")
    ok, over = verdict(rows, TEMPLATE_ALLOWANCE_TOKENS)
    print(f"\n{'PASS' if ok else 'FAIL'}: Ollama counted at most ours + {TEMPLATE_ALLOWANCE_TOKENS} on "
          f"{len(rows) - len(over)} of {len(rows)} requests" + (f"; over: {over}" if over else ""))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
