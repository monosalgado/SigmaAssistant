#!/usr/bin/env python3
"""qwen3.6 settings probe, part 1 (plan: log 2026-10-16, fixed before any request; needs the tunnel)

Two questions before the pipeline runs on a thinking model:
1. Does it "think" through the OpenAI-compatible endpoint by default, how does the answer show it, and which request
   field turns it off? T1 nothing extra, T2 `"think": false`, T3 `"reasoning_effort": "none"` - a tiny prompt each.
2. Does a `presence_penalty` sent with the request override the Modelfile's (1.5 for qwen3.6)? A prompt whose JSON
   repeats its keys: J1 and J2 with no penalty sent (are identical requests identical?), J3 with `presence_penalty: 0`.
Raw HTTP to /v1/chat/completions (what the pipeline's client sends), ONE REQUEST AT A TIME, temperature 0,
max_tokens 4,096, the pipeline's JSON system message. 6 requests. Results printed and saved as JSON lines.

Usage:
    .venv/bin/python eval/probe_model_settings.py --model qwen3.6:latest --out eval/results/probe_qwen36_settings.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

import requests

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

BASE = "http://localhost:11434/v1/chat/completions"
MAX_TOKENS = 4096
TINY = 'Reply with exactly {"ok": true} and nothing else.'
REPEATED = ("Output JSON only: {\"items\": [...]} with 15 objects, each {\"field\": \"CommandLine\", \"value\": "
            "\"cmd.exe /c whoami\"} - the same field and value every time.")
_THINK = re.compile(r"<think>(.*?)</think>", re.S)


def reasoning_of(message: dict) -> str:
    """A thinking model's reasoning: a `reasoning` / `reasoning_content` field, or the text inside <think> tags."""
    for key in ("reasoning", "reasoning_content"):
        if message.get(key):
            return str(message[key]).strip()
    found = _THINK.search(message.get("content") or "")
    return found.group(1).strip() if found else ""


def answer_of(message: dict) -> str:
    """The answer without any <think> part."""
    return _THINK.sub("", message.get("content") or "").strip()


def override_verdict(j1: str, j2: str, j3: str) -> str:
    if j1 != j2:
        return "inconclusive: identical requests gave different answers"
    return "no effect seen" if j3 == j1 else "the request's value overrides the Modelfile's"


def _send(model: str, prompt: str, extra: dict) -> dict:
    from backend.llm_client import request_messages
    body = {"model": model, "messages": request_messages(prompt, True), "temperature": 0, "max_tokens": MAX_TOKENS,
            **extra}
    started = time.monotonic()
    r = requests.post(BASE, json=body, timeout=600)            # waited for before the next request
    seconds = round(time.monotonic() - started, 1)
    data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"error": r.text}
    choice = (data.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    return {"status": r.status_code, "seconds": seconds, "finish": choice.get("finish_reason"),
            "usage": data.get("usage"), "answer": answer_of(message), "reasoning": reasoning_of(message),
            "message_keys": sorted(message), "error": data.get("error")}


def main(argv: list) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--model", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args(argv[1:])
    rows = []

    def run(name, prompt, extra):
        res = {"name": name, "extra": extra, **_send(args.model, prompt, extra)}
        rows.append(res)
        u = res["usage"] or {}
        print(f"  {name:3} {json.dumps(extra):34} status {res['status']}  {res['seconds']:6}s  "
              f"completion {u.get('completion_tokens')}  reasoning {len(res['reasoning'])} chars  "
              f"finish {res['finish']}  answer {res['answer'][:60]!r}")
        return res

    t = [run("T1", TINY, {}), run("T2", TINY, {"think": False}), run("T3", TINY, {"reasoning_effort": "none"})]
    off = next((r["extra"] for r in t[1:] if r["status"] == 200 and not r["reasoning"]), {})
    print(f"\nthinking by default: {'yes' if t[0]['reasoning'] else 'no'}; "
          f"turned off by: {json.dumps(off) if off else 'neither field (J uses T1 settings)'}\n")
    j1 = run("J1", REPEATED, dict(off))
    j2 = run("J2", REPEATED, dict(off))
    j3 = run("J3", REPEATED, {**off, "presence_penalty": 0})
    print(f"\npresence_penalty: {override_verdict(j1['answer'], j2['answer'], j3['answer'])}")
    Path(args.out).write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
