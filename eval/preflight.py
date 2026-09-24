#!/usr/bin/env python3
"""Pre-run checklist for an evaluation run (plan 1.4b). Needs the VPN.

Runs, in order, the checks that used to be done by hand before every run, and
stops at the first failure with the fix:

  1. tunnel   The SSH tunnel answers a real HTTP request. A running `ssh` process
              is not evidence: a dropped tunnel leaves its listener bound.
  2. model    The model answers and reports token counts (else C1 would be empty).
  3. context  The server gives the model >= 32k context (`ollama ps` on the
              Spark). Since Change 12, prompts reach ~25k tokens and our code sets
              no num_ctx, so a smaller server context would truncate silently.
  4. tests    The offline test suite passes.
  5. smoke    A 2-case run (seed 7, a sample the real runs do not use) passes
              every gate of `summarise.check_gates`.

Exit status 0 only if all five pass. The smoke output goes to
eval/results/preflight/ (gitignored), a fresh file each time so resume never
skips it.

Usage:
    .venv/bin/python eval/preflight.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

MIN_CONTEXT = 32768


def context_from_ollama_ps(text: str, model: str):
    """The CONTEXT value for `model` in `ollama ps` output, or None if not loaded.

    `ollama ps` prints fixed-width columns, so the value is sliced at the header's
    column positions rather than split on spaces (PROCESSOR reads "100% GPU").
    """
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines or "CONTEXT" not in lines[0]:
        return None
    header = lines[0]
    start = header.index("CONTEXT")
    end = header.index("UNTIL") if "UNTIL" in header else None
    for line in lines[1:]:
        if line.split()[0] == model:
            value = line[start:end].strip()
            return int(value) if value.isdigit() else None
    return None


def has_token_counts(response: dict) -> bool:
    usage = response.get("usage") or {}
    return all(isinstance(usage.get(k), int) and usage[k] > 0
               for k in ("prompt_tokens", "completion_tokens"))


def run_preflight(steps) -> int:
    """Run (name, fn) steps in order; each fn returns (ok, detail). Stop at the
    first failure. Returns the exit status."""
    for name, fn in steps:
        try:
            ok, detail = fn()
        except Exception as exc:
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<8} {detail}")
        if not ok:
            print("\nPreflight FAILED - fix the step above before starting a run.")
            return 1
    print("\nPreflight passed - safe to start the run.")
    return 0


# --------------------------------------------------------------------------
# The real steps (network, SSH, subprocesses)
# --------------------------------------------------------------------------

def _settings() -> dict:
    from dotenv import load_dotenv
    load_dotenv(REPO / ".env")
    return {
        "base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/"),
        "model": os.getenv("OLLAMA_MODEL", "qwen3-coder:30b"),
        "ssh": f"{os.getenv('SPARK_SSH_USER', '')}@{os.getenv('SPARK_SSH_HOST', '')}",
    }


def real_steps(cfg: dict) -> list:
    import requests

    tunnel_fix = ("rebuild it: pkill -f 'ssh.*11434'; ssh -N -f -o ExitOnForwardFailure=yes "
                  "-o ServerAliveInterval=30 -o ServerAliveCountMax=3 "
                  f"-L 11434:localhost:11434 {cfg['ssh']}")

    def tunnel():
        try:
            r = requests.get(f"{cfg['base_url']}/api/version", timeout=5)
        except Exception as exc:
            return False, f"no answer ({type(exc).__name__}); {tunnel_fix}"
        return r.status_code == 200, f"HTTP {r.status_code}" + ("" if r.status_code == 200 else f"; {tunnel_fix}")

    def model():
        r = requests.post(f"{cfg['base_url']}/v1/chat/completions", timeout=300, json={
            "model": cfg["model"], "temperature": 0,
            "messages": [{"role": "user", "content": "Reply with OK"}]})
        data = r.json()
        ok = r.status_code == 200 and has_token_counts(data)
        return ok, f"{cfg['model']}: HTTP {r.status_code}, usage {data.get('usage')}"

    def context():
        out = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                              cfg["ssh"], "ollama ps"], capture_output=True, text=True, timeout=30)
        ctx = context_from_ollama_ps(out.stdout, cfg["model"])
        if ctx is None:
            return False, f"{cfg['model']} not in `ollama ps` ({out.stderr.strip()[:80]})"
        return ctx >= MIN_CONTEXT, f"{ctx} tokens (need >= {MIN_CONTEXT})"

    def tests():
        out = subprocess.run([sys.executable, "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider"],
                             cwd=REPO, capture_output=True, text=True, timeout=600)
        last = (out.stdout.strip().splitlines() or ["no output"])[-1]
        return out.returncode == 0, last

    def smoke():
        from eval.summarise import check_gates, load
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_file = REPO / "eval/results/preflight" / f"smoke-{stamp}.jsonl"
        env = dict(os.environ, LLM_PROVIDER="ollama", ECONOMY_PROVIDER="ollama")
        run = subprocess.run([sys.executable, "eval/run_eval.py", "--sample", "2", "--seed", "7",
                              "--no-web-enrich", "--arm", "preflight", "--out", str(out_file)],
                             cwd=REPO, env=env, capture_output=True, text=True, timeout=1800)
        if run.returncode != 0 or not out_file.exists():
            tail = (run.stdout.strip().splitlines() or [""])[-1]
            return False, f"run_eval exited {run.returncode}: {tail[:160]}"
        rows = load(out_file)
        gates = check_gates(rows)
        failing = [c["name"] for c in gates["checks"] if c["status"] != "PASS"]
        detail = f"{len(rows)} rows, verdict {gates['verdict']}" + (f", not passing: {failing}" if failing else "")
        return len(rows) == 2 and gates["verdict"] == "CITABLE", f"{detail} ({out_file.name})"

    return [("tunnel", tunnel), ("model", model), ("context", context),
            ("tests", tests), ("smoke", smoke)]


def main() -> int:
    cfg = _settings()
    print(f"Preflight: {cfg['model']} at {cfg['base_url']} (Spark {cfg['ssh']})")
    return run_preflight(real_steps(cfg))


if __name__ == "__main__":
    sys.exit(main())
