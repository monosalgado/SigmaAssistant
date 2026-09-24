#!/usr/bin/env python3
"""Run the evaluation and relaunch it after a connection drop (plan 1.4c). Needs the VPN.

Replaces the old /tmp watchdog. That script had to spot garbage rows after the
fact and purge them; since Change 16 the harness itself refuses to write a row
with a failed LLM call and exits with status 2, so all that is left is to react
to that status:

  0          the run finished                       -> done
  2          stopped at a failed LLM call           -> rebuild the SSH tunnel,
             (usually the VPN or tunnel dropped)       check it answers, rerun the
                                                       same command (resume picks
                                                       up at the unwritten case)
  other      the harness itself failed (a bug)      -> stop; repeating won't help

At most 5 relaunches. If the tunnel cannot be brought back (VPN down), it waits
and retries for up to ~10 minutes before giving up with status 3.

Usage (arguments after -- go to eval/run_eval.py unchanged):
    .venv/bin/python eval/run_resilient.py -- --sample 60 --seed 0 --arm baseline_v2 \\
        --no-web-enrich --out eval/results/baseline60_v2.jsonl
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
STOPPED_AT_FAILED_CALL = 2   # run_eval.py's exit status (Change 16)
NO_TUNNEL = 3


def supervise(run, ensure_tunnel, max_relaunches: int = 5, sleep=time.sleep) -> int:
    """Run until finished; relaunch only on STOPPED_AT_FAILED_CALL. Returns the
    final exit status."""
    relaunches = 0
    while True:
        if not ensure_tunnel():
            print("\nGiving up: the tunnel to the Spark could not be established "
                  "(is the USF VPN connected?).")
            return NO_TUNNEL
        code = run()
        if code != STOPPED_AT_FAILED_CALL:
            return code
        if relaunches >= max_relaunches:
            print(f"\nGiving up after {relaunches} relaunches; the run keeps stopping "
                  "at a failed LLM call. Rerun later: finished cases are kept.")
            return code
        relaunches += 1
        print(f"\n--- relaunch {relaunches}/{max_relaunches} after a failed LLM call ---")
        sleep(30)


# --------------------------------------------------------------------------
# The real run and tunnel
# --------------------------------------------------------------------------

def _tunnel_answers(base_url: str) -> bool:
    import requests
    try:
        return requests.get(f"{base_url}/api/version", timeout=5).status_code == 200
    except Exception:
        return False


def make_ensure_tunnel(base_url: str, ssh_target: str, attempts: int = 10, wait_s: int = 60):
    def ensure_tunnel() -> bool:
        for attempt in range(1, attempts + 1):
            if _tunnel_answers(base_url):
                return True
            print(f"  tunnel not answering (attempt {attempt}/{attempts}); rebuilding")
            subprocess.run(["pkill", "-f", "ssh.*11434"], capture_output=True)
            subprocess.run(["ssh", "-N", "-f", "-o", "ExitOnForwardFailure=yes",
                            "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
                            "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                            "-L", "11434:localhost:11434", ssh_target],
                           capture_output=True, timeout=30)
            time.sleep(3)
            if _tunnel_answers(base_url):
                return True
            if attempt < attempts:
                time.sleep(wait_s)
        return False
    return ensure_tunnel


def main() -> int:
    from dotenv import load_dotenv
    load_dotenv(REPO / ".env")
    args = sys.argv[1:]
    if args and args[0] == "--":
        args = args[1:]
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    ssh_target = f"{os.getenv('SPARK_SSH_USER', '')}@{os.getenv('SPARK_SSH_HOST', '')}"
    env = dict(os.environ, LLM_PROVIDER="ollama", ECONOMY_PROVIDER="ollama")

    def run() -> int:
        return subprocess.run([sys.executable, "eval/run_eval.py", *args], cwd=REPO, env=env).returncode

    return supervise(run, make_ensure_tunnel(base_url, ssh_target))


if __name__ == "__main__":
    sys.exit(main())
