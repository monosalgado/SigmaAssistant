#!/usr/bin/env python3
"""Snapshot the GitHub files and gists the PoC stage fetches (plan 1.3a, defect 16).

Why this exists
---------------
`PoCAnalysisStage` fetches up to three GitHub files and two gists linked from the
text. The evaluation served reference pages from snapshots but let these fetches
go to the live network, so 43 of 303 cases were not reproducible, and their input
changed as repositories changed or disappeared (10 of the 45 files already
returned 404 when first measured, 2026-09-23).

This script computes, for every case, exactly the URLs the stage would fetch
(`github_fetch_targets`, shared with the stage), fetches each unique URL once, and
stores the body under `eval/snapshots/github/` (gitignored, like the pages). The
manifest `eval/github_manifest.jsonl` is committed: one line per URL with its
status, size, SHA-256 and fetch time. A URL that returned 404 is recorded as
such, and the evaluation replays the 404.

Idempotent: URLs already in the manifest are not fetched again.

Usage (network, no VPN needed):
    .venv/bin/python eval/build_poc_snapshots.py
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

USER_AGENT = "Mozilla/5.0 SigmaAssistant/1.0"  # the header the PoC stage sends


def _relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO))
    except ValueError:
        return str(path.resolve())


def snapshot_urls(urls, out_dir: Path, manifest: Path, fetch) -> dict:
    """Fetch each URL not yet in `manifest` and record it. Returns counts.

    `fetch(url)` returns an object with `status_code` and `content` (bytes); it is
    injected so the logic can be tested offline.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    known = set()
    if manifest.exists():
        known = {json.loads(l)["fetch_url"] for l in manifest.read_text().splitlines() if l.strip()}

    counts = {"already_stored": 0, "fetched": 0, "not_found": 0, "failed": 0}
    with manifest.open("a", encoding="utf-8") as fh:
        for url in sorted(set(urls)):
            if url in known:
                counts["already_stored"] += 1
                continue
            entry = {"fetch_url": url, "fetched_at": datetime.now(timezone.utc).isoformat()}
            try:
                resp = fetch(url)
            except Exception as exc:
                # Not recorded: a network error says nothing about the file, so
                # the next run tries again rather than replaying a failure.
                counts["failed"] += 1
                print(f"  FAILED {url}: {type(exc).__name__}: {exc}")
                continue
            entry["status"] = resp.status_code
            body = resp.content if resp.status_code == 200 else b""
            if resp.status_code == 200:
                path = out_dir / (hashlib.sha256(url.encode()).hexdigest()[:16] + ".body")
                path.write_bytes(body)
                entry.update(path=_relative(path), bytes=len(body),
                             sha256=hashlib.sha256(body).hexdigest())
                counts["fetched"] += 1
            else:
                entry.update(path=None, bytes=0, sha256=None)
                counts["not_found"] += 1
            fh.write(json.dumps(entry) + "\n")
            fh.flush()
    return counts


def corpus_targets(min_chars: int = 2000) -> set:
    """Every URL the PoC stage would fetch, across all evaluation cases."""
    from backend.pipeline.stage_poc_analysis import github_fetch_targets
    from backend.pipeline.stage_preprocess import PreprocessStage
    from eval.run_eval import load_cases, snapshots_instead_of_network

    urls = set()
    for case in load_cases(REPO / "eval/manifest.jsonl", REPO, min_chars):
        with snapshots_instead_of_network(case["url_to_path"]), \
                contextlib.redirect_stdout(io.StringIO()):
            ctx = PreprocessStage(None, "").run(
                {"original_query": " ".join(case["urls"]), "history": [], "media_file": None})
        files, gists = github_fetch_targets(ctx["preprocessed"]["combined_text"])
        urls |= {t["fetch_url"] for t in files + gists}
    return urls


def main() -> int:
    import requests

    urls = corpus_targets()
    print(f"{len(urls)} unique URLs the PoC stage would fetch")
    counts = snapshot_urls(
        urls, REPO / "eval/snapshots/github", REPO / "eval/github_manifest.jsonl",
        fetch=lambda u: requests.get(u, timeout=15, headers={"User-Agent": USER_AGENT}))
    print(counts)
    return 1 if counts["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
