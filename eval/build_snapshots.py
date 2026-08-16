"""Build a frozen, offline evaluation dataset from the SigmaHQ emerging-threats rules.

Why this exists
---------------
Evaluating the pipeline against live URLs is not reproducible: pages change, links
rot, and paywalls appear. This script fetches each rule's reference URLs exactly
once and caches the raw HTML on disk, so every later evaluation run is offline,
repeatable, and costs nothing.

Why this dataset
----------------
`data/sigma/rules-emerging-threats` is NOT ingested into the vector store
(`ingest_rules.py` walks only `data/sigma/rules`), so these rules cannot be
retrieved by RAG. Each rule carries the `references:` URLs its human author
actually read, which yields genuine (CTI page -> gold rule) pairs without the
leakage introduced by synthesising a report from a rule.

What it stores
--------------
Raw HTML, keyed by URL hash so pages shared between rules are fetched once.
HTML-to-text extraction is deliberately NOT done here: that is pipeline logic
(`PreprocessStage._extract_page_content`) which may change, and baking it into the
snapshot would force a re-crawl every time it does.

Usage
-----
    .venv/bin/python eval/build_snapshots.py --limit 5      # sample first
    .venv/bin/python eval/build_snapshots.py                # full crawl

Re-running is safe and resumable: already-cached URLs are not re-fetched.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
import urllib.robotparser
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml

# Hosts that return HTTP 200 but serve a login wall, an interactive app, or a
# binary — so a naive status-code check overstates how many references are usable.
WALLED_HOSTS = {
    "twitter.com", "x.com", "mobile.twitter.com",
    "www.virustotal.com", "virustotal.com",
    "app.any.run", "any.run",
    "www.hybrid-analysis.com", "hybrid-analysis.com",
    "app.box.com", "box.com",
    "www.linkedin.com", "linkedin.com",
    "t.me",
}

# Matches the User-Agent used by PreprocessStage so snapshots reflect what the
# pipeline would actually receive.
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# PreprocessStage reads at most 3 URLs per query (stage_preprocess.py: urls[:3]),
# so fetching more references than this would cache pages the pipeline can never
# consume.
MAX_REFS_PER_RULE = 3


def is_usable_reference(url: str) -> bool:
    """Reject references that cannot serve as CTI text input."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if parsed.netloc.lower() in WALLED_HOSTS:
        return False
    if parsed.path.lower().endswith((".pdf", ".zip", ".exe", ".bin", ".gz")):
        return False
    return True


def url_key(url: str) -> str:
    """Stable filename for a URL, so pages shared by several rules are fetched once."""
    return hashlib.sha1(url.encode("utf-8")).hexdigest()[:16]


def load_gold_rules(rules_dir: Path) -> list:
    """Load emerging-threats rules that have at least one reference URL."""
    rules = []
    for path in sorted(rules_dir.rglob("*.yml")):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                content = yaml.safe_load(fh)
        except Exception as exc:
            print(f"  skip (unparseable): {path} ({exc})")
            continue

        if not isinstance(content, dict) or "title" not in content:
            continue
        if "detection" not in content or "logsource" not in content:
            continue

        references = content.get("references") or []
        if not isinstance(references, list):
            references = [references]
        references = [str(r).strip() for r in references if r]

        rules.append({
            "rule_id": content.get("id", str(path)),
            "rule_path": str(path),
            "title": content.get("title", ""),
            "logsource": content.get("logsource", {}) or {},
            "tags": content.get("tags", []) or [],
            "level": content.get("level", ""),
            "references_all": references,
        })
    return rules


class RobotsCache:
    """Per-host robots.txt checks. Fails open: unreachable robots.txt allows fetching."""

    def __init__(self) -> None:
        self._parsers = {}

    def allows(self, url: str) -> bool:
        parsed = urlparse(url)
        host = f"{parsed.scheme}://{parsed.netloc}"
        if host not in self._parsers:
            parser = urllib.robotparser.RobotFileParser()
            parser.set_url(f"{host}/robots.txt")
            try:
                parser.read()
            except Exception:
                parser = None
            self._parsers[host] = parser
        parser = self._parsers[host]
        if parser is None:
            return True
        try:
            return parser.can_fetch(USER_AGENT, url)
        except Exception:
            return True


def fetch_url(session: requests.Session, url: str, timeout: int) -> dict:
    """Fetch one URL. Returns a record describing the outcome, never raises."""
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        return {
            "status": resp.status_code,
            "content": resp.content if resp.status_code == 200 else b"",
            "final_url": resp.url,
            "error": None,
        }
    except Exception as exc:
        return {
            "status": None,
            "content": b"",
            "final_url": url,
            "error": f"{type(exc).__name__}: {exc}",
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-dir", default="data/sigma/rules-emerging-threats")
    parser.add_argument("--out-dir", default="eval/snapshots")
    parser.add_argument("--manifest", default="eval/manifest.jsonl")
    parser.add_argument("--limit", type=int, default=0,
                        help="Only process the first N rules (0 = all).")
    parser.add_argument("--max-refs", type=int, default=MAX_REFS_PER_RULE,
                        help="Max references to fetch per rule.")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="Seconds to sleep between network requests.")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--dry-run", action="store_true",
                        help="Report what would be fetched without making requests.")
    parser.add_argument("--ignore-robots", action="store_true")
    args = parser.parse_args()

    rules_dir = Path(args.rules_dir)
    if not rules_dir.exists():
        raise SystemExit(f"Rules directory not found: {rules_dir}")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading gold rules from {rules_dir} ...")
    rules = load_gold_rules(rules_dir)
    print(f"  parsed {len(rules)} rules with title+logsource+detection")

    if args.limit:
        rules = rules[:args.limit]
        print(f"  limited to first {len(rules)}")

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    robots = RobotsCache()

    stats = {
        "rules_total": len(rules),
        "rules_no_refs": 0,
        "rules_all_walled": 0,
        "rules_with_snapshot": 0,
        "rules_fetch_failed": 0,
        "urls_attempted": 0,
        "urls_ok": 0,
        "urls_cached_hit": 0,
        "urls_robots_blocked": 0,
        "urls_failed": 0,
    }

    manifest_entries = []

    for idx, rule in enumerate(rules, 1):
        refs_all = rule["references_all"]
        # Deduplicate while preserving author order.
        seen = set()
        usable = []
        for url in refs_all:
            if url in seen:
                continue
            seen.add(url)
            if is_usable_reference(url):
                usable.append(url)

        entry = dict(rule)
        entry["references_usable"] = usable
        entry["snapshots"] = []

        if not refs_all:
            entry["status"] = "no_refs"
            stats["rules_no_refs"] += 1
            manifest_entries.append(entry)
            continue

        if not usable:
            entry["status"] = "all_walled"
            stats["rules_all_walled"] += 1
            manifest_entries.append(entry)
            continue

        for url in usable[:args.max_refs]:
            key = url_key(url)
            dest = out_dir / f"{key}.html"

            if dest.exists():
                stats["urls_cached_hit"] += 1
                entry["snapshots"].append({
                    "url": url,
                    "path": str(dest),
                    "status": 200,
                    "bytes": dest.stat().st_size,
                    "from_cache": True,
                })
                continue

            if args.dry_run:
                stats["urls_attempted"] += 1
                continue

            if not args.ignore_robots and not robots.allows(url):
                stats["urls_robots_blocked"] += 1
                print(f"[{idx}/{len(rules)}] robots.txt disallows: {url}")
                continue

            stats["urls_attempted"] += 1
            result = fetch_url(session, url, args.timeout)
            time.sleep(args.delay)

            if result["status"] == 200 and result["content"]:
                dest.write_bytes(result["content"])
                stats["urls_ok"] += 1
                entry["snapshots"].append({
                    "url": url,
                    "path": str(dest),
                    "status": 200,
                    "bytes": len(result["content"]),
                    "final_url": result["final_url"],
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                    "from_cache": False,
                })
                print(f"[{idx}/{len(rules)}] ok {len(result['content']):>8} B  {url}")
            else:
                stats["urls_failed"] += 1
                reason = result["error"] or f"HTTP {result['status']}"
                print(f"[{idx}/{len(rules)}] FAIL {reason}  {url}")

        if entry["snapshots"]:
            entry["status"] = "ok"
            stats["rules_with_snapshot"] += 1
        else:
            entry["status"] = "fetch_failed" if not args.dry_run else "dry_run"
            if not args.dry_run:
                stats["rules_fetch_failed"] += 1

        manifest_entries.append(entry)

    if not args.dry_run:
        manifest_path = Path(args.manifest)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(manifest_path, "w", encoding="utf-8") as fh:
            for entry in manifest_entries:
                fh.write(json.dumps(entry) + "\n")
        print(f"\nManifest written: {manifest_path} ({len(manifest_entries)} entries)")

    print("\n--- Summary ---")
    for key, value in stats.items():
        print(f"{key:>22}: {value}")

    usable_cases = stats["rules_with_snapshot"]
    if stats["rules_total"]:
        pct = 100.0 * usable_cases / stats["rules_total"]
        print(f"\nUsable eval cases: {usable_cases}/{stats['rules_total']} ({pct:.1f}%)")
        print("NOTE: 'usable' here means a page was retrieved, not that it contains "
              "usable CTI. Text-yield filtering happens at eval time.")


if __name__ == "__main__":
    main()
