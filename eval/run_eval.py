"""Run the pipeline over the frozen evaluation cases and record scores + cost.

Why this exists
---------------
This is the piece that finally answers "did the changes help?". It joins the three
earlier parts: the frozen cases (Change 3), the deterministic scorers (Change 4),
and the telemetry (Change 5), writing one JSONL row per case.

How pages are served
--------------------
`PreprocessStage` fetches reference URLs with `requests.get`. During evaluation the
`requests` reference inside that module is swapped for a shim that serves the cached
snapshot instead. Everything downstream — HTML extraction, truncation, segmentation —
runs exactly as in production, so the only altered behaviour is where the bytes come
from. Nothing in `backend/` is modified.

Cost warning
------------
With `ECONOMY_PROVIDER=ollama` (hybrid), **only economy-tier calls go to the Spark**.
poc_analysis, attack_vector, analysis and review are `economy=True` and run locally,
but **rule generation uses the Gemini primary tier** (`stage_generate.py:235`), so a
hybrid run still spends Gemini quota and is rate-limited to ~9 RPM: one primary call
per case, two when the generation retry fires. For a zero-cost run set
`LLM_PROVIDER=ollama`, which routes every stage to Ollama and makes web enrichment a
no-op. The provider actually used is recorded in each output row.

Usage
-----
    # smoke test: 2 cases, no web search
    .venv/bin/python eval/run_eval.py --limit 2 --no-web-enrich --out eval/results/smoke.jsonl

    # stratified subsample, resumable
    .venv/bin/python eval/run_eval.py --sample 60 --seed 0 --out eval/results/run1.jsonl

Re-running with the same --out resumes: cases already present are skipped.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import time
import traceback
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urldefrag

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.pipeline.stage_preprocess import PreprocessStage  # noqa: E402
from backend.telemetry import TELEMETRY  # noqa: E402
from eval.scorers import score_case  # noqa: E402

_YAML_BLOCK_RE = re.compile(r"```ya?ml\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)

# Intermediate results kept in each row, so a score can be explained: what the
# attack-vector and analysis stages concluded, what review objected to, and how
# many generation calls ran. Everything else in pipeline_metadata is left out
# (e.g. enrichment sources, which are always empty on the all-local setup).
DIAGNOSIS_FIELDS = (
    "attack_vector", "attack_summary", "indicators", "ttp_mappings",
    "logsource_suggestions", "logsource_primary", "suggested_log_sources",
    "coverage_check", "validation_issues", "poc_snippets_found",
    "generations", "generation_retried",
)


# --------------------------------------------------------------------------
# Serving snapshots in place of the network
# --------------------------------------------------------------------------

class _SnapshotResponse:
    """Duck-types the parts of `requests.Response` that PreprocessStage uses."""

    def __init__(self, content: bytes, status_code: int = 200):
        self.content = content
        self.status_code = status_code


def snapshot_key(url: str) -> str:
    """Normalise a URL for snapshot lookup by dropping the `#fragment`.

    A fragment is a client-side anchor and is never sent to the server, so two
    URLs differing only by fragment name the same page and the same snapshot
    file. The pipeline strips it while extracting links, so without this the
    manifest key (fragment kept) and the lookup (fragment gone) never match and
    the case silently degrades to a 404.
    """
    return urldefrag(url)[0]


class _SnapshotRequests:
    """Stands in for the `requests` module inside PreprocessStage."""

    def __init__(self, url_to_path: dict):
        self._map = url_to_path
        self.served = 0
        self.missed = 0

    def get(self, url, **kwargs):
        path = self._map.get(snapshot_key(url))
        if path is None:
            self.missed += 1
            # 404 rather than an exception: the pipeline already handles a bad
            # status, and a case with a missing snapshot should degrade the same
            # way a dead link does in production.
            return _SnapshotResponse(b"", status_code=404)
        self.served += 1
        return _SnapshotResponse(Path(path).read_bytes(), status_code=200)


@contextmanager
def snapshots_instead_of_network(url_to_path: dict):
    """Swap PreprocessStage's `requests` for a snapshot-backed shim.

    Patches the module attribute rather than `requests.get` globally, so nothing
    else in the process loses network access.
    """
    import backend.pipeline.stage_preprocess as module

    original = module.requests
    shim = _SnapshotRequests(url_to_path)
    module.requests = shim
    try:
        yield shim
    finally:
        module.requests = original


@contextmanager
def web_enrichment_disabled(client, disabled: bool):
    """Optionally stub out Gemini Google-Search grounding.

    Enrichment is non-deterministic week to week and bills to the primary tier,
    so it is separated from the deterministic core rather than silently included.
    """
    if not disabled:
        yield
        return
    original = client.web_search
    client.web_search = lambda query: {"text": "", "sources": []}
    try:
        yield
    finally:
        client.web_search = original


# --------------------------------------------------------------------------
# Case loading
# --------------------------------------------------------------------------

def load_cases(manifest_path: Path, repo_root: Path, min_chars: int) -> list:
    """Load manifest entries that have a snapshot with enough extracted text.

    Text is extracted with the pipeline's own `_extract_page_content`, so the
    threshold is applied to exactly what the model would receive.
    """
    extractor = PreprocessStage(client=None, model_name="")
    cases = []

    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("status") != "ok":
            continue

        gold_path = repo_root / entry["rule_path"]
        try:
            gold = yaml.safe_load(gold_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(gold, dict) or "detection" not in gold:
            continue

        url_to_path, total_chars, urls = {}, 0, []
        for snap in entry.get("snapshots", []):
            path = repo_root / snap["path"]
            if not path.exists():
                continue
            try:
                text, _ = extractor._extract_page_content(path.read_bytes(), snap["url"])
            except Exception:
                continue
            total_chars += len(text)
            url_to_path[snapshot_key(snap["url"])] = str(path)
            # `urls` keeps the original reference, fragment and all, because that
            # is what a user would paste; only the lookup key is normalised.
            urls.append(snap["url"])

        if total_chars < min_chars:
            continue

        cases.append({
            "rule_id": entry["rule_id"],
            "rule_path": entry["rule_path"],
            "title": entry.get("title", ""),
            "category": (entry.get("logsource") or {}).get("category") or "none",
            "product": (entry.get("logsource") or {}).get("product") or "none",
            "urls": urls,
            "url_to_path": url_to_path,
            "text_chars": total_chars,
            "gold": gold,
        })
    return cases


def stratified_sample(cases: list, n: int, seed: int) -> list:
    """Sample while preserving the logsource-category mix.

    A uniform sample would under-represent the non-Windows categories, which are
    exactly the ones the corpus-expansion change (A3) was meant to affect.
    """
    if n >= len(cases):
        return cases
    by_category = defaultdict(list)
    for case in cases:
        by_category[case["category"]].append(case)

    rng = random.Random(seed)
    fraction = n / len(cases)
    selected, leftovers = [], []

    # Floor the proportional quota and keep at least one per category, then top
    # up to exactly `n`. Rounding each quota independently loses cases — every
    # category rounding down makes the sample smaller than requested, so the run
    # would not match the sample size reported alongside the results.
    for category in sorted(by_category):
        group = sorted(by_category[category], key=lambda c: c["rule_id"])
        rng.shuffle(group)
        take = min(len(group), max(1, int(len(group) * fraction)))
        selected.extend(group[:take])
        leftovers.extend(group[take:])

    if len(selected) < n:
        rng.shuffle(leftovers)
        selected.extend(leftovers[:n - len(selected)])
    elif len(selected) > n:
        # Only reachable when n is smaller than the number of categories, in
        # which case not every category can be represented.
        rng.shuffle(selected)
        selected = selected[:n]

    rng.shuffle(selected)
    return selected


def extract_rule_yamls(response_text: str) -> list:
    """Pull YAML blocks out of the pipeline's markdown response."""
    return [m.strip() for m in _YAML_BLOCK_RE.findall(response_text or "") if m.strip()]


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

def run_case(agent, case: dict, config: dict, no_web_enrich: bool) -> dict:
    """Run the pipeline on one case and return its result row."""
    client = agent.client
    TELEMETRY.reset()
    started = time.time()
    row = {
        "rule_id": case["rule_id"],
        "rule_path": case["rule_path"],
        "title": case["title"],
        "category": case["category"],
        "product": case["product"],
        "urls": case["urls"],
        "text_chars": case["text_chars"],
        "config": config,
        "run_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        with snapshots_instead_of_network(case["url_to_path"]) as shim, \
                web_enrichment_disabled(client, no_web_enrich):
            # run_sync, not agent.analyze_attack: the agent wraps this same call
            # in a catch-all that returns the error as ordinary response text,
            # which would turn a crashed case into a normal-looking row with
            # zero rules. Called directly, a crash lands in the except below.
            try:
                result = agent.orchestrator.run_sync(description=" ".join(case["urls"]))
            finally:
                # Kept on a crash too, so gate 1 is computable for every row.
                row["snapshots_served"] = shim.served
                row["snapshots_missed"] = shim.missed

        response_text = result.get("rule", "")
        rules = extract_rule_yamls(response_text)
        # Every generated rule is stored so best-of-N can be computed
        # later without paying for another run; scoring uses the first,
        # which is what a user sees.
        row["n_rules"] = len(rules)
        row["rules_yaml"] = rules
        row["scores"] = score_case(rules[0], case["gold"]) if rules else \
            score_case(response_text, case["gold"])
        row["response_chars"] = len(response_text)
        if not rules:
            # Only kept when there is nothing else to look at: rules_yaml already
            # holds every rule, and the full text would double the file.
            row["response_text"] = response_text
        metadata = result.get("pipeline_metadata") or {}
        row["pipeline"] = {k: metadata[k] for k in DIAGNOSIS_FIELDS if k in metadata}
        row["error"] = None
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
        row["traceback"] = traceback.format_exc()[-1500:]
        row["scores"] = None
        row["n_rules"] = 0

    row["elapsed_s"] = round(time.time() - started, 2)
    row["telemetry"] = TELEMETRY.summary()
    row["llm_calls"] = TELEMETRY.as_dicts()
    return row


def unmeasured_reason(row: dict):
    """Why a case's row is not a measurement of the pipeline, or None if it is.

    A failed LLM call means some stage ran on its empty default instead of the
    model's answer, so the case measured a degraded pipeline. Two shapes occurred
    (defect 12): every call failing within seconds while the backend was
    unreachable, and one failed call in a case that then hung for hours but still
    produced rules. Both are caught here; a pipeline crash with every call
    succeeding is not, because that is a finding about the pipeline itself.
    """
    calls = row.get("llm_calls") or []
    failed = [c for c in calls if not c.get("ok", True)]
    if not failed:
        return None
    stages = sorted({c.get("stage") or "unknown" for c in failed})
    return (f"{len(failed)} of {len(calls)} LLM calls failed "
            f"(stages: {', '.join(stages)}); first error: {failed[0].get('error')}")


def run_cases(agent, cases: list, config: dict, no_web_enrich: bool, out_file):
    """Run cases in order, appending one JSON row per case to `out_file`.

    Stops at the first case with a failed LLM call and does NOT write its row, so
    rerunning the same command resumes from that case instead of skipping it.
    Returns (n_ok, n_failed, stopped), where `stopped` is None when every case ran.
    """
    n_ok = n_failed = 0
    stopped = None
    for idx, case in enumerate(cases, 1):
        row = run_case(agent, case, config, no_web_enrich)
        reason = unmeasured_reason(row)
        if reason:
            stopped = (f"STOPPED at case {case['rule_id']} ({idx}/{len(cases)}): {reason}. "
                       "Its row was NOT written. Check the backend (VPN, SSH tunnel, "
                       "Ollama), then rerun the same command to resume from this case.")
            print("\n" + stopped)
            break

        if row["error"] is None:
            n_ok += 1
        else:
            n_failed += 1

        out_file.write(json.dumps(row) + "\n")
        out_file.flush()  # a crash must not lose completed cases

        scores = row.get("scores") or {}
        validity = (scores.get("validity") or {}).get("parses")
        tokens = row["telemetry"].get("total_tokens")
        print(f"[{idx}/{len(cases)}] {case['rule_id'][:8]} "
              f"{case['category']:<18} valid={validity} "
              f"rules={row['n_rules']} {row['elapsed_s']}s "
              f"tokens={tokens} {'ERROR: ' + row['error'] if row['error'] else ''}")
    return n_ok, n_failed, stopped


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default="eval/manifest.jsonl")
    parser.add_argument("--out", default="eval/results/run.jsonl")
    parser.add_argument("--min-chars", type=int, default=2000,
                        help="Minimum extracted text for a case to be usable.")
    parser.add_argument("--limit", type=int, default=0, help="First N cases (0 = all).")
    parser.add_argument("--sample", type=int, default=0,
                        help="Stratified subsample of N cases (0 = no sampling).")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--no-web-enrich", action="store_true",
                        help="Stub out Gemini Google-Search grounding.")
    parser.add_argument("--arm", default="default",
                        help="Label recorded with every row, for comparing runs.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report the case selection without calling any LLM.")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    manifest_path = repo_root / args.manifest
    if not manifest_path.exists():
        raise SystemExit(f"Manifest not found: {manifest_path}. Run build_snapshots.py first.")

    print(f"Loading cases from {manifest_path} ...")
    cases = load_cases(manifest_path, repo_root, args.min_chars)
    print(f"  {len(cases)} cases with >= {args.min_chars} chars of extracted text")

    if args.sample:
        cases = stratified_sample(cases, args.sample, args.seed)
        print(f"  stratified subsample: {len(cases)} cases (seed {args.seed})")
    if args.limit:
        cases = cases[:args.limit]
        print(f"  limited to first {len(cases)}")

    out_path = repo_root / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)

    done = set()
    if out_path.exists():
        for line in out_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    done.add(json.loads(line)["rule_id"])
                except Exception:
                    continue
        if done:
            print(f"  resuming: {len(done)} cases already in {out_path}")

    todo = [c for c in cases if c["rule_id"] not in done]
    print(f"  {len(todo)} cases to run")

    mix = defaultdict(int)
    for case in todo:
        mix[case["category"]] += 1
    print("  category mix:", dict(sorted(mix.items(), key=lambda kv: -kv[1])))

    if args.dry_run:
        print("\nDry run: no LLM calls made.")
        return

    # Imported late so --dry-run needs no vector store or API key.
    from backend.agent import SigmaAgent

    print("\nInitialising agent ...")
    agent = SigmaAgent()
    client = agent.client
    config = {
        "arm": args.arm,
        "backend": type(client).__name__,
        "primary_model": getattr(client, "model_name", ""),
        "fast_model": getattr(client, "fast_model_name", ""),
        "economy_model": getattr(client, "economy_model_name", ""),
        "web_enrich": not args.no_web_enrich,
        "min_chars": args.min_chars,
    }
    print(f"Config: {config}")
    if type(client).__name__ == "HybridLLMClient":
        print("NOTE: hybrid mode — rule generation uses the Gemini primary tier "
              "(~1 call/case, rate-limited to ~9 RPM). Every other stage is local. "
              "Set LLM_PROVIDER=ollama for a zero-cost run.")

    started_all = time.time()
    with open(out_path, "a", encoding="utf-8") as out_file:
        n_ok, n_failed, stopped = run_cases(agent, todo, config, args.no_web_enrich, out_file)

    elapsed = time.time() - started_all
    print(f"\n--- Done in {elapsed/60:.1f} min ---")
    print(f"  succeeded: {n_ok}")
    print(f"  failed   : {n_failed}")
    print(f"  output   : {out_path}")
    if stopped:
        # Non-zero, so a wrapper can tell "stopped early" from "finished".
        print("\n" + stopped)
        raise SystemExit(2)
    print("\nSummarise with: .venv/bin/python eval/summarise.py " + str(args.out))


if __name__ == "__main__":
    main()
