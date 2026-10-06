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
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urldefrag

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.pipeline.sigma_logsource import _clean, load_logsource_table, on_table  # noqa: E402
from backend.pipeline.stage_preprocess import PreprocessStage  # noqa: E402
from backend.telemetry import TELEMETRY, summarise_calls  # noqa: E402
from eval.scorers import score_case  # noqa: E402

_YAML_BLOCK_RE = re.compile(r"```ya?ml\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)

# Intermediate results kept in each row, so a score can be explained: what the
# attack-vector and analysis stages concluded, what review objected to, and how
# many generation calls ran. Everything else in pipeline_metadata is left out
# (e.g. enrichment sources, which are always empty on the all-local setup).
DIAGNOSIS_FIELDS = (
    "attack_vector", "attack_summary", "indicators", "ttp_mappings", "ttp_dropped_ids",
    "logsource_suggestions", "logsource_primary", "suggested_log_sources",
    "coverage_check", "indicator_use", "pre_review_rules", "review_changes", "validation_issues", "poc_snippets_found",
    "generations", "generation_retried",
    # Change 45: what the web stage searched, kept, dropped and digested.
    "web_enrichment",
    # Only in the simulated-analyst run's oracle rows (plan 5.3): the review and its check.
    "analyst_review", "analyst_check",
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


class _PocSnapshotResponse:
    """Duck-types what PoCAnalysisStage reads from a response: status, text, json()."""

    def __init__(self, content: bytes, status_code: int):
        self.content = content
        self.status_code = status_code

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.text)


class _PocSnapshotRequests:
    """Stands in for the `requests` module inside PoCAnalysisStage (defect 16).

    A URL in the manifest is replayed as it was snapshotted, including a recorded
    404. A URL not in the manifest is answered 404 and counted as a miss, so it can
    never reach the live network unnoticed.
    """

    def __init__(self, url_map: dict):
        self._map = url_map
        self.served = 0
        self.missed = 0

    def get(self, url, **kwargs):
        entry = self._map.get(url)
        if entry is None:
            self.missed += 1
            return _PocSnapshotResponse(b"", 404)
        self.served += 1
        body = Path(entry["path"]).read_bytes() if entry.get("path") else b""
        return _PocSnapshotResponse(body, entry["status"])


def load_github_manifest(path: Path) -> dict:
    """fetch_url -> manifest entry, with stored paths made absolute."""
    repo_root = Path(__file__).resolve().parent.parent
    url_map = {}
    if not Path(path).exists():
        return url_map
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("path") and not Path(entry["path"]).is_absolute():
            entry["path"] = str(repo_root / entry["path"])
        url_map[entry["fetch_url"]] = entry
    return url_map


@contextmanager
def poc_snapshots_instead_of_network(url_map: dict):
    """Swap PoCAnalysisStage's `requests` for the snapshot-backed shim."""
    import backend.pipeline.stage_poc_analysis as module

    original = module.requests
    shim = _PocSnapshotRequests(url_map)
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


def web_mode_error(no_web_enrich: bool, web_snapshots) -> Optional[str]:
    """The evaluation never searches live (Change 45): the web is off, or every query is answered from a saved file."""
    if no_web_enrich and web_snapshots:
        return "use either --no-web-enrich or --web-snapshots, not both"
    if not no_web_enrich and not web_snapshots:
        return ("the evaluation never searches live: use --no-web-enrich, or --web-snapshots FILE "
                "(build it with eval/build_web_snapshots.py)")
    if web_snapshots and not Path(web_snapshots).is_file():
        return f"--web-snapshots: {web_snapshots} not found"
    return None


@contextmanager
def web_search_from_file(agent, path):
    """Change 45: the web stage's searches answered from a saved file - nothing is sent; a query not in the file is
    recorded as missing - and rule pages dropped, so a found human rule cannot make the score measure copying."""
    if not path:
        yield
        return
    from backend.web_search import OllamaWebSearch
    searcher = OllamaWebSearch(None, cache_path=path, offline=True)
    client, stage = agent.client, agent.orchestrator.web_enrich
    original, original_exclude = client.web_search, stage.exclude_rule_pages

    def search(query):
        out = searcher.search(query)
        return {"text": "", "sources": [{"url": r["url"], "title": r["title"]} for r in out["results"]],
                "results": out["results"], "error": out["error"], "limited": False, "cached": True}

    client.web_search = search
    stage.exclude_rule_pages = True
    try:
        yield
    finally:
        client.web_search = original
        stage.exclude_rule_pages = original_exclude


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

def _base_row(case: dict, config: dict) -> dict:
    return {
        "rule_id": case["rule_id"],
        "rule_path": case["rule_path"],
        "title": case["title"],
        "category": case["category"],
        "product": case["product"],
        "urls": case["urls"],
        "text_chars": case["text_chars"],
        # None = not in the flag list (unknown), never assumed clean (plan 1.3b).
        "contamination": case.get("contamination"),
        "config": config,
        "run_at": datetime.now(timezone.utc).isoformat(),
    }


def _record_result(row: dict, result: dict, gold: dict) -> None:
    response_text = result.get("rule", "")
    rules = extract_rule_yamls(response_text)
    # Every generated rule is stored so best-of-N can be computed
    # later without paying for another run; scoring uses the first,
    # which is what a user sees.
    row["n_rules"] = len(rules)
    row["rules_yaml"] = rules
    row["scores"] = score_case(rules[0], gold) if rules else score_case(response_text, gold)
    row["response_chars"] = len(response_text)
    if not rules:
        # Only kept when there is nothing else to look at: rules_yaml already
        # holds every rule, and the full text would double the file.
        row["response_text"] = response_text
    metadata = result.get("pipeline_metadata") or {}
    row["pipeline"] = {k: metadata[k] for k in DIAGNOSIS_FIELDS if k in metadata}
    row["error"] = None


def _record_error(row: dict, exc: Exception) -> None:
    row["error"] = f"{type(exc).__name__}: {exc}"
    row["traceback"] = traceback.format_exc()[-1500:]
    row["scores"] = None
    row["n_rules"] = 0


def _head_revision() -> str:
    import subprocess
    return subprocess.run(["git", "-C", str(Path(__file__).resolve().parent.parent), "rev-parse", "--short",
                           "HEAD"], capture_output=True, text=True).stdout.strip()


def _file_record(path):
    if not path:
        return None
    import hashlib
    return {"path": str(path), "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()}


def run_config(agent, args, head_revision=_head_revision) -> dict:
    """What every row records about the run, including which code ran: this checkout's commit,
    or the older checkout given with --code (eval/old_code.py)."""
    client = agent.client
    old = getattr(args, "code", None)
    return {
        "arm": args.arm,
        "backend": getattr(client, "backend", None) or type(client).__name__,
        "primary_model": getattr(client, "model_name", ""),
        "fast_model": getattr(client, "fast_model_name", ""),
        "economy_model": getattr(client, "economy_model_name", ""),
        "web_enrich": not args.no_web_enrich,
        "web_snapshots": _file_record(getattr(args, "web_snapshots", None)),
        "min_chars": args.min_chars,
        "code": agent.code_revision if old else head_revision(),
        "code_path": old,
    }


def run_case(agent, case: dict, config: dict, no_web_enrich: bool,
             poc_url_map: dict = None, web_snapshots=None) -> dict:
    """Run the pipeline on one case and return its result row."""
    client = agent.client
    TELEMETRY.reset()
    started = time.time()
    row = _base_row(case, config)

    try:
        with snapshots_instead_of_network(case["url_to_path"]) as shim, \
                poc_snapshots_instead_of_network(poc_url_map or {}) as poc_shim, \
                web_enrichment_disabled(client, no_web_enrich), \
                web_search_from_file(agent, web_snapshots):
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
                row["poc_snapshots_served"] = poc_shim.served
                row["poc_snapshots_missed"] = poc_shim.missed

        _record_result(row, result, case["gold"])
    except Exception as exc:
        _record_error(row, exc)

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


def run_cases(agent, cases: list, config: dict, no_web_enrich: bool, out_file,
              poc_url_map: dict = None, web_snapshots=None):
    """Run cases in order, appending one JSON row per case to `out_file`.

    Stops at the first case with a failed LLM call and does NOT write its row, so
    rerunning the same command resumes from that case instead of skipping it.
    Returns (n_ok, n_failed, stopped), where `stopped` is None when every case ran.
    """
    n_ok = n_failed = 0
    stopped = None
    for idx, case in enumerate(cases, 1):
        row = run_case(agent, case, config, no_web_enrich, poc_url_map, web_snapshots)
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


# --------------------------------------------------------------------------
# Simulated analyst (plan 5.3): one analysis, two generations
# --------------------------------------------------------------------------

def load_done(path: Path) -> set:
    """The rule_ids already in a result file, so a rerun resumes after them."""
    done = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    done.add(json.loads(line)["rule_id"])
                except Exception:
                    continue
    return done


def gold_logsource(gold: dict):
    """The gold rule's log source in Sigma's form (placeholders absent), or None."""
    logsource = gold.get("logsource") if isinstance(gold, dict) else None
    if not isinstance(logsource, dict):
        return None
    choice = {f: _clean(logsource.get(f)) for f in ("category", "product", "service")}
    return choice if any(choice.values()) else None


def oracle_review(gold: dict, table: dict):
    """The simulated analyst's review: the gold log source as the analyst's choice, when
    SigmaHQ's table has it (the same check a real analyst's choice passes); else None.
    Nothing else from the gold rule is used."""
    choice = gold_logsource(gold)
    return {"logsource": choice} if choice and on_table(choice, table) else None


def _result_of(events) -> dict:
    result = None
    for event in events:
        if event.get("event") == "result":
            result = event["data"]
    if result is None:
        raise RuntimeError("the pipeline stream ended without a result")
    return result


def run_oracle_case(agent, case: dict, config: dict, no_web_enrich: bool,
                    poc_url_map: dict = None, table: dict = None) -> tuple:
    """The simulated analyst on one case (plan 5.3).

    The analysis runs once; generation then runs from it twice: arm "unreviewed" with no
    review (the automated path; nothing from the gold rule) and arm "oracle" with the gold
    log source as the analyst's choice. Each arm's row is scored against the gold rule and
    costed as the analysis plus its own generation. Returns (unreviewed row, oracle row) -
    the oracle row is None when SigmaHQ's table lacks the gold log source.
    """
    table = table if table is not None else load_logsource_table()
    review = oracle_review(case["gold"], table)
    arms = [("unreviewed", {})] + ([("oracle", review)] if review else [])
    rows = {}
    for arm, arm_review in arms:
        rows[arm] = _base_row(case, dict(config, arm=f"{config.get('arm', 'default')}_{arm}"))
        if arm == "oracle":
            rows[arm]["oracle_review"] = arm_review

    TELEMETRY.reset()
    started = time.time()
    analysis_calls, analysis_s = [], 0.0
    try:
        with snapshots_instead_of_network(case["url_to_path"]) as shim, \
                poc_snapshots_instead_of_network(poc_url_map or {}) as poc_shim, \
                web_enrichment_disabled(agent.client, no_web_enrich):
            checkpoint = None
            try:
                for event in agent.orchestrator.analyse_for_review(description=" ".join(case["urls"])):
                    if event.get("event") == "checkpoint":
                        checkpoint = event["data"]
            finally:
                analysis_calls = TELEMETRY.calls()
                analysis_s = time.time() - started
                for row in rows.values():
                    row["snapshots_served"] = shim.served
                    row["snapshots_missed"] = shim.missed
                    row["poc_snapshots_served"] = poc_shim.served
                    row["poc_snapshots_missed"] = poc_shim.missed
            if checkpoint is None:
                raise RuntimeError("the analysis ended without a checkpoint")

            for arm, arm_review in arms:
                row = rows[arm]
                TELEMETRY.reset()
                arm_started = time.time()
                try:
                    _record_result(row, _result_of(
                        agent.orchestrator.generate_after_review(checkpoint["state"], arm_review)), case["gold"])
                except Exception as exc:
                    _record_error(row, exc)
                calls = analysis_calls + TELEMETRY.calls()
                row["elapsed_s"] = round(analysis_s + time.time() - arm_started, 2)
                row["telemetry"] = summarise_calls(calls)
                row["llm_calls"] = [asdict(c) for c in calls]
    except Exception as exc:
        # The analysis failed: neither arm has anything to generate from.
        for row in rows.values():
            _record_error(row, exc)
            row["elapsed_s"] = round(time.time() - started, 2)
            row["telemetry"] = summarise_calls(analysis_calls)
            row["llm_calls"] = [asdict(c) for c in analysis_calls]
    return rows["unreviewed"], rows.get("oracle")


def run_oracle_cases(agent, cases: list, config: dict, no_web_enrich: bool, out_unreviewed, out_oracle,
                     poc_url_map: dict = None, table: dict = None):
    """Run the simulated analyst over the cases. A case's rows are written only when both
    arms ran with every LLM call answered; otherwise the loop stops and neither row is
    written, so rerunning resumes from that case (the harness's stop rule).
    Returns (n_ok, n_failed, stopped) as `run_cases` does."""
    table = table if table is not None else load_logsource_table()
    n_ok = n_failed = 0
    stopped = None
    for idx, case in enumerate(cases, 1):
        row_u, row_o = run_oracle_case(agent, case, config, no_web_enrich, poc_url_map, table)
        reasons = [r for r in (unmeasured_reason(row_u), unmeasured_reason(row_o) if row_o else None) if r]
        if reasons:
            stopped = (f"STOPPED at case {case['rule_id']} ({idx}/{len(cases)}): {reasons[0]}. "
                       "Neither row was written. Check the backend (VPN, SSH tunnel, "
                       "Ollama), then rerun the same command to resume from this case.")
            print("\n" + stopped)
            break

        if row_u["error"] is None and (row_o is None or row_o["error"] is None):
            n_ok += 1
        else:
            n_failed += 1
        out_unreviewed.write(json.dumps(row_u) + "\n")
        out_unreviewed.flush()
        if row_o is not None:
            out_oracle.write(json.dumps(row_o) + "\n")
            out_oracle.flush()

        def s3(row):
            logsource = (row.get("scores") or {}).get("logsource") or {}
            return logsource.get("exact_match")
        print(f"[{idx}/{len(cases)}] {case['rule_id'][:8]} {case['category']:<18} "
              f"S3 unreviewed={s3(row_u)} oracle={s3(row_o) if row_o else 'n/a (not in the table)'} "
              f"{row_u['elapsed_s']}s/{row_o['elapsed_s'] if row_o else '-'}s")
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
    parser.add_argument("--web-snapshots", default=None, metavar="FILE",
                        help="Answer the web stage's searches from this saved file (Change 45; build it with "
                             "eval/build_web_snapshots.py); nothing is sent and rule pages are dropped.")
    parser.add_argument("--arm", default="default",
                        help="Label recorded with every row, for comparing runs.")
    parser.add_argument("--github-manifest", default="eval/github_manifest.jsonl",
                        help="Snapshots of the PoC stage's GitHub fetches "
                             "(build with eval/build_poc_snapshots.py).")
    parser.add_argument("--contamination", default="eval/contamination.jsonl",
                        help="Per-case flag: does a detection rule reach the pipeline "
                             "(build with eval/flag_contamination.py).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report the case selection without calling any LLM.")
    parser.add_argument("--code", default=None, metavar="CHECKOUT",
                        help="Run an older version of the pipeline from this checkout through this "
                             "harness (eval/old_code.py), e.g. ../SigmaAssistant-may for the May code.")
    parser.add_argument("--oracle-logsource", action="store_true",
                        help="Simulated analyst (plan 5.3): one analysis per case, then generation "
                             "with no review and with the gold log source as the analyst's choice; "
                             "writes <out>_unreviewed.jsonl and <out>_oracle.jsonl.")
    args = parser.parse_args()
    web_error = web_mode_error(args.no_web_enrich, args.web_snapshots)
    if web_error:
        parser.error(web_error)
    if args.web_snapshots and args.oracle_logsource:
        parser.error("--web-snapshots is not wired into --oracle-logsource")

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
    oracle_paths = None
    if args.oracle_logsource:
        oracle_paths = (out_path.with_name(out_path.stem + "_unreviewed.jsonl"),
                        out_path.with_name(out_path.stem + "_oracle.jsonl"))
        print(f"  simulated analyst: {oracle_paths[0].name} + {oracle_paths[1].name}")

    # In the oracle mode a case is done when its unreviewed row is written (both rows
    # are written together).
    resume_path = oracle_paths[0] if oracle_paths else out_path
    done = load_done(resume_path)
    if done:
        print(f"  resuming: {len(done)} cases already in {resume_path}")

    flags_path = repo_root / args.contamination
    flags = {}
    if flags_path.exists():
        for line in flags_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                entry = json.loads(line)
                flags[entry["rule_id"]] = {"flagged": entry["flagged"], "reasons": entry["reasons"]}
    for case in cases:
        case["contamination"] = flags.get(case["rule_id"])
    n_flagged = sum(1 for c in cases if (c["contamination"] or {}).get("flagged"))
    print(f"  contamination: {n_flagged} of {len(cases)} selected cases flagged "
          f"({sum(1 for c in cases if c['contamination'] is None)} without a flag)")

    todo = [c for c in cases if c["rule_id"] not in done]
    print(f"  {len(todo)} cases to run")

    mix = defaultdict(int)
    for case in todo:
        mix[case["category"]] += 1
    print("  category mix:", dict(sorted(mix.items(), key=lambda kv: -kv[1])))

    if args.oracle_logsource:
        table = load_logsource_table()
        choosable = sum(1 for c in todo if oracle_review(c["gold"], table))
        print(f"  oracle arm: {choosable} of {len(todo)} cases have a gold log source in SigmaHQ's table")

    if args.dry_run:
        print("\nDry run: no LLM calls made.")
        return

    poc_url_map = load_github_manifest(repo_root / args.github_manifest)
    print(f"  PoC GitHub snapshots: {len(poc_url_map)} URLs from {args.github_manifest}")

    print("\nInitialising agent ...")
    if args.code:
        if args.oracle_logsource:
            raise SystemExit("--code runs the old pipeline end to end; it has no review checkpoint")
        from eval.old_code import OldCodeAgent
        agent = OldCodeAgent(code_path=args.code, no_web_enrich=args.no_web_enrich)
    else:
        # Imported late so --dry-run needs no vector store or API key.
        from backend.agent import SigmaAgent
        agent = SigmaAgent()
    client = agent.client
    config = run_config(agent, args)
    print(f"Config: {config}")
    if type(client).__name__ == "HybridLLMClient":
        print("NOTE: hybrid mode — rule generation uses the Gemini primary tier "
              "(~1 call/case, rate-limited to ~9 RPM). Every other stage is local. "
              "Set LLM_PROVIDER=ollama for a zero-cost run.")

    started_all = time.time()
    if oracle_paths:
        with open(oracle_paths[0], "a", encoding="utf-8") as out_u, \
                open(oracle_paths[1], "a", encoding="utf-8") as out_o:
            n_ok, n_failed, stopped = run_oracle_cases(agent, todo, config, args.no_web_enrich,
                                                       out_u, out_o, poc_url_map)
    else:
        with open(out_path, "a", encoding="utf-8") as out_file:
            n_ok, n_failed, stopped = run_cases(agent, todo, config, args.no_web_enrich, out_file,
                                                poc_url_map, args.web_snapshots)

    elapsed = time.time() - started_all
    print(f"\n--- Done in {elapsed/60:.1f} min ---")
    print(f"  succeeded: {n_ok}")
    print(f"  failed   : {n_failed}")
    print(f"  output   : {out_path}")
    if stopped:
        # Non-zero, so a wrapper can tell "stopped early" from "finished".
        print("\n" + stopped)
        raise SystemExit(2)
    if oracle_paths:
        print("\nCompare the arms with: .venv/bin/python eval/compare_runs.py "
              f"{os.path.relpath(oracle_paths[0], repo_root)} {os.path.relpath(oracle_paths[1], repo_root)}")
        return
    print("\nSummarise with: .venv/bin/python eval/summarise.py " + str(args.out))


if __name__ == "__main__":
    main()
