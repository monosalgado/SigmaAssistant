#!/usr/bin/env python3
"""Web enrichment, step 1: what does Ollama's web search return for our reports? (user 2026-10-06: "Do the probe";
plan fixed in the log before any query)

The web enrichment stage has been a silent no-op since the pipeline went all-local. For the 60 tuning cases this probe
sends two queries to `POST https://ollama.com/api/web_search` (the key from `.env`, never printed or saved):
- stage: exactly what the stage would send - the report preprocessed offline from its snapshots, then
  `WebEnrichStage._build_search_query`;
- cve:   the CVE IDs the report's text mentions (up to 3, most frequent first), when it mentions any.
Per result it flags the case's own page, a detection-rule site (fixed list), Sigma rule text, and a gold leak (the gold
rule's id or title), and counts the human rule's values (>= 6 characters) and techniques that the report lacks and a
result holds. Only the query leaves the machine. Raw results go to eval/web_snapshots/ (gitignored, reused on a rerun:
a saved query is not sent again); the measures to eval/results/web_probe_tuning60.json.

Usage:
    .venv/bin/python eval/probe_web_search.py
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import statistics
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.diagnose_detection import grounded  # noqa: E402

ENDPOINT = "https://ollama.com/api/web_search"
MAX_RESULTS = 5
MIN_VALUE_CHARS = 6
# The free account's hourly limit (first run: 25 searches, then HTTP 429): wait and ask again, at most 4 hours per stop.
LIMIT_WAIT_S = 600
LIMIT_WAIT_MAX_S = 4 * 3600
RAW_PATH = REPO / "eval/web_snapshots/probe_tuning60.jsonl"
OUT_PATH = REPO / "eval/results/web_probe_tuning60.json"
# Detection-rule publishers (host, path prefix), fixed before any query.
RULE_SITES = (("github.com", "/sigmahq/"), ("sigma.nasbench.dev", ""), ("detection.fyi", ""), ("socprime.com", ""),
              ("uncoder.io", ""), ("research.splunk.com", ""), ("github.com", "/splunk/security_content"),
              ("github.com", "/elastic/detection-rules"))
FLAGS = ("own_page", "rule_site", "sigma_text", "gold_leak", "gold_leak_id")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# --- a result's flags -------------------------------------------------------------------------------------------------

def _host_path(url: str) -> tuple:
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = (parsed.hostname or "").lower()
    host = host[4:] if host.startswith("www.") else host
    return host, parsed.path.lower()


def norm_url(url: str) -> str:
    host, path = _host_path(url)
    return host + path.rstrip("/")


def domain(url: str) -> str:
    return _host_path(url)[0]


def is_own_page(url: str, case_urls: list) -> bool:
    return norm_url(url) in {norm_url(u) for u in case_urls}


def is_rule_site(url: str) -> bool:
    host, path = _host_path(url)
    return any((host == h or host.endswith("." + h)) and path.startswith(p) for h, p in RULE_SITES)


def has_sigma_text(content: str) -> bool:
    text = (content or "").lower()
    return all(f"{key}:" in text for key in ("logsource", "detection", "condition"))


def gold_leak(result: dict, gold_rule: dict) -> bool:
    haystack = " ".join(str(result.get(k) or "") for k in ("title", "url", "content")).lower()
    marks = [str(gold_rule.get(k) or "").strip().lower() for k in ("id", "title")]
    return any(m and m in haystack for m in marks)


def gold_leak_by_id(result: dict, gold_rule: dict) -> bool:
    """The precise leak: the gold rule's `id` (a title can also be a phrase of the report itself)."""
    return gold_leak(result, {"id": gold_rule.get("id")})


# --- what the results add that the report lacks -----------------------------------------------------------------------

def values_added(gold_values: set, report_text: str, contents: list, min_chars: int = MIN_VALUE_CHARS) -> tuple:
    """The gold rule's values (`scorers.extract_detection_values` pairs) judged absent from the report, and those of
    them some result's content holds (`diagnose_detection.grounded`)."""
    lacking = {v for _, v in gold_values if grounded(v, report_text, min_chars) is False}
    added = {v for v in lacking if any(grounded(v, c, min_chars) for c in contents)}
    return lacking, added


def _mentions(technique: str, text: str) -> bool:
    return re.search(rf"\b{re.escape(technique)}(?![\d.]\d|\d)", text or "", re.IGNORECASE) is not None


def techniques_added(gold_techniques: set, report_text: str, contents: list) -> tuple:
    lacking = {t for t in gold_techniques if not _mentions(t, report_text)}
    added = {t for t in lacking if any(_mentions(t, c) for c in contents)}
    return lacking, added


def cve_query(text: str) -> Optional[str]:
    found = [m.upper() for m in _CVE.findall(text or "")]
    if not found:
        return None
    counts, first = Counter(found), {}
    for i, cve in enumerate(found):
        first.setdefault(cve, i)
    return " ".join(sorted(counts, key=lambda c: (-counts[c], first[c]))[:3])


# --- the request ------------------------------------------------------------------------------------------------------

def search(query: str, key: str, session=None, max_results: int = MAX_RESULTS, timeout: float = 60) -> dict:
    """One query. Never raises; the record holds the status, seconds, results and an error, never the key."""
    if session is None:
        import requests
        session = requests
    started = time.monotonic()
    try:
        response = session.post(ENDPOINT, json={"query": query, "max_results": max_results},
                                headers={"Authorization": f"Bearer {key}"}, timeout=timeout)
        status = response.status_code
        try:
            body = response.json()
        except ValueError:
            body = {}
        results = [{"title": r.get("title", ""), "url": r.get("url", ""), "content": r.get("content", "")}
                   for r in (body.get("results") or [])] if status == 200 else []
        error = None if status == 200 else str(body.get("error") or f"HTTP {status}")[:300]
    except Exception as exc:  # noqa: BLE001 - recorded, not raised
        status, results, error = None, [], f"{type(exc).__name__}: {exc}"[:300]
    return {"status": status, "seconds": round(time.monotonic() - started, 2), "results": results,
            "error": error.replace(key, "<key>") if error and key else error}


def needs_query(saved: Optional[dict], offline: bool = False) -> bool:
    """A query is sent unless an answer is saved; a saved error (e.g. the hourly limit) is asked again. Offline,
    nothing is sent."""
    return not offline and (saved is None or bool(saved.get("error")))


def is_hourly_limit(record: dict) -> bool:
    return record.get("status") == 429 and "hourly request limit" in str(record.get("error") or "")


# --- the run ----------------------------------------------------------------------------------------------------------

def _preprocess(case: dict, url_map: dict) -> tuple:
    """The case's `preprocessed` context (for the stage's query) and the text the model reads (as
    `diagnose_detection._case_text`)."""
    from backend.pipeline.stage_preprocess import PreprocessStage
    from eval.count_example_copies import github_bodies, model_input
    from eval.run_eval import snapshots_instead_of_network
    with snapshots_instead_of_network(case["url_to_path"]), contextlib.redirect_stdout(io.StringIO()):
        ctx = PreprocessStage(None, "").run({"original_query": " ".join(case["urls"]), "history": [],
                                             "media_file": None})
    text = ctx["preprocessed"]["combined_text"]
    return ctx["preprocessed"], model_input(text, github_bodies(text, url_map))


def stage_query(preprocessed: dict) -> str:
    from backend.pipeline.stage_web_enrich import WebEnrichStage
    return WebEnrichStage(None, "")._build_search_query(preprocessed)


def measure(record: dict, case: dict, gold: dict, report_text: str) -> dict:
    from eval.scorers import extract_detection_values, extract_techniques
    results = record["results"]
    flags = [{"domain": domain(r["url"]), "chars": len(r["content"] or ""), "own_page": is_own_page(r["url"], case["urls"]),
              "rule_site": is_rule_site(r["url"]), "sigma_text": has_sigma_text(r["content"]),
              "gold_leak": gold_leak(r, gold), "gold_leak_id": gold_leak_by_id(r, gold)} for r in results]
    clean = [r["content"] for r, f in zip(results, flags) if not (f["gold_leak"] or f["rule_site"] or f["sigma_text"])]
    values = extract_detection_values(gold.get("detection"))
    techniques = extract_techniques(gold.get("tags"))
    v_lacking, v_added = values_added(values, report_text, [r["content"] for r in results])
    _, v_added_clean = values_added(values, report_text, clean)
    t_lacking, t_added = techniques_added(techniques, report_text, [r["content"] for r in results])
    _, t_added_clean = techniques_added(techniques, report_text, clean)
    return {"status": record["status"], "seconds": record["seconds"], "error": record["error"], "results": flags,
            "urls": [r["url"] for r in results],
            "values_lacking": len(v_lacking), "values_added": len(v_added), "values_added_clean": len(v_added_clean),
            "techniques_lacking": len(t_lacking), "techniques_added": len(t_added),
            "techniques_added_clean": len(t_added_clean)}


def summarise(measures: list) -> dict:
    answered = [m for m in measures if m["status"] == 200]
    flat = [f for m in answered for f in m["results"]]
    out = {"queries": len(measures), "answered": len(answered), "errors": len(measures) - len(answered),
           "with_results": sum(1 for m in answered if m["results"]),
           "results": len(flat), "median_seconds": statistics.median([m["seconds"] for m in answered]) if answered else None}
    for flag in FLAGS:
        out[flag] = {"results": sum(f[flag] for f in flat), "cases": sum(any(f[flag] for f in m["results"]) for m in answered)}
    for kind in ("values", "techniques"):
        out[kind] = {"lacking": sum(m[f"{kind}_lacking"] for m in answered),
                     "added": sum(m[f"{kind}_added"] for m in answered),
                     "added_clean": sum(m[f"{kind}_added_clean"] for m in answered),
                     "cases_added_clean": sum(1 for m in answered if m[f"{kind}_added_clean"])}
    out["domains"] = dict(Counter(f["domain"] for f in flat).most_common(15))
    return out


def _load_raw(path: Path) -> dict:
    saved = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                saved[(r["rule_id"], r["variant"])] = r
    return saved


def main(argv: list = None) -> int:
    import argparse

    import yaml
    from dotenv import load_dotenv

    from eval.run_eval import load_cases, load_github_manifest, stratified_sample
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--offline", action="store_true", help="summarise the saved answers; send nothing")
    args = parser.parse_args(argv)
    load_dotenv(REPO / ".env")
    key = os.getenv("OLLAMA_API_KEY", "").strip()
    if not key and not args.offline:
        print("OLLAMA_API_KEY is not set in .env")
        return 1
    with contextlib.redirect_stdout(io.StringIO()):
        cases = stratified_sample(load_cases(REPO / "eval/manifest.jsonl", REPO, 2000), 60, 0)
    url_map = load_github_manifest(REPO / "eval/github_manifest.jsonl")
    RAW_PATH.parent.mkdir(parents=True, exist_ok=True)
    saved = _load_raw(RAW_PATH)
    measures, errors_in_a_row = {"stage": [], "cve": []}, 0
    offline = {"stage_has_cve": 0, "report_has_cve": 0, "planned": {"stage": 0, "cve": 0}}
    for n, case in enumerate(cases, 1):
        preprocessed, text = _preprocess(case, url_map)
        gold = yaml.safe_load((REPO / case["rule_path"]).read_text(encoding="utf-8")) or {}
        queries = {"stage": stage_query(preprocessed), "cve": cve_query(text)}
        offline["stage_has_cve"] += bool(_CVE.search(queries["stage"] or ""))
        offline["report_has_cve"] += queries["cve"] is not None
        for variant, query in queries.items():
            if not query:
                continue
            offline["planned"][variant] += 1
            record = saved.get((case["rule_id"], variant))
            if needs_query(record, args.offline):
                if errors_in_a_row >= 3:
                    continue
                time.sleep(1)
                record = search(query, key)
                waited = 0
                while is_hourly_limit(record) and waited < LIMIT_WAIT_MAX_S:
                    print(f"  hourly search limit reached; waiting {LIMIT_WAIT_S // 60} min "
                          f"({waited // 60} min waited so far)")
                    time.sleep(LIMIT_WAIT_S)
                    waited += LIMIT_WAIT_S
                    record = search(query, key)
                if record["error"] and not is_hourly_limit(record):
                    time.sleep(10)
                    record = search(query, key)
                errors_in_a_row = errors_in_a_row + 1 if record["error"] else 0
                record = {"rule_id": case["rule_id"], "variant": variant, "query": query, **record}
                with RAW_PATH.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
                status = record["status"] if not record["error"] else f"{record['status']} {record['error'][:60]}"
                print(f"  {n:>2}/60 {variant:5} {status}  {len(record['results'])} results  {record['seconds']} s  "
                      f"{query[:70]}")
            if record is None:
                continue
            measures[variant].append({"rule_id": case["rule_id"], "query": query, **measure(record, case, gold, text)})
    if errors_in_a_row >= 3:
        print("stopped: 3 errors in a row (saved queries are kept; rerun to continue)")
    summary = {"cases": len(cases), "offline": offline,
               "variants": {v: summarise(m) for v, m in measures.items()}, "per_query": measures}
    OUT_PATH.write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    print(f"\n{len(cases)} cases; the stage's query holds a CVE ID in {offline['stage_has_cve']}; the report mentions "
          f"one in {offline['report_has_cve']}")
    for variant, s in summary["variants"].items():
        print(f"\n{variant}: {offline['planned'][variant]} planned, {s['queries']} asked, answered {s['answered']}, errors {s['errors']}, with results "
              f"{s['with_results']}, results {s['results']}, median {s['median_seconds']} s")
        for flag in FLAGS:
            print(f"  {flag:10} {s[flag]['results']:>3} results in {s[flag]['cases']:>2} cases")
        for kind in ("values", "techniques"):
            k = s[kind]
            print(f"  human {kind} the report lacks: {k['lacking']}; a result holds {k['added']} "
                  f"(without leaks, rule sites, Sigma text: {k['added_clean']}, in {k['cases_added_clean']} cases)")
        print(f"  domains: {s['domains']}")
    print(f"\n-> {OUT_PATH.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
