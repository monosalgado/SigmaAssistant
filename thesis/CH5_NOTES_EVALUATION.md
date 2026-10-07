# Chapter 5 — Evaluation Methodology: working notes

**Purpose.** Raw material for writing Chapter 5. Not prose. Every number here was
measured on this machine; the command that produced it is given so it can be re-run.
Chronological record of *how* each piece was built is in `ENGINEERING_LOG.md` —
this file is organised by *topic* instead, so it can be written from directly.

**Reading rule.** Every claim below is tagged:
- `[MEASURED]` — a number produced by running something. Date given.
- `[DESIGN]` — a decision made, with its justification.
- `[UNMEASURED]` — not yet known. Do not write these as facts.
- `[DISCLOSE]` — a limitation that must appear in the thesis.

Last updated 2026-09-23. **Since 2026-09-09:** the first real run exists (baseline v1,
n=60, 2026-09-19), and running it exposed five ways the harness could produce wrong but
normal-looking results — each now guarded (§5.9). The measured *results* live in
`CH6_NOTES_RESULTS.md`; limitations are collected in `CH7_NOTES_LIMITATIONS.md`.

---

## 5.0 Metric numbering — RESOLVED 2026-09-09

### The problem that existed
Three files numbered the same metrics differently. Not two — **three**:

| ID | `OUTLINE.md` said | `eval/scorers.py` did | `backend/telemetry.py` did |
|---|---|---|---|
| E3 | backend compilability | **logsource match** | — |
| E5 | detection efficacy (Zircolite) | **detection field overlap** | — |
| E6 | false-positive rate | — | **cost** |
| E7 | cost **and** latency | — | **latency** |

Four IDs meant different things depending on which file you read. Left alone, the
thesis would have contradicted its own source code in a way an examiner can grep for.

### The resolution `[DESIGN]` — applied
Three families, replacing E0–E7 entirely:

- **S — Static.** Offline, from rule text alone. *Built (S1–S5).*
  S1 validity · S2 validator issues · S3 logsource · S4 ATT&CK · S5 detection fields ·
  S6 backend compilability *(not built)*
- **R — Runtime.** Needs detonated telemetry. *Not built — novelty claim 1.*
  R1 detection efficacy (TPR) · R2 false-positive rate
- **C — Cost.** *Built.* C1 tokens/cost per rule · C2 latency per rule per tier

**Why `R` and not `D`:** the first draft of these notes proposed D1–D2 for the dynamic
family. That was wrong — `OUTLINE.md` already uses **D1–D4 for the datasets**
(D1 Holdout, D2 Temporal, D3 Detonation, D4 Benign). Using D for metrics as well would
have replaced one collision with another. Caught before it was applied.

**Why families beat patched numbers:** the S/R split *is* the honest status of the
project — the static half is finished, the runtime half is the headline claim and is
unbuilt. A reader sees that from the IDs alone, and the obvious defense question
("why are there no numbers for E5?") is answered structurally: R1 requires the
detonation lab.

**Cost of the change `[MEASURED]`:** near zero. The E-numbers appeared only in
comments, docstrings and print labels — the data keys were already semantic
(`validity`, `logsource`, `attack`, `detection_fields`; `validity_rate`,
`logsource_exact`, `attack_f1`, `detection_f1`). No JSONL schema change, no test logic
change, 85 tests still pass.

Applied to: `OUTLINE.md` §5 and §6.1, `eval/scorers.py`, `eval/summarise.py`,
`backend/telemetry.py`, `tests/test_eval_scorers.py`, `tests/test_eval_summarise.py`.
`ENGINEERING_LOG.md` entries were **deliberately not rewritten** — a dated log that is
edited retroactively stops being evidence. A new entry records the change instead.

### Separate correction, also applied
`OUTLINE.md` said pySigma has **33 validator classes** in two places. `[MEASURED]
2026-09-09` the real count is **31**:
```
.venv/bin/python -c "from sigma.validators.core import validators; print(len(validators))"
# 31        (pySigma 0.11.23)
```

---

## 5.1 Dataset construction

### The problem the outline correctly identified
`OUTLINE.md` warns: SigmaHQ rules are not paired with source CTI, and synthesising a
CTI report *from* a rule leaks the rule's own fields into the input, making results
meaningless. It concludes D1 "requires hand-built real CTI→rule pairs."

### The solution actually used `[DESIGN]`
Sigma rules carry a `references:` field — URLs to the CTI the human author worked from.
That is a **real, human-made CTI→rule pair**, already present in the corpus, requiring
no synthesis and no hand-labelling. The input is the analyst's source document; the
output is the analyst's rule.

This defeats the leakage trap: the CTI is written by a third party who had never seen
the Sigma rule. Nothing about the rule's field names or structure is embedded in it.

**Write this up as a methodological contribution, not an implementation detail.** It is
a cheap, general, reusable way to build CTI→rule evaluation pairs, and it is the reason
this evaluation exists at all.

### Source corpus `[DESIGN]`
`rules-emerging-threats/` from the SigmaHQ repo. Chosen because `[MEASURED]` it has
**0 of 437 rules overlapping the ingested RAG index** — the system has never retrieved
any of them, so they are a genuine held-out set with respect to *our retrieval*.
`[DISCLOSE]` This says nothing about **pretraining** contamination — SigmaHQ is public
on GitHub and these rules are very likely in the base models' training data. This is
disclosed, not engineered around. It biases results **optimistically**; treat absolute
scores as upper bounds and rely on *between-arm deltas*, which the contamination
affects roughly equally.

### The funnel `[MEASURED] 2026-09-09`
Produced by `eval/build_snapshots.py`, recorded in `eval/manifest.jsonl` (437 entries).

| Stage | Count | Lost | Why |
|---|---|---|---|
| Rules in `rules-emerging-threats/` | 437 | — | |
| With ≥1 non-walled reference URL | 368 | −69 | refs are all login/JS-walled hosts |
| With ≥1 successfully fetched snapshot | 341 | −27 | dead links, timeouts, non-200 |
| With ≥2000 chars extracted text | **303** | −38 | page fetched but near-empty after extraction |

`[DESIGN]` The ≥2000-char floor exists because a page that extracts to a few hundred
characters is a JS shell or a cookie wall, not CTI. Feeding it in would measure the
model's ability to hallucinate from nothing, which is not the research question.

Walled hosts excluded by construction (`WALLED_HOSTS` in `build_snapshots.py`):
twitter.com, x.com, virustotal.com, any.run, etc. — these require auth or execute JS,
so `requests.get` returns a shell regardless.

### Snapshot corpus properties `[MEASURED] 2026-09-09`
```
.venv/bin/python -c "
import pathlib,sys; sys.path.insert(0,'.')
from eval.run_eval import load_cases
cases = load_cases(pathlib.Path('eval/manifest.jsonl'), pathlib.Path('.'), 2000)
..."
```
- **303 usable cases**, 17 logsource categories
- extracted text per case: **min 2083 / median 18842 / max 79018** chars
- reference URLs per case: min 1 / median 1 / max 3
  (capped at 3 to match production `stage_preprocess.py:32`, `urls[:3]`)
- **232 / 303** carry an `attack.tXXXX` tag → S4 is defined for 232, undefined for 71
- **7 / 303** are keyword-only rules (no field names in `detection`) → S5 undefined
- snapshots on disk: ~158 MB, **gitignored**; `manifest.jsonl` (520 KB) is committed

`[DISCLOSE]` Category distribution is heavily skewed and this must be stated:

| category | n | | category | n |
|---|---|---|---|---|
| process_creation | 123 | | registry_event | 6 |
| webserver | 54 | | ps_script | 4 |
| file_event | 36 | | registry_add | 2 |
| *(none)* | 33 | | dns_query | 2 |
| proxy | 17 | | firewall, file_delete, create_remote_thread, dns, appliance, process_access | 1 each |
| registry_set | 10 | | | |
| image_load | 10 | | | |

Consequence: an unweighted mean over all cases is ~40% a statement about
`process_creation` alone. Report **per-category** results, or weight, or both.

### Robots.txt — a decision that must be defended `[DISCLOSE]`
The first crawl applied a robots.txt check that I added on my own initiative. It
silently removed 154 URLs and ~48 rules, **concentrated in the highest-quality CTI
sources** (rapid7, crowdstrike, thedfirreport). Re-running with `--ignore-robots`
recovered the corpus from 250 → **303** cases.

Both datasets were retained. Justification for using the 303-case version, ordered
strongest first — **lead with 1, not 4**:
1. The pages are public, non-authenticated, and already retrieved once by the rule's
   own human author; no access control is being circumvented.
2. Crawl volume is trivial (hundreds of GETs, one-time, cached) — no service impact.
3. Snapshots are stored locally and never redistributed; only the manifest is published.
4. The production pipeline performs no robots check either, so honouring it in eval
   would evaluate a *different system* than the one shipped. **This is the weakest
   argument — it justifies consistency, not the underlying behaviour. Do not lead
   with it.**
5. Excluding the best CTI sources would bias the benchmark toward low-quality inputs.

An examiner may still press on this. The honest answer is that robots.txt governs
crawler politeness, not copyright or access, and the retained snapshots are a private
research cache.

### The PoC stage's GitHub fetches are frozen too `[DESIGN]` (added 2026-09-23)
- The PoC stage fetches up to 3 GitHub files and 2 gists linked anywhere in the text.
  Until 2026-09-23 these went to the live network during evaluation, outside the page
  snapshots (defect 16, §5.9).
- `[MEASURED] 2026-09-23` 43 / 303 cases (10 / 60 in the sample) trigger such fetches:
  72 file + 9 gist fetches, 45 + 5 unique URLs.
- Frozen the same way as the pages: `eval/build_poc_snapshots.py` fetches each URL once;
  `eval/github_manifest.jsonl` (committed) records status, size, SHA-256 and time;
  bodies live in gitignored `eval/snapshots/github/`. 40 stored (575 KB), 10 recorded as
  404 and replayed as 404. The stage and the builder share one function
  (`github_fetch_targets`), so what is stored is exactly what the stage asks for.
- `[DISCLOSE]` Link rot is real and measurable: **10 of the 45 linked GitHub files had
  already disappeared** when first measured. An unfrozen run would get a different input
  month to month.
- Log: Change 17 (`c6c1842`).

### Contamination — a detection rule already in the input `[MEASURED]` `[DISCLOSE]` (added 2026-09-23)
- In some cases a detection rule reaches the pipeline, so the task is partly "adapt the
  rule that is already there". Not a product defect (an analyst's source containing a
  rule is fine to read); a **threat to the evaluation's validity**.
- Three routes, `[MEASURED] 2026-09-23`, all 303 cases / sample of 60:

  | Route | 303 | 60 |
  |---|---|---|
  | The PoC stage downloads a rule-like file (SigmaHQ rules, Rapid7's own Sigma rule for CVE-2024-3400, DFIR Report Sigma rules, Sentinel detections, a nuclei template) | 13 | 4 |
  | An input URL is itself a rule file or rule repository | 10 | 1 |
  | A Sigma rule is printed in the page text | 7 | 1 |
  | **Any** | **23 (7.6%)** | **5** |

- `[DESIGN]` Handling chosen by the user: **keep, flag, report separately**, headline on
  the clean cases. Dropping would lose data and change the sample; disclosing only would
  leave "did the input contain the answer?" without a measured answer.
- `[DESIGN]` Definition in one pure function (`eval/contamination.py`), each reason
  recorded with its evidence (the URL or file). Committed list of all 303 cases with
  reasons: `eval/contamination.jsonl`. The summariser prints all / clean / flagged.
- `[DISCLOSE]` The definition is a heuristic and an **upper bound**: the `.yml` criterion
  over-counts (one of the 5 sample cases downloads a YAML list of TTPs, not a rule).
- `[MEASURED]` Baseline v1 split: on the 55 clean cases every metric is within **0.008** of
  the full run (e.g. S3 0.140 vs 0.145) → **the headline does not depend on the
  contaminated cases.** The 5 flagged cases are too few to conclude anything about them.
- Log: Change 18 (`5903239`).

---

## 5.2 Scorers (`eval/scorers.py`, 301 lines, 28 tests)

`[DESIGN]` All scorers are **pure functions**: no LLM, no network, no judge model.
Deterministic and re-runnable offline. Explicitly rejected LLM-as-judge — it would make
the evaluation non-reproducible and put a model in the position of grading itself.

| ID | Metric | Oracle |
|---|---|---|
| S1 | parses via `SigmaCollection.from_yaml` | pySigma |
| S2 | validator issues, count + by severity/class | pySigma `SigmaValidator` (31 classes) |
| S3 | logsource category/product/service exact match | gold rule |
| S4 | ATT&CK technique precision/recall/F1, exact + parent-level | gold rule |
| S5 | `detection` field-name precision/recall/F1 | gold rule |

`[DISCLOSE]` (added 2026-09-26) **Until Change 33, S2 was dominated by one warning**: underscore
tactic tags copied from the rule writer's example ("Invalid MITRE ATT&CK tagging", 145 issues in
the Change 29 run). With SigmaHQ's hyphenated tags S2 fell 0.77 → 0.00 issues per rule. S2 values
from earlier runs mostly measure that convention, not rule defects.

### Two rules that shaped the implementation `[DESIGN]`

**1. Undefined ≠ zero.** `_prf()` returns `None`, never `0.0`, when a metric has no
denominator. A rule with no ATT&CK tags has *undefined* S4, not S4 = 0. Scoring it as 0
would drag every aggregate down and make an arm look worse for cases it was never asked
to handle. Consequence: **every reported metric carries its own n**, and those n differ
(S4 n=232, S5 n=296, S1/S2/S3 n=303). `eval/summarise.py` prints each metric with its
own n for exactly this reason.

**2. Validator state leaks.** pySigma's core validators (duplicate-title,
identifier-collision) accumulate state across calls. Reusing one `SigmaValidator` makes
rule #2 fail because rule #1 existed. A **fresh validator is constructed per call**.
Pinned by `test_validator_state_does_not_leak_between_calls`. This is a real bug that a
naive harness would hit and would silently inflate the error rate over a run.

### S5 limitation `[DISCLOSE]`
S5 compares **field names only**, not values. A rule matching
`Image|endswith: '\evil.exe'` and one matching `Image|endswith: '\good.exe'` score
identically. Modifiers (`|contains`, `|endswith`) are stripped; `condition` is skipped.
This is pinned deliberately by `test_field_names_match_even_when_values_differ` so the
limitation is visible in the test suite rather than discovered by an examiner.
S5 measures *"did it look at the right telemetry fields"*, which is worth measuring, but
it is **not** semantic equivalence and must not be described as such.

---

## 5.3 Scorer validation — the part that makes results credible

`[DESIGN]` A scorer that always returns 1.0 would look like a great result. Two controls
were run *before* any real generation, so no number could be rationalised after the fact.

### Control A — self-comparison (upper bound) `[MEASURED] 2026-09-09`
Score each gold rule against **itself**. A correct scorer must return perfect.
- 0 parse failures · 0 logsource mismatches · **264/264 ATT&CK F1 = 1.0**

### Control B — mismatched pairs (null / chance baseline) `[MEASURED] 2026-09-09`
Score each gold rule against a **different, randomly paired** gold rule (n=341, seed 0).
This is what "no real capability" looks like — the floor any result must beat.

| Metric | Null baseline | Note |
|---|---|---|
| logsource exact match | **17.3%** | high because `process_creation` dominates — guessing it is often right |
| detection field F1 | **mean 0.133** (median 0.0) | mean > median: a few field names are near-universal |
| ATT&CK technique F1 (exact) | **mean 0.092** (median 0.0) | |

These are hardcoded in `eval/summarise.py` as `NULL_BASELINES` and printed next to every
result, with a `<-- at/below chance` marker.

**This is the single most defensible thing in the evaluation and should be foregrounded
in the chapter.** It converts "the system got 45% logsource accuracy" — which means
nothing on its own — into "45% against a 17.3% chance floor." The 17.3% figure also
pre-empts the obvious examiner question *"isn't that just because most rules are
process_creation?"* — yes, partly, and it is quantified.

`[DISCLOSE]` Control B is a *discrimination* control, not a competitive baseline. It
shows the scorer distinguishes matched from mismatched pairs. It is not a rival system.
A naive-baseline arm (e.g. always emit the most common logsource, no LLM) would be a
stronger comparator and is not yet built. `[UNMEASURED]`

---

## 5.4 Cost & latency instrumentation (`backend/telemetry.py`, 220 lines, 17 tests)

### Why it lives inside the clients `[DESIGN]`
A non-invasive wrapper was attempted first and **is impossible**: both backends discard
the usage object before returning — `GeminiLLMClient.generate` returns `response.text`,
`OllamaLLMClient.generate` returns the message content. Token counts are destroyed at
the source, so capture has to happen inside each client. Three call sites instrumented
in `llm_client.py`. `HybridLLMClient` deliberately **not** instrumented — it delegates,
so instrumenting it would double-count.

`[DESIGN]` Gemini timing starts **after** `_limiters[tier].acquire()`, so the recorded
latency is model latency, not our own rate-limiter queueing. Reporting queue time as
model latency would misattribute a self-imposed cost to the provider.

### The thinking-token trap `[DESIGN]` — most important finding here
`gemini-2.5-flash` is a **thinking model**. Its usage metadata has three separate counts:
`prompt_token_count`, `candidates_token_count`, `thoughts_token_count`.

**`thoughts_token_count` is billed at the output rate but is NOT included in
`candidates_token_count`.** The obvious implementation — `total = prompt + completion` —
therefore undercounts every primary-tier call, silently. It would have produced
systematically optimistic cost figures for **exactly the tier the thesis argues is
expensive** — i.e. it would have manufactured support for the cost-routing claim.

Fixed: `thinking_tokens` recorded as its own field, and `summary()` prefers the
provider's `total_token_count` over any derived sum. Pinned by
`test_thinking_tokens_are_not_dropped_from_the_total`.

**Worth a short passage in the thesis.** Any cost-routing paper that compares a thinking
model against a non-thinking one and derives totals by addition is understating the
thinking model's cost. This is a generalisable methodological warning.

### Same null-safety rule `[DESIGN]`
Missing token data is `None`, never 0. `summary()` exposes
`calls_without_token_data`, so a silent extraction failure surfaces as a count rather
than as a plausible-looking cheap result.

`[MEASURED]` **Ollama path verified live**: `calls_without_token_data == 0` on the first
pilot (2026-09-11) and over all 321 calls of baseline v1 (2026-09-19).
`thinking_tokens == 0` is correct for qwen3-coder:30b, which does not think.

`[UNMEASURED]` `[DISCLOSE]` **The Gemini thinking-token path was never verified live.**
The key was suspended on 2026-09-11 and deleted on 2026-09-23. Unless a new key is
created, the thinking-token argument above remains a design argument, not a measurement.

### Every call records its stage `[DESIGN]` (Change 13, 2026-09-23)
Every call used to record `operation: "generate"`, so stages could only be told apart by
call order (which shifts when the PoC stage or a regeneration runs). A context variable
set in `PipelineStage.llm_call` now labels each call with its stage; the clients are
unchanged. Verified live: a stopped run reported the real failing stages.

---

## 5.5 The runner (`eval/run_eval.py`, 389 lines, 19 tests)

### Core principle `[DESIGN]`
The runner drives the **real production pipeline** — `orchestrator.run_sync` — not a
reimplementation. `[DISCLOSE]` Until Change 14 (2026-09-23) it went through
`agent.analyze_attack`, whose catch-all returned a crash as ordinary text, so crashed
cases looked like normal zero-rule rows (defect 17, §5.9). It now calls `run_sync`
directly; the web app is unchanged.

It substitutes only the **sources of non-determinism**, each at its boundary:

1. **Page fetches** → `snapshots_instead_of_network` swaps the `requests` reference
   *inside* `backend.pipeline.stage_preprocess` for a shim serving frozen snapshots.
2. **PoC GitHub fetches** (since Change 17) → `poc_snapshots_instead_of_network` does the
   same inside `stage_poc_analysis`; an unknown URL is a counted miss, never a live fetch.
3. **Live web search** → `web_enrichment_disabled` stubs `client.web_search`.

Both restore in a `finally` block; pinned by
`test_requests_restored_even_when_the_body_raises`.

`[DESIGN]` The swap targets the **module attribute**, not `requests.get` globally. This
means the production extraction path (`_extract_page_content`, the 40 000-char cap, the
`urls[:3]` slice) runs completely unmodified. What is evaluated is the shipped system,
not a copy of it — which is the difference between an evaluation and a simulation.
`test_preprocess_stage_reads_snapshot_instead_of_network` asserts this against the real
stage, not a mock.

`[DESIGN]` A missing snapshot returns **404**, never raises. The pipeline already
handles a failed fetch, so a gap degrades one case instead of aborting the run. The
count is surfaced as `snapshots_missed` per row so silent degradation is visible.

### Sampling `[DESIGN]`
**Stratified by logsource category.** A uniform random sample of 60 from a corpus that
is 40% `process_creation` would very likely contain **zero** cases from the rare
categories — and those are exactly the ones Change 2 (A3, full-corpus ingestion)
targeted. A uniform sample would structurally hide the effect being tested.

`[MEASURED]` A bug was found and fixed here: `round(len(group) * fraction)` rounded down
for every category and returned 24 when 25 were requested. Now floors with `int()`,
guarantees ≥1 per category, then tops up from a leftover pool. Verified exact for
30 / 60 / 100. Caught by `test_sample_respects_requested_size`.

`[MEASURED]` Stratified sample of 60 → process_creation 23, webserver 9, none 7,
file_event 6, proxy 3, remainder spread across the tail.

### Output `[DESIGN]`
One JSONL row per case: identifiers, config, `snapshots_served` / `snapshots_missed`,
extracted rule YAML, all scores, `telemetry`, `llm_calls`, `elapsed_s`, `error`.
Appended with `flush()` after every case and **resumable by `rule_id`** — a run that
dies at case 47 of 60 does not lose 47 cases of API spend.

### What each row records since 2026-09-23 `[DESIGN]`
- Every LLM call with its **stage** (Change 13).
- `row["pipeline"]`: the stages' intermediate results — attack vector, logsource
  suggestions, indicators, ATT&CK mappings, coverage check, review issues, and a
  **per-generation-call log** of rules produced and ids replaced (a regeneration used to
  overwrite the first call's count) (Change 15).
- `response_text` when no rule was extracted (the two zero-rule cases of baseline v1
  could not be diagnosed: only their length was kept).
- `poc_snapshots_served / _missed` (Change 17) and the case's `contamination` flag
  (Change 18).

### A case with a failed LLM call is never written `[DESIGN]` (Change 16)
Stages swallow their own failed calls, so with the backend down a case "finished" in
seconds with zero rules — and resume then skipped it (defect 12, §5.9). Now a row is
written **only if every LLM call succeeded**; otherwise the run stops at that case, names
the failed stages, and exits with status 2; rerunning resumes from that case. Verified
live (no VPN): exit 2, zero rows written.

`[DESIGN]` **Infrastructure failure vs model failure** (Change 24, 2026-09-24). The stop rule
is for the *infrastructure* — connection errors, timeouts, server errors — because a row
written then measures a broken backend, not the pipeline. A *model* failure is different: an
answer that loops and stops at the output limit (16,384 tokens; defect 19) is what the
pipeline really does on that case. Such a call is recorded `output_limited` (not failed),
the stage falls back as it would in production, and the case is written and scored. The
summariser reports "answers cut at limit" in every file. Why it matters: before Change 24 a
looping case halted the run at the same place every time (observed, case `9a2d8b3e`), and
excluding it would have biased the result in favour of the pipeline that fails on it.

### Summariser (`eval/summarise.py`)
Prints every metric with its own n, next to its null baseline; one file or two (A/B
delta table). Since 2026-09-23 also: the **gates and a citability verdict** (Change 19,
§5.6) and **all / clean / flagged** blocks for contamination (Change 18).

---

## 5.6 Cost of a run, and what makes a result file citable

### Measured cost `[MEASURED]`
- Everything runs **all-local** on `qwen3-coder:30b` (user decision, 2026-09-23; the
  Gemini key is gone anyway), so cost is time, not money.
- Baseline v1 (2026-09-19, 60 cases): **101.9 min** wall time; per case mean 102.6 s,
  **median 89.1 s**, range 38.7–320.7 s; **321 LLM calls, 2,227,584 tokens** (mean 37,126
  per case). The 4 defect-14 cases were rerun separately (7.4 min).
- After Change 12 (whole source up to 100,000 chars): the attack-vector stages alone went
  15.1 → 19.0 min (+26%) on the probe.
- `[MEASURED] 2026-09-24` Baseline v2 (same 60 cases, current pipeline): sum of per-case
  time **169 min** (mean 169.3 s, **median 142 s**); **53,803 tokens per case** (+45% on v1,
  paired). About 3 h 30 min of wall time, of which ~41 min was a network outage. **Budget
  for planning: ~2 h 50 min of compute per 60-case run** of the current pipeline, before
  any interruption.
- Superseded figures — **never cite**: "~46 s/case" (pre-defect-8 pilot), "132 s/case"
  (9 cases of an aborted run), "~900 primary calls" (the old hybrid estimate).

### The gates — computed by `summarise.check_gates` `[DESIGN]` (Change 19)
A file is citable only if every check passes:

| Check | Guards against |
|---|---|
| page snapshots all served | a case silently generated from the URL string alone (defects 8, 14) |
| PoC GitHub snapshots all served | a live fetch slipping into the run (defect 16) |
| token data on every call | incomplete cost figures |
| no failed LLM calls | a stage running on its empty default (defect 12) |
| no case-level errors | a crash (defect 17 made this blind before Change 14) |
| no suspiciously fast cases (< 30 s) | the defect-12 signature |
| no duplicate cases | a resume mishap |

Verdicts: CITABLE · CITABLE WITH CAVEATS (a check the file never recorded) · NOT CITABLE.
`[MEASURED]` baseline v1 → **CITABLE WITH CAVEATS (2)**: PoC fetches were live, and crashes
were invisible (both fixed since). The defect-12 and defect-14 evidence files → NOT
CITABLE, matching every earlier hand check.

### Run recipe `[DESIGN]` (Changes 20–21)
1. USF VPN on (the lab OpenVPN off — the two together stall).
2. `eval/preflight.py` — tunnel answers HTTP, model returns token counts, server context
   ≥ 32k (prompts reach ~25k tokens since Change 12 and the code sets no context size),
   tests pass, a 2-case smoke run is CITABLE. Stops at the first failure with the fix.
3. `eval/run_resilient.py -- <run_eval arguments>` — relaunches after a connection drop
   (exit status 2), at most 5 times.
4. `eval/summarise.py <file>` — the verdict must be CITABLE.

`[MEASURED] 2026-09-24` **First real use (baseline v2) — the guards under two real failures**
(corrected the same day from the GlobalProtect logs; log entry "Correction: … two separate
events"):
1. At case 52 of 60 one analysis call never answered (client timeout, 600 s × 3 attempts)
   while the network was up — the case's later calls succeeded. The pipeline continued on
   an empty analysis ("0 indicators, 0 TTPs") and still produced 2 rules — the exact
   defect-12 pattern — and **Change 16 refused the row** and stopped the run. Cause
   unknown; hypothesis: an unbounded generation (the client sets no `max_tokens`).
2. On the relaunch, the **VPN dropped** (13:25, keep-alive timeout — the USF gateway stopped
   answering; not a session time limit). GlobalProtect's auto-restore needs a manual gateway
   choice, so the user reconnected (13:31); the tunnel was then rebuilt by hand and the
   wrapper continued. Case 52 passed in 166 s. Result: CITABLE, all 60 rows complete.
`[DISCLOSE]` One manual intervention (the tunnel rebuild, after the user's VPN reconnect).
The wrapper's own rebuild works (0.7 s on a spare port) but has not yet recovered a run by
itself; it gives up after ~12 min, shorter than a drop that needs the user.
Worth one paragraph in the thesis: the stop rule was designed after defect 12 and here
it caught a real instance — that is the evidence it earns its place.

### One run against chance `[DESIGN]` (added 2026-09-26)
Is S3 above the chance level (0.173)? Exact binomial test, **one-sided**, alpha 0.05, with a 95%
Wilson interval, printed by `eval/summarise.py` under S3 (with the smallest k that would reach
p < 0.05). Standard library; 10 tests anchored to scipy values. `[DISCLOSE]` Pre-registered to be
applied **once**, to the final Phase 2 run; earlier values are descriptive. **Revised
2026-09-26, before any held-out result existed:** applied once to the final pipeline's
**held-out** run (next section), not to the 60 cases the changes were tuned on; test, alpha,
null and sidedness unchanged. The null is treated as fixed. Descriptive after Change 26: 14/57, CI 0.152–0.371, p = 0.104 — not yet above chance.
After Change 27: 13/56, CI 0.141–0.358, p = 0.160. After Change 28: 14/55, CI 0.158–0.383, p = 0.082.

### Comparing two runs — paired, not unpaired `[DESIGN]` (added 2026-09-24)
Two runs on the same cases must be compared **case by case**: each metric only on cases
scored in both runs; exact McNemar for S1/S3 (discordant pairs), paired bootstrap 95% CI
of the mean difference for S4/S5 and cost. Reason, measured on v1 → v2: the unpaired S4
mean rose 0.123 → 0.175, but on the same 35 cases the difference was +0.014, CI
[−0.048, +0.086]. S2–S5 are computed only on cases whose first rule parses, so a change in
*which* rules parse changes *which* cases are averaged.
Tool: `eval/compare_runs.py <A> <B>` (Change 23) — standard library only; 11 tests,
including one that reproduces the v1 → v2 comparison from the committed result files.
`[DISCLOSE]` (added 2026-09-26) **The same trap applies to counts.** The diagnosis tool's
counts ("web labels when the gold rule is not a web rule") are over cases whose first rule
parses, so their denominators differ between runs. In the Change 27 run the primary count
fell 18/48 → 14/45, but only 4 cases changed label; 2 of the 4-case drop were cases leaving
the count. Such counts are reported as counts, not tested; a paired, all-rows version would
need its own committed tool. Every denominator is quoted from the tool's output (two were
once copied from an earlier run — log, "Correction: two … denominators").
`[DESIGN]` (added 2026-09-26, Change 28) **The first measure built to avoid it:**
`eval/compare_suggestions.py` compares the analysis stage's top suggestion with the gold log
source over **all** rows — the gold comes from the manifest, not from the scored first rule —
paired, exact McNemar; a case with no suggestion counts as a miss. 9 tests.

### Two code versions, k runs each — and an older version through today's harness `[DESIGN]` (added 2026-09-29)
- **`run_eval.py --code <checkout>`** runs an older pipeline version (the May code) through today's harness: the
  old code in a worker process, today's saved pages, LLM client and call recording, row, scorer, resume and
  stop-on-failure (`eval/old_code.py`, `eval/old_code_worker.py`). Rows record which code ran.
- **`eval/compare_arms.py`**: each case's value = the mean over an arm's k runs; arms compared case by case
  (paired bootstrap CI). Primary view "as the user gets it": a first rule that does not parse counts as wrong,
  so a version that fails to parse more often is not flattered by leaving those cases out. Consistency = the
  same first-rule log source in all k runs (paired exact McNemar), plus per-stage divergence per pair of runs.
- Used for the May-vs-now rerun (k = 3, held-out 60; CH6 §6.0d). One run is one sample (CH7 items 50–51):
  a k-run design is what lets a result speak about consistency at all.

### Held-out confirmation — the answer to "did you tune on your test set?" `[DESIGN]` (added 2026-09-26)
Every Phase 2 change was found by reading failures in the 60 seed-0 cases and measured on the
same 60. The final check (plan 2.9) uses **60 cases no run has ever touched**: drawn by a
committed script (stratified, seed 0) from the 242 corpus cases absent from every result file
(61 distinct cases were ever run, in 23 files; a new seed alone would reuse 13–15 of the 60).
The list is committed before any run; nobody reads held-out outputs and no pipeline file
changes until both runs are done. Two runs on it — the final pipeline and baseline v2's code —
give a paired before/after on unseen cases, and the chance test (above) is applied there.
**Drawn 2026-09-26** (`eval/draw_heldout.py`, once; `eval/manifest_heldout.jsonl`): 60 cases —
24 `process_creation`, 12 `webserver`, 7 `file_event`, 6 service-based, 3 `proxy`, 8 others. The
pipeline was frozen first (`a6e9157`). Baseline v2's code (`5627e91`) and the final pipeline are
scored by the same, unchanged scorer. `[DISCLOSE]` baseline v2's code has no output limit: a case it
cannot finish is removed from both arms of the paired comparison and reported (rule fixed in advance).
**Done 2026-09-27** — results in CH6 §6.0. The rule was applied to two cases (one stopped six times;
one stopped three times, then finished on a fourth attempt — excluded as the rule says, decided before
any score was read, with the comparison also reported including it: same p).

### Attribution: one run per change, with one planned exception `[DESIGN]` (added 2026-09-26)
Phase 2 ran one 60-case run per change so each effect could be attributed (user, 2026-09-24).
From 2.6 on (user, 2026-09-26): 2.6 and 2.6b still run alone; defect 15's fix, 2.7, 2.8 and
the rule writer's example fix (Change 33) then share one run. Each keeps a mechanism measure counted by code (example copies, invented technique
IDs, list length and cut answers); their effect on S3–S5 is reported as joint.

## 5.6b Methods added 2026-09-29 to 2026-10-05 `[DESIGN]` (added 2026-10-05)

### The research protocol, as practised — what answers "did you tune until it looked good?"
- **Three sets, three roles.** The 60 **tuning** cases (seed 0) are where failures are read and changes designed;
  the 60 **held-out** cases (`manifest_heldout.jsonl`, drawn 2026-09-26) confirmed Phase 2; **confirmation set 2**
  (`manifest_confirm2.jsonl`, 60 cases never run, drawn 2026-09-29, only categories looked at) is spent on one
  change at a time, only after it passes a gate on the tuning set. Case-level reading of held-out or fresh cases is
  avoided, so they stay usable.
- **Plans before runs.** Every run's measures, primary metric and pass/fail gate are written into the engineering
  log before the run starts (append-only, dated); later precisions are logged before the numbers they affect exist.
- **Gate, then confirm.** A change passes to the confirmation set only if its primary moves the right way on the
  tuning set, its mechanism measure moves, and no guard drops with a 95% CI entirely below 0. Confirmation: k = 3
  runs per arm, each case's value the mean of its runs, **confirmed only if the paired 95% CI's lower bound is
  above 0**. No row is read until every run has finished.
- **Negative results are kept and the change is removed.** Changes 38 (three iterations), 40 and 41 were removed
  after failing their gate or their confirmation; their code stays in git history, their results in the log and in
  CH6 (§6.5b, §6.5c). Iterations on the tuning set are counted and disclosed (a researcher degree of freedom).
- **Frozen code for every arm.** Each arm runs from a separate checkout of a named commit with the data linked in;
  the main working tree may change, the run's code cannot.
- **Tests first, and tests that are shown to catch errors.** Every tool is written test-first and the tests are
  seen to fail; for measuring tools, deliberate bugs are planted one at a time and each must be caught (e.g. the
  evaluator: 4, the replay builder: 4, the replay scoring: 5). This caught a real bug (a variable that hid the report
  text, so every rule looked "grounded").
- **Every cited number comes from committed code**, run on committed result files; quick checks are labelled as such
  and not cited.

### Two arms on the same night `[DESIGN]` (added 2026-10-03)
P-B (CH6 §6.0c) showed the model's answers depend on the server's state: identical prompts repeat within a session
but can differ a day apart. So a change is compared against the code before it **run at the same time** (two arms
started together in two terminals), not against a run from another day. Used for Changes 40 and 41 and for the
confirmation runs. `[DISCLOSE]` Runs straddling a server restart or a connection drop are resumed per file and the
conditions are logged (2026-10-04: the shared Spark restarted mid-confirmation; the arms straddle it unequally).

### P / Pany — the analysis stage's top log-source pick `[DESIGN]` (added 2026-09-29)
**P** = the top pick equals the gold rule's log source (S3's exact match); **Pany** = it equals the gold's *or another
human-written SigmaHQ rule's for the same report* (`alternative_logsources.py`: an emerging-threats rule citing one
of the case's input URLs; a URL cited by more than 5 rules links nothing). Answers "wrong, or just different?": about
25 of 60 tuning picks match no human rule for the report. No pick = wrong. In `compare_arms.py --manifest`.
`ranking_effect.py` measured Change 38 v3's ranking step **within one run** (each row keeps the order before the
step), free of run-to-run variation.

### S5v — the value-level detection score `[DESIGN]` (added 2026-10-03; definition fixed before it scored a run)
S5 compares field names only; S5v compares the **values** a detection looks for (`scorers.score_detection_values`).
Values: every string or number, lower-cased, `*` at the ends removed, a doubled backslash read as one; field = the
name before `|`; `filter…` selections, `condition`, `timeframe` skipped. A human value is **found** when one of ours
contains it, or is contained in it and is at least half as long (under 3 characters: only when equal). Recall (any
field / same field), precision, F1. In `compare_arms.py`: **S5vu** (as the user gets it: an unparsed or valueless
rule scores 0) and S5v (parsed rules). Not a harness metric; computed post-hoc from saved rules.
**Detection diagnosis** (`diagnose_detection.py`): per case, fields missed/added, values found/missed, the best of the
case's rules; with `--grounding`, which values occur in the report's own text (pages + fetched PoC code; a leading
path separator not required; `--min-value-chars` for a sensitivity check, used at 6); for each human value in the
report that the first rule misses, how it reached the rule writer — rebuilt with the pipeline's own formatting:
as a payload pattern, as an indicator, only inside a description, on the incidental list, or never given.
`indicator_use` (`backend/pipeline/indicator_use.py`, recorded since Change 40) counts indicators the rules use;
`count_example_copies.py` counts the attack-vector prompt's inline example strings absent from the input.

### A rule evaluator, validated on real recordings `[DESIGN]` `[MEASURED]` (added 2026-10-04)
`rule_matcher.py`: pySigma parses the rule (modifiers, wildcards, `1 of`/`all of`); our matcher walks the parsed
condition per event — strings case-insensitive (`|cased` sensitive), numbers, null, `|re` with its flags, exists,
cidr, comparisons, field references, expansions, keywords anywhere; anything else "cannot evaluate", never a guess.
No new dependency (pySigma's SQLite backend was the alternative: a new dependency and more steps between rule and
verdict). **Validation** on SigmaHQ's 138 regression recordings (`validate_matcher.py`): **132 of 136 evaluable agree
on the first pass**; the 4 disagreements were checked and are recordings with more qualifying events than their
stated count; 2 have no JSON copy. Only 2 of the corpus's 303 gold rules have a recording, so the recordings
validate the evaluator but cannot score our rules.

### Synthetic replay — designed, validated, and not used `[DESIGN]` `[MEASURED]` (added 2026-10-05)
Events built from the human rules (`event_builder.py`: DNF, one event per way the rule can fire, minimal values,
nothing invented; regex or contradiction = "cannot build"), our rules scored on them (`replay.py`: hit over every
human rule for the report, any of the case's rules, lenient log-source applicability; coverage, breadth, miss
reasons, report-grounded misses). Read as a **lower bound** (a different valid rule can catch the attack through
other evidence). **Validated before use** (`validate_replay.py`, thresholds fixed first): V1 builder, V2 synthetic vs
real recordings, V3 unrelated rules quiet, V4 a known ordering (today vs the May code), V5 shuffled-rule null.
**V4 failed** (CH6 §6.5d) → by the plan, not used to score our rules. Methodological point for the chapter: **a test
built from the reference answers inherits the reference's blind spot** — here it was specific (0.17% false fires vs
real logs) but caught only 15 of 44 real "different rule, same attack" pairs.

### Web enrichment in the evaluation — saved answers, never live `[DESIGN]` (added 2026-10-07)
The web stage (Change 45) searches the live web, whose answers change and whose free account allows ~25 searches per
hour and ~50 per "session". So **each case is searched once and the answers saved** (`eval/build_web_snapshots.py`;
`eval/web_snapshots/<set>.jsonl`, local — third-party page text); every run, arm and rerun reads the same file
(`run_eval.py --web-snapshots`), which never sends a query (a missing one is recorded); the file's SHA-256 is in each
run's config. **The harness refuses to run unless the web is off or answered from a saved file** — an evaluation can
never search live. **Rule pages are dropped** in the evaluation (`exclude_rule_pages`: rule mirrors, any page with
Sigma rule text) and kept pages are checked for the gold rule's `id` (`web_effect.py`), because a found human rule would
make the score measure copying — in the assistant they are kept and listed (the user: context for the analyst).
**Disclose:** the pages were found in October 2026 for reports up to years older, so later write-ups can carry
detection knowledge that did not exist when the report came out; the measured effect is an upper bound for a brand-new
report. The probe that informed this design: CH6 §6.5f.

## 5.7 Status — what exists vs. what is claimed (2026-09-24)

| Component | State |
|---|---|
| Dataset (303 cases, frozen page + PoC snapshots) | built, verified; contamination flagged (23 cases) |
| Scorers S1–S5 | built; self-comparison + null baseline done |
| Telemetry | built; Ollama path verified live; stage labels; Gemini path never verified |
| Runner, summariser, gates, preflight, relaunch wrapper | built; offline tests |
| **Results** | **baseline v2** (n=60, 2026-09-24, **CITABLE**) = the reference; baseline v1 (citable with 2 caveats) kept for comparison — see `CH6_NOTES_RESULTS.md` |
| Paired comparison of two runs | `eval/compare_runs.py` (Change 23) |
| Logsource diagnosis | `eval/diagnose_logsource.py` (plan 2.1) |
| Two code versions, k runs each | `eval/compare_arms.py` (S3u, S5u, S5vu, P/Pany, consistency) — 2026-09-29 / 10-03 |
| Pick and detection diagnosis | `alternative_logsources.py`, `ranking_effect.py`, `diagnose_detection.py`, `count_example_copies.py` |
| Rule evaluator | `eval/rule_matcher.py`, validated 132 of 136 (`validate_matcher.py`) — 2026-10-04 |
| Synthetic replay | `event_builder.py`, `replay.py`, `validate_replay.py` — failed V4, not used (2026-10-05) |

`[MEASURED] 2026-09-24` Full suite **253 passed**, fully offline.

`[DISCLOSE]` Changes 1–3 (pySigma validation, RAG exemplar format, full-corpus ingestion)
landed **before** the harness existed, so their effect on quality is **unmeasured**.
Write them as defects identified by code audit, not as improvements.

## 5.8 Open items for Chapter 5

- [x] ~~Renumbering~~ — S/R/C applied 2026-09-09.
- [x] ~~First live run assertions~~ — replaced by `check_gates` (Change 19).
- [x] ~~Contamination handling~~ — flagged and reported separately (Change 18).
- [x] ~~Baseline v2~~ — run 2026-09-24, CITABLE (plan 1.5).
- [x] ~~Committed paired-comparison script~~ — `eval/compare_runs.py`, Change 23; reproduces v1 → v2.
- [ ] **Naive baseline arm** (most-common logsource, no LLM) — a stronger comparator than
      the null control alone.
- [ ] Per-category vs weighted reporting, given the `process_creation` skew.
- [ ] Number of seeds: at ~2 h 50 min of compute per 60-case run (measured, v2), k ≥ 5
      per arm is a real time budget — decide it, don't default to it.
- [ ] Ablations A1–A7 not wired (`--arm` is only a label); likely core: A1 (no RAG),
      A5 (single prompt vs pipeline).
- [ ] R1/R2 detonation — depends on the contributions agreed with the professor. The evaluator for it is built and
      validated (2026-10-04); the synthetic substitute failed validation (2026-10-05), so real logs are the route.
- [ ] S6 backend compilability — cheap, not built.
- [ ] **Simulated analyst (plan 5.3)** `[DESIGN]` (added 2026-09-27) — Change 34 made it
      implementable without new pipeline code: `generate_after_review(saved analysis, review)`
      generates from a saved analysis and a review, so the "analyst" can choose the **gold** log
      source (and reject techniques absent from the gold) and the rules are rescored. It shows what
      confirmation is worth *when the analyst is right* (no user study).
      **Built 2026-09-27** (`eval/run_eval.py --oracle-logsource`): per case the analysis runs
      **once**, then generation twice from it — no review (arm U) and the gold log source as the
      analyst's choice (arm O, when SigmaHQ's table has it: 58 of the 60 tuning cases). Paired
      within case, so only the decision differs; nothing else from the gold rule reaches the
      pipeline. Primary measure S5; S3 in O reported as *adherence*, not a gain (the review check
      enforces it). U against `p2g_shared60` doubles as the A/A noise floor. Measurement plan in
      `ACTION_PLAN.md` 5.3, fixed before the run. **Run 2026-09-27 (265 min, 60/60, CITABLE):
      results CH6 §6.0b.**

---

## 5.9 Validity problems found by running the evaluation `[MEASURED]`

**Write this up as a methodology finding in its own right.** Each problem made the
harness produce *wrong results that looked normal* — no error, plausible numbers. None
was visible from reading the code; all surfaced only by running it and checking the
numbers against each other. Each now has a guard and a test.

| # | Problem | How it hid | Size | Guard | Log |
|---|---|---|---|---|---|
| 14 | Snapshot lookup kept the URL `#fragment`; the pipeline strips it → 404 | the case still ran, scored, `error: None` | 4 / 60 cases, 2 with **no page at all** | normalised key on both sides | Change 10 |
| 12 | Backend unreachable → every stage swallows its failed call → "finished" row | resume then skipped the case | 14 / 21 rows of an attempt (13 in ~6 s + 1 that hung 3.6 h) | write only if every call succeeded | Change 16 |
| 17 | The agent's catch-all turned crashes into normal zero-rule rows | the case-error gate could never fire | baseline v1's 2 zero-rule cases fit a hidden crash (86-char reply; not proven) | harness calls `run_sync` directly | Change 14 |
| 16 | The PoC stage fetched GitHub live | outside the snapshot gate | 43 / 303 cases; 10 of 45 files already gone | PoC snapshots + counted misses | Change 17 |
| 18 | A detection rule already in the input | a normal, scoring case | 23 / 303 (5 / 60) | flag + separate reporting | Change 18 |

**The lesson for the chapter:** an LLM pipeline degrades gracefully by design — every
stage catches its own failure and continues on a default — and that same property makes
evaluation failures silent. The countermeasure is to count what the harness *should*
see (snapshots served, calls succeeded, crashes, contamination) and refuse to call a file
citable unless the counts are clean.
