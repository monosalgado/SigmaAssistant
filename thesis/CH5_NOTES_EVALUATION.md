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

Last updated 2026-09-09.

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

`[UNMEASURED]` **Token extraction has never been verified against a live API response.**
The field names were confirmed offline via `model_fields` on the SDK's response type,
but no real Gemini call has been observed. **The first live run must assert
`summary()["calls_without_token_data"] == 0`.** If it is non-zero, extraction is broken
and every cost number is void.

---

## 5.5 The runner (`eval/run_eval.py`, 389 lines, 19 tests)

### Core principle `[DESIGN]`
The runner drives the **real production pipeline** — `orchestrator.run_sync`
(`orchestrator.py:122`) — not a reimplementation. It substitutes only the **two sources
of non-determinism**, each at its boundary:

1. **Network fetches** → `snapshots_instead_of_network` swaps the `requests` reference
   *inside* `backend.pipeline.stage_preprocess` for a shim serving frozen snapshots.
2. **Live web search** → `web_enrichment_disabled` stubs `client.web_search`.

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

### Summariser (`eval/summarise.py`, 172 lines, 21 tests)
Prints every metric with its own n, next to its null baseline. Accepts one file
(single arm) or two (A/B delta table).

---

## 5.6 Cost of running this — must be planned before spending `[DESIGN]`

**Corrects an earlier assumption that "cost is time, not tokens."** That is false in the
default HYBRID configuration. Per-stage tier attribution (verified, commit `cccbddc`):
only **economy-tier** calls reach the local Ollama box. `attack_vector`, `analysis` and
`generation` all use the **Gemini primary tier**.

`[UNMEASURED, ESTIMATE]` ≈3 primary calls/case → ≈900 primary calls for a full 303-case
run, rate-limited at 9 RPM. **Do not state this as fact in the thesis** — it is an
estimate, and estimates in this project have run consistently optimistic.

For a genuinely zero-cost run set `LLM_PROVIDER=ollama` (requires VPN + the lab Spark).

### Commands
```bash
.venv/bin/python eval/run_eval.py --sample 60 --seed 0 --arm baseline \
    --out eval/results/baseline.jsonl --no-web-enrich
.venv/bin/python eval/summarise.py eval/results/a.jsonl eval/results/b.jsonl
```

### First live run — mandatory assertions `[DESIGN]`
1. `calls_without_token_data == 0` → else token extraction is broken, cost numbers void
2. `snapshots_missed == 0` → else the harness is silently degrading inputs

Non-zero in either case means the run is **not** a valid result, regardless of how the
scores look.

---

## 5.7 Status — what exists vs. what is claimed

| Component | State |
|---|---|
| Dataset (303 cases, frozen snapshots) | built, crawled, verified |
| Scorers S1–S5 | built, 28 tests, self-comparison + null baseline done |
| Telemetry | built, 17 tests, **token extraction unverified against live API** |
| Runner + summariser | built, 40 tests, dry run = 303 cases |
| **Any actual result** | **none — zero evaluation runs have been executed** |

Full suite: `[MEASURED] 2026-09-09` **85 passed in 0.32s**, fully offline
(`.venv/bin/python -m pytest tests/ -q`).

`[DISCLOSE]` **Changes 1–3 all landed with their effect on output quality unmeasured**,
including A3 (full-corpus ingestion), which may be neutral or harmful. The evaluation
harness was built *after* those changes specifically so the claim "these fixes helped"
can be tested rather than asserted. Until a run happens, the thesis cannot claim they
helped. Write them as *defects identified by code audit*, not as *improvements*, until
there are numbers.

### Blocked on
Lab Spark (Ollama economy tier) unreachable — the admin added firewall rules that
dropped access. `[MEASURED]` SSH port 22 **times out** rather than refusing, which is a
DROP signature, not an auth failure. VPN, routing and SSH key all verified working.
Waiting on the admin. Note the VPN pool is dynamic (10.247.x.x), so a single-IP allowlist
will not survive reconnects.

---

## 5.8 Open items for Chapter 5

- [x] ~~Decide and apply the renumbering~~ DONE 2026-09-09 — S/R/C applied across
      outline, scorers, summariser, telemetry and tests. `33`→`31` also fixed.
- [ ] Build a **naive baseline arm** (most-common logsource, no LLM) — a stronger
      comparator than the null control alone
- [ ] Decide per-category vs. weighted reporting given the process_creation skew
- [ ] Confirm k≥5 seeds is affordable at ~900 primary calls/full run, or reduce scope
      and say so
- [ ] Ablations A1–A7 from `OUTLINE.md` are **not** yet wired to the runner (`--arm` is
      currently only a label written into the output rows)
- [ ] Runtime metrics R1/R2 (detonation, Zircolite/EVTX) — novelty claim 1, unbuilt
- [ ] S6 backend compilability — automatable and cheap, but not implemented
