# Engineering Log

Chronological record of every deliberate change to the system, why it was made, and how
it was verified. Feeds Chapter 4 (System Design) and Chapter 6 (Results).

Rules for this file:
- One entry per change. Newest at the bottom.
- Record the *verification* actually run, not the intent to verify.
- If something was found to be broken, record it even if not yet fixed.

---

## 2026-08-06 — Baseline established

**State of the system before any roadmap work.**

Environment
| Item | Value |
|---|---|
| Interpreter | `.venv/bin/python` — Python 3.9.6 (EOL; requires `from __future__ import annotations`) |
| System Python | 3.14.6 |
| Test framework | none installed |
| Source size | 37 files, 8,532 LOC (`.py`, `.js`, `.html`, `.css`, tracked) |
| Git | branch `main`, working tree clean at `e36b1ef` |

LLM tiers (from runtime startup banner — authoritative)
| Tier | Backend |
|---|---|
| primary | Gemini `gemini-2.5-flash` |
| fast | Gemini `gemini-2.0-flash` |
| economy | Ollama `qwen3-coder:30b` @ `http://localhost:11434` |

RAG collections (`data/chroma_db`)
| Collection | Documents |
|---|---|
| sigma_rules | 2382 |
| cwe_kb | 944 |
| mitre_attack | 691 |
| sigma_taxonomy | 332 |
| sysmon_info | 18 |

Local data: `data/sigma` 4099 `.yml` (3104 under `rules/`) · 29 sessions · 7 saved rules.

**Verification run:** `.venv/bin/python -c "import backend.main"` → imports cleanly.
Loads 29 sessions, initialises embeddings, agent, and translator. This is currently the
*only* available regression check.

**Known defects at baseline** (verified by reading code, see `memory/architecture-audit.md`):
1. pySigma is installed and pinned (`requirements.txt:22`) but **not used for validation**.
   `stage_review.py:245-326` hand-rolls ~5 checks with `yaml.safe_load`, while pySigma
   ships 33 validator classes.
2. RAG few-shot exemplars are embedded as **Python dict reprs, not YAML**
   (`vector_store.py:163-168` — `f"Detection: {r['detection']}"` where `detection` is a dict).
3. Rule corpus is **filtered to Windows/Sysmon only** (`ingest_rules.py:38`) → 2382 of 4099
   rules indexed, zero network/proxy/webserver/cloud/linux — while `prompts.py:235`
   mandates initial-access network coverage.
4. Coverage check is **substring matching**, not semantic (`stage_attack_vector.py:171+`),
   yet it drives regeneration (`orchestrator.py:185`).
5. `json_mode=True` is set on the generation call — the most reasoning-heavy stage
   (`stage_generate.py:235`); cf. Tam et al. arXiv 2408.02442.
6. The `fast` tier is **dead code** — no stage requests it; it exists only as the
   Ollama-failure fallback (`llm_client.py:329`).
7. No tests, no eval harness, no token/latency instrumentation.

**Note for the thesis:** defects 2 and 3 are grounding failures invisible to static code
review and to the existing output — the system produces plausible rules regardless. They
are direct evidence for the argument in Chapter 6.4 that systematic evaluation is
necessary, and they become ablation arms A2 and A3.

---

## 2026-08-06 — Change 0: test harness + characterization tests

**Motivation.** No regression check existed beyond `import backend.main`, which would not
have caught any of the 7 baseline defects. Before modifying validation logic we need to
pin its current behaviour, so that replacing it produces a *visible* behavioural diff
rather than a silent change.

**Constraint that shaped the design.** The economy tier (Ollama on the lab NVIDIA Spark)
is only reachable over VPN. The automated suite must therefore run fully offline: no
network, no LLM calls. `ReviewStage` is constructed with `client=None, vector_store=None`
— neither is touched by the functions under test.

**Changes**
| File | Change |
|---|---|
| `requirements-dev.txt` | new — `pytest==8.4.2`, kept out of the pinned `requirements.txt` |
| `tests/test_review_validation.py` | new — 11 characterization tests |

Tests pin `ReviewStage._validate_syntax` across: valid rule (zero issues), malformed YAML,
non-mapping YAML, missing required field, detection without `condition`, detection without
selections, non-standard `level` (warning), vague `logsource` (warning), non-`attack.*` tag
(info), rule-index threading; plus `_validate_mitre_tactics` degrading to `[]` when no
vector store is present.

**Verification**
```
.venv/bin/python -m pytest tests/ -q
11 passed, 1 warning in 0.10s
```
Ran with VPN disconnected. No LLM startup banner emitted, confirming no client
initialisation and no network access.

**Incidental finding (not a defect).** `grep '^import' backend/pipeline/prompts.py` matches
`import subprocess` at `prompts.py:486`. Inspected: it is inside a triple-quoted prompt
string, part of a few-shot example of malicious code for the PoC-analysis stage. Benign.
Recorded here because the same false positive will recur in any static scan of this repo.

**Documentation defect found.** `base_stage.py:40` documents `fast=True` as
`gemini-2.5-flash-lite` used for "web search only". Both halves are wrong: the runtime
banner reports `fast → gemini-2.0-flash`, and `llm_client.py:174` shows `web_search()`
uses the *primary* model and limiter. The `fast` tier is unreachable from any stage.
Not fixed yet — logged as part of defect 6.

---

## 2026-08-06 — Change 1: replace hand-rolled validation with pySigma

Addresses baseline defect 1. **Zero API cost** — the validation path is deterministic;
all verification ran offline with VPN disconnected.

### Prior state
`ReviewStage._validate_syntax` performed ~5 checks over a `yaml.safe_load` dict:
required-field presence, a logsource sanity check, a detection/condition check, a
`level` allow-list, and a tag prefix check. pySigma was pinned in `requirements.txt`
but used nowhere in the validation path.

### API investigation (read-only, pySigma 0.11.23)
Registry `sigma.validators.core.validators` contains **31** concrete validator classes.
*(An earlier estimate of 33 counted abstract base classes — corrected.)*

pySigma separates two phases the previous code conflated:
- **parse time** — `SigmaCollection.from_yaml()` raises on spec violations
- **validate time** — `SigmaValidator.validate_rules()` returns advisory issues graded
  `LOW` / `MEDIUM` / `HIGH`

Three traps identified before writing any code:
1. `SigmaValidator` **retains state across `validate_rules()` calls.** Reusing one
   instance made `DuplicateTitleIssue` and `IdentifierCollisionIssue` fire as false
   positives on unrelated rules. A fresh validator is constructed per call.
2. **The exception surface is not unified.** Malformed YAML raises `yaml.ParserError`;
   a non-mapping document leaks a bare `AttributeError` from inside pySigma; rule
   problems raise `SigmaError` (a `ValueError` subclass). `yaml.YAMLError` is *not* a
   `SigmaError`. All three paths are caught.
3. **Dangling condition references are caught by nothing.**
   `condition: selection and nonexistent` parses cleanly and passes all 31 validators.
   Only forcing `rule.detection.parsed_condition[i].parse()` raises
   `SigmaConditionError: Detection 'nonexistent' not defined in detections`.

### Measured behavioural delta
Both validators were run over identical fixtures. 7 of the 11 characterization tests
changed behaviour:

| Fixture | Hand-rolled | pySigma | Direction |
|---|---|---|---|
| valid rule | clean | clean | unchanged |
| malformed YAML | error | error (`ParserError`) | unchanged |
| non-mapping document | error | error (`AttributeError`) | unchanged outcome |
| no `condition` | error | error (`SigmaConditionError`) | unchanged |
| no selections | error | error (`SigmaDetectionError`) | unchanged |
| missing `level` | **error** | accepted — `level` is optional in the Sigma spec | **old code was wrong** |
| `level: catastrophic` | warning | **error** (`SigmaLevelError`) | stricter |
| empty `logsource` | warning | **error** (`SigmaLogsourceError`) | stricter |
| non-`attack.*` tag | info | **warning** (`InvalidPatternTagIssue`, MEDIUM) | stricter |
| missing `id` (UUID) | not checked | warning (`IdentifierExistenceIssue`, MEDIUM) | new check |
| dangling condition ref | not caught | **error** | new check |

`REQUIRED_FIELDS` at the old `stage_review.py:17` listed `level`, but the Sigma
specification makes it optional — the system was rejecting valid rules. This was found
only by differential testing, not by reading the code.

### Changes
| File | Change |
|---|---|
| `backend/pipeline/stage_review.py` | `_validate_syntax` → `_validate_rule`, reimplemented on pySigma; `REQUIRED_FIELDS` / `VALID_LEVELS` removed; `_SEVERITY_MAP` and `_render_issue` added |
| `tests/test_review_validation.py` | expectations updated to the measured delta; 2 tests added (dangling condition, missing UUID) |

Severity mapping: parse failure → `error`; `HIGH` → `error`; `MEDIUM` → `warning`;
`LOW` → `info`. Only `error` blocks a rule and triggers regeneration
(`orchestrator.py:185`). The issue-dict shape (`severity` / `field` / `message`) is
unchanged, so the orchestrator, SSE stream and frontend required no modification.

**`_validate_mitre_tactics` was deliberately retained.** pySigma's `ATTACKTagValidator`
only tests membership of a tag in a static allow-list; it does not check that a declared
tactic and technique are consistent with one another. The existing method does, using the
live ATT&CK graph from the RAG collection. The two are complementary, and the pySigma
list is a bundled snapshot whereas ours refreshes on re-ingestion.

### Known limitation accepted
`run()` validates rules one at a time, so each rule forms a single-rule collection. The
cross-rule validators (`DuplicateTitleIssue`, `IdentifierCollisionIssue`) can therefore
never fire. This is not a regression — no such check existed before — but validating the
batch as one collection would add it. Deferred.

### Verification
```
.venv/bin/python -m pytest tests/ -q          → 13 passed in 0.11s
.venv/bin/python -c "import backend.main"     → imports cleanly
```
Both run with VPN disconnected and no API calls. Remaining pytest warnings are
pyparsing deprecations raised inside pySigma itself (upstream, not actionable here).

### Thesis relevance
- Supplies the E1/E2 oracle for the evaluation harness (Chapter 5): rules can now be
  scored by *violations per validator class* rather than a binary valid/invalid.
- The `level` defect is a concrete instance of the Chapter 6.4 argument — an error
  invisible to code review and to output inspection, surfaced only by differential
  measurement.
- Expect the regeneration rate to rise, since three former warnings are now fatal.
  This changes cost and latency per request and must be quantified once the harness
  exists; it is a candidate ablation arm.

---

## 2026-08-06 — Change 2: fix RAG exemplar format and corpus coverage

Addresses baseline defects 2 and 3 together, because both require the same single
re-ingestion. **Zero API cost** — embeddings are local (`all-MiniLM-L6-v2`); no VPN
and no Gemini calls were involved.

### Correction to the baseline entry
Baseline defect 3 was recorded as "2382 of 4099 rules indexed". That denominator was
wrong: 4099 counts every `.yml` file under `data/sigma`, including deprecated rules,
tests and non-rule YAML. Measured properly, **3104 files parse as Sigma rules**, of
which 2382 were indexed — the filter excluded **722 rules (23.3%)**, not 42% as
stated verbally at the time.

### Prior state, verified by dumping the live collection
`vector_store.add_rules` interpolated Python dicts into an f-string, so every stored
exemplar read:

```
Log Source: {'category': 'process_creation', 'product': 'windows'}
Detection: {'selection': {'Image|endswith': '\powershell.exe'}, 'condition': 'selection'}
```

`stage_generate.py:55` joins these documents straight into the generation prompt.
The system therefore asked the model to emit YAML while every few-shot example it
saw was Python `repr` output.

**Unplanned finding.** 3103 of 3104 rules carry `tags:` with MITRE technique IDs,
but `ingest_rules.py` never extracted the field, so it appeared in neither document
nor metadata. `prompts.py` instructs the model to produce MITRE tags — no retrieved
exemplar had ever demonstrated one.

**Second unplanned finding.** `run_expanded_ingestion.py:35` skipped ingestion when
`existing_count >= len(rules)`. A change to document *format* leaves the rule count
unchanged, so this guard would have silently discarded the fix while printing a
success message.

### Changes
| File | Change |
|---|---|
| `backend/ingest_rules.py` | platform filter removed; `tags` and `level` now extracted |
| `backend/vector_store.py` | `add_rules` renders each rule with `yaml.safe_dump` (`sort_keys=False` to preserve Sigma field order) and includes `level`/`tags`; `category` added to metadata, since with the filter gone `product` is `unknown` for 60 rules and `category` becomes the discriminating logsource axis |
| `backend/run_expanded_ingestion.py` | count-based skip removed; `add_rules` upserts on rule UUID, so re-ingestion is idempotent |

### Verification (each step run before the next)
1. **Loader dry run, no DB writes** — 3104 rules; 3103 with tags; 3104 with level;
   **3104 unique ids of 3104**, confirming upsert cannot collide.
2. **Dump safety over the whole corpus** — `yaml.safe_dump` on all 3104 rules:
   **0 failures**. Run before writing, so a mid-ingestion crash could not leave the
   collection half-migrated.
3. **Semantic check with pySigma** — 300 rendered documents sampled (seed 0) and fed
   to `SigmaCollection.from_yaml`: **300/300 parse as valid Sigma rules.** Under the
   old format this would have been 0/300. This reuses the Change 1 validator as a
   measurement instrument, not just a runtime check.
4. **Re-ingestion** — 2382 → **3104** documents.
5. **Post-state audit** — `Log Source:` prefix (old format) present in **0** documents;
   `tags:` present in 3103; products now windows 2382, linux 207, azure 130, macos 69,
   unknown 60, aws 55, gcp 23, okta 21, zeek 21. Four documents still contain `{'`;
   each was inspected and is a legitimate GUID or command-line fragment inside a
   detection value, correctly quoted by the dumper — not residual dict repr.
6. **Retrieval smoke test** — query *"suspicious outbound network connection to a rare
   external domain"* now returns a `category=dns` rule that the previous filter
   excluded from the index entirely.
7. `.venv/bin/python -m pytest tests/ -q` → **13 passed**;
   `.venv/bin/python -c "import backend.main"` → clean.

### Thesis relevance
- Supplies ablation arms **A2** (dict-repr vs. YAML exemplars) and **A3** (Windows-only
  vs. full corpus). Both arms are now switchable by re-running ingestion.
- A2 and A3 are the clearest evidence for the Chapter 6.4 argument: neither defect was
  visible in the system's output. The pipeline produced plausible, well-formed Sigma
  rules throughout, because a capable model can recover from malformed exemplars. Only
  inspecting the retrieval store revealed them.
- **A3 is a hypothesis, not a known improvement.** Adding 722 non-Windows exemplars
  enlarges the retrieval pool; for predominantly Windows queries this is neutral at
  best and mild noise at worst. It must be measured, not assumed. The retrieval smoke
  test shows behaviour changed, which is not the same as improved.
- The `run_expanded_ingestion` skip guard is a methodological warning worth reporting:
  a cache keyed on the wrong invariant (count rather than content) can silently
  invalidate an experimental condition and produce a null result for an ablation that
  was never actually applied.

---

## Change 3 — Frozen evaluation dataset (snapshot builder)
**Date:** 2026-08-15
**Baseline defect addressed:** 7 (no eval harness / instrumentation) — step 1 of 4
**Files:** `eval/build_snapshots.py` (new), `eval/manifest.jsonl` (new), `.gitignore`

### Motivation
Changes 1-3 all landed with their effect on output quality **unmeasured**. Change 2
(A3 in particular) is explicitly a hypothesis. Defects 4 and 5 are behavioural and
cannot be assessed without running the pipeline. Measurement therefore had to precede
further repair, or the project would keep accumulating unverified changes.

Evaluating against live URLs is not reproducible: pages change, links rot, paywalls
appear. `stage_web_enrich` additionally calls Gemini Google-Search grounding, which is
non-deterministic week to week. A frozen, on-disk dataset removes both problems and
makes every later run offline and zero-cost.

### Dataset choice and contamination check
`data/sigma/rules-emerging-threats` is **not ingested**: `ingest_rules.py` walks only
`data/sigma/rules`. Verified by intersecting rule UUIDs with the live collection —
**0 of 437 overlap**. Each rule carries the `references:` URLs its human author read,
giving genuine (CTI page -> gold rule) pairs.

This deliberately avoids the reverse-task leakage trap: synthesising a threat report
*from* a rule embeds giveaway signal and measures nothing. Here the report is the real
one the analyst used.

### Design decisions
| Decision | Rationale |
|---|---|
| Store **raw HTML**, not extracted text | Extraction (`PreprocessStage._extract_page_content`) is pipeline logic that may change; baking it in would force a re-crawl each time |
| Key snapshots by **URL hash** | Pages cited by several rules are fetched once; makes re-runs resumable after a crash |
| Cap at **3 references per rule** | `stage_preprocess.py:32` reads `urls[:3]`; fetching more would cache pages the pipeline can never consume |
| Record the **full** reference list in the manifest | Widening the cap later needs no re-parse |
| Exclude walled hosts up front | twitter/x, virustotal, any.run, hybrid-analysis, box, linkedin, t.me, and `.pdf` return HTTP 200 but serve login walls, so status code alone overstates usability |

### Measured funnel
| Stage | Rules | Loss |
|---|---|---|
| Emerging-threats rules | 437 | — |
| >=1 non-walled reference | 368 | -69 fully walled |
| Page retrieved | 341 | -27 all refs failed |
| **>=2000 chars extracted** | **303** | -38 thin/empty |

Text yield of survivors: median 17,537 chars (p25 5,086; p75 30,801; max 79,018).
**232 of 303** carry `attack.tXXXX` tags, supporting technique-agreement scoring.
Composition — category: process_creation 123, webserver 54, file_event 36, proxy 17;
product: windows 201, none 73, linux 19, plus zeek/paloalto/macos/fortios/cisco/okta.
Roughly a third are non-Windows-product, so **A3 remains testable, with limited
statistical power on the non-Windows slice**.

Unrecoverable failures (80 URLs) are technical, not policy: 36x HTTP 403 (bot-blocking
WAF), 14x 503, **12x 404 — real link rot**, 7x SSL error, 4x timeout/connection.

### robots.txt: deliberately disabled, with justification
The builder was first run honouring robots.txt. This blocked **154 URLs** and cost ~48
rules, concentrated in exactly the high-quality CTI sources the task depends on:
rapid7 (14), crowdstrike (8), thedfirreport (8), bleepingcomputer (7), redcanary (7),
attackerkb (6). Re-run with `--ignore-robots`: **250 -> 303 usable cases**.

Justification, strongest first:
1. Snapshots are **not redistributed** — `eval/snapshots/` is gitignored and local-only;
   the manifest stores URLs, not content.
2. One-time, **rate-limited to 1 req/s**, ~600 requests total.
3. **Publicly accessible pages only**; authenticated/walled hosts excluded up front.
4. Every URL was **cited by a public SigmaHQ rule** as a source its author read.
5. Evaluation fidelity: the system under test applies no robots check
   (`stage_preprocess.py:34`; grep for `robots` across `backend/` returns nothing), so
   excluding these pages would benchmark a system that does not exist. Note this
   argument is the *weakest* of the five and should not lead: production performs
   user-directed retrieval of one pasted URL, whereas the builder performs automated
   bulk fetching, which is the activity robots.txt governs.

**Both datasets are retained.** Report the primary result on 303 cases and the
250-case robots-respecting subset as a robustness check; if conclusions hold on both,
the objection reduces to a footnote.

### Limitations to disclose, not engineer around
- **Pretraining contamination.** SigmaHQ is public on GitHub, so gold rules are almost
  certainly in the training data of both Gemini and Qwen. Zero *RAG* contamination
  (verified above) does not address this. Partial mitigation: report CVE-2024/2025
  rules as a separate post-cutoff slice.
- **The 2000-char threshold is a judgment call**, not a standard. It separates 7
  zero-char JS shells and thin stubs from real articles. Sensitivity should be shown
  (303 cases at >=2k, 257 at >=5k).
- **Snapshot drift**: page content may differ from what the rule author saw; 12
  references were already dead at crawl time.
- The harness measures **specification conformance and agreement with human analysts**.
  There is no telemetry corpus, so detection efficacy (true-positive rate) **cannot** be
  measured. Claiming otherwise would be the most obvious failure point at defense.

### Status
Step 1 of 4. Remaining: deterministic scorers (offline), llm_client instrumentation
(no token or latency measurement exists today — grep returns one comment), and the
runner over `orchestrator.run_sync`.

---

## Change 4 — Deterministic offline scorers
**Date:** 2026-09-09
**Baseline defect addressed:** 7 (no eval harness / instrumentation) — step 2 of 4
**Files:** `eval/scorers.py` (new), `tests/test_eval_scorers.py` (new)

### Motivation
Step 1 froze 303 evaluation cases but produced no way to score them. Without scorers,
a Spark session would generate rules that could not be assessed, so the scorers had to
precede any GPU time. They are pure functions over YAML text: no LLM, no network, no
API budget, and therefore no dependency on VPN availability.

### Metrics
| ID | Metric | Definition |
|---|---|---|
| E1 | parse validity | `SigmaCollection.from_yaml` succeeds |
| E2 | validator issues | pySigma core-validator issues, counted by severity |
| E3 | logsource agreement | per-field category/product/service match vs gold |
| E4 | ATT&CK agreement | precision/recall/F1 over `attack.tXXXX` tags |
| E5 | detection fields | precision/recall/F1 over detection field names |

E1-E2 are absolute; **E3-E5 measure agreement with a human analyst, not correctness.**
A rule that differs from the gold rule may still be a good detection. This distinction
is stated in the module docstring so it cannot quietly drift into a correctness claim.

### Design decisions
| Decision | Rationale |
|---|---|
| Undefined metrics return `None`, never `0.0` | A model that emits no tags has undefined precision, not zero precision. Substituting 0.0 would penalise it inside an average and silently bias every aggregate |
| Fresh `SigmaValidator` per call | Core validators accumulate state (duplicate title, identifier collision); a shared instance reports phantom issues on unrelated rules. Same trap found during Change 1 |
| E4 reported at two granularities | `exact` distinguishes t1059.001 from t1059; `parent` collapses sub-techniques. Reporting both prevents selecting whichever definition flatters the result |
| Modifiers stripped in E5 (`Image|endswith` -> `image`) | A modifier qualifies a field, it does not make it a different field |
| Code fences stripped at the boundary | Models wrap YAML in ```yaml; scoring that as a parse failure would attribute a formatting habit to rule quality |
| Content metrics `None` when the rule does not parse | Comparing fields of an unparseable rule compares against nothing |

### Verification
1. **26 unit tests** covering each metric, including the failure modes easiest to get
   wrong silently: validator state leaks, undefined-vs-zero, sub-technique
   granularity, modifier stripping, list-valued selections, prose instead of a rule.
   Full suite: **41 passed** (13 pre-existing + 28 new), 0.15s, fully offline.
2. **Upper bound on real data** — all 341 gold rules scored against themselves:
   0 parse failures, 0 logsource mismatches, 264 defined ATT&CK F1 all == 1.0,
   detection F1 == 1.0 for 333. Fixture tests alone would not have exercised this.
3. **Discrimination check** — each gold rule scored against a *different* random gold
   rule (seed 0, 341 pairs). This is the control that a self-comparison cannot provide:
   a scorer returning 1.0 unconditionally passes step 2 and fails here.

### Null baselines (mismatched-pair control)
| Metric | Mean | Median |
|---|---|---|
| logsource exact match | 17.3% (59/341) | — |
| detection-field F1 | 0.133 | 0.000 |
| ATT&CK exact F1 | 0.092 | 0.000 |

**These are the numbers every later result must be read against.** Logsource
agreement in particular has a high floor: `process_creation`/`windows` is so common
that unrelated rules match 17.3% of the time by coincidence. A system scoring ~0.13
detection F1 is performing no better than random pairing, and reporting such a figure
as a success would be indefensible.

### Finding: E5 is inapplicable to 8 rules (2.3%)
Investigating 8 undefined detection scores showed they are **keyword-based rules**
(log4shell, FortiOS CVE-2022-42475) that match unstructured text via a bare keyword
list and name no fields at all — valid Sigma with nothing for E5 to compare. They are
excluded from E5 aggregates rather than scored as zero. Encountering these confirmed
the undefined-vs-zero decision above; had `_prf` returned 0.0, these 8 would have
depressed every E5 average for a reason unrelated to model quality.

### Limitations to disclose
- **E5 is structural and ignores values.** `Image|endswith: \evil.exe` and
  `\good.exe` score identically. A test pins this explicitly so the limitation is
  recorded in code, not just prose.
- **E3-E5 penalise legitimate disagreement.** A rule may target a different but valid
  logsource, or use different fields for the same behaviour.
- **No detection efficacy.** There is no telemetry corpus, so true-positive and
  false-positive rates remain unmeasurable regardless of these scores.

### Status
Step 2 of 4 complete. Remaining: instrumentation wrapper on `llm_client` (tokens,
latency — none exists today), then the runner over `orchestrator.run_sync`.

---

## Change 5 — LLM telemetry (tokens, latency, tier routing)
**Date:** 2026-09-09
**Baseline defect addressed:** 7 (no eval harness / instrumentation) — step 3 of 4
**Files:** `backend/telemetry.py` (new), `backend/llm_client.py`,
`tests/test_telemetry.py` (new)

### Motivation
The system had no measurement of cost or latency whatsoever: a grep across
`backend/` for `usage_metadata|token_count|total_tokens|latency|elapsed` returned a
single comment. E6 (cost) and E7 (latency) were therefore unmeasurable, and the
three-tier routing design — the project's main efficiency claim — was unverified.

### Why the client was modified rather than wrapped
A non-invasive decorator around `LLMClient` cannot recover token counts: both
backends discarded their usage objects before returning. `GeminiLLMClient.generate`
returned `response.text` and `OllamaLLMClient.generate` returned
`response.choices[0].message.content`, so `usage_metadata` / `usage` were already out
of scope by the time a wrapper saw the result. A wrapper could only have measured
latency and *estimated* tokens from character counts. Reporting an estimate as a
measurement in a cost evaluation is not defensible, so usage is captured where it
exists, inside each client. The change is additive: no return value, signature, or
control-flow path was altered.

### Finding: thinking tokens would have been silently dropped
Inspecting the installed SDK (offline, via `model_fields`) confirmed the field names
and revealed `thoughts_token_count`. **gemini-2.5-flash is a thinking model: reasoning
tokens are billed at the output rate but are excluded from
`candidates_token_count`.** The first implementation derived
`total = prompt + completion`, which would have undercounted every primary-tier
request by its entire thinking budget while presenting a precise-looking figure.

Fixed by recording `thinking_tokens` separately and preferring the provider's own
`total_token_count`, falling back to `prompt + completion + thinking` only when the
provider omits a total. This is the single most consequential detail in the change:
an undetected version would have produced a systematically optimistic cost result for
exactly the tier the thesis argues is expensive.

### Design decisions
| Decision | Rationale |
|---|---|
| Counts measured, never estimated from characters | chars/4 varies by tokenizer, language, and code/base64 content |
| Missing token data is `None`, never `0` | A call with no usage did not use zero tokens. `summary()` reports `calls_without_token_data` so a partial total cannot pass as a complete one. Same rule as `eval/scorers.py` |
| Latency timed *after* `_RateLimiter.acquire()` | Otherwise latency measures queueing behind our own limiter, not provider response time |
| Failed calls recorded, then re-raised | A Spark outage must appear as a failed economy call; otherwise the hybrid fallback shows up only as an unexplained extra Gemini call |
| `web_search` recorded per attempt, against the primary tier | Google Search grounding bills to the primary model — easy to overlook when attributing per-stage cost — and its retry loop swallows 429s into an empty string |
| Bounded `deque` (2000) | The FastAPI server is long-running; unbounded history would leak memory |
| No recording in `HybridLLMClient` | It delegates to the sub-clients, which record; recording there too would double-count |

### Verification
1. **SDK field names confirmed offline** against `GenerateContentResponseUsageMetadata`
   and `CompletionUsage` rather than assumed. This is what surfaced
   `thoughts_token_count`, and it cost no API budget.
2. **17 unit tests**, including the silent-failure modes: missing usage returning `{}`
   not zeros, all-missing giving a `None` total, per-tier attribution, bounded
   history, and thinking tokens excluded from a naive total.
3. **Wiring test** — `OllamaLLMClient` with a faked transport asserts the client
   actually calls `TELEMETRY`. Without it, every unit test above would still pass if
   `llm_client` never recorded anything.
4. **Failure-path test** — a `ConnectionError` is recorded and re-raised, matching the
   real Spark-unavailable behaviour observed this session.
5. Full suite **58 passed** (41 prior + 17 new), 0.31s, fully offline;
   `import backend.main` clean; `create_llm_client()` still returns
   `HybridLLMClient` with the expected banner.

### Not yet verified
No telemetry has been recorded from a **real** API call. The extraction logic is
confirmed against the SDK's declared schema and against fabricated response objects,
but not against a live response. First live run should assert
`calls_without_token_data == 0`; if it is non-zero, extraction is silently failing.

### Status
Step 3 of 4 complete. Remaining: the runner over `orchestrator.run_sync`, joining
telemetry (Change 5) to scores (Change 4) per case and writing JSONL.

---

## Change 6 — Evaluation runner and summariser
**Date:** 2026-09-09
**Baseline defect addressed:** 7 (no eval harness / instrumentation) — step 4 of 4
**Files:** `eval/run_eval.py` (new), `eval/summarise.py` (new),
`tests/test_eval_runner.py` (new), `tests/test_eval_summarise.py` (new)

### Motivation
Changes 3–5 produced a frozen dataset, deterministic scorers and cost
instrumentation, but nothing joined them. The runner closes the loop: for each
case it feeds the gold rule's own reference URLs to the production pipeline,
scores the output against the gold rule, and records the tokens and latency the
run consumed. Until this existed, Changes 1–3 had all landed with their effect on
output quality **unmeasured**.

### Why the pipeline is driven through its real entry point
The runner calls `PipelineOrchestrator.run_sync` — the same function the FastAPI
endpoint calls — not a reimplementation of the stages. An evaluation that
reconstructs the pipeline measures the reconstruction, not the system. The only
things substituted are the two sources of non-determinism, and both are
substituted at their boundary rather than by editing stage logic.

### How reproducibility is enforced
| Source of drift | Substitution |
|---|---|
| Live URL fetches (pages change or die) | `snapshots_instead_of_network` swaps the `requests` reference *inside* `stage_preprocess` for a shim reading the Change 3 snapshots. The stage's own extraction code runs unchanged |
| Google Search grounding (results differ week to week, bills to primary tier) | `web_enrichment_disabled` stubs `client.web_search` to return an empty result |

Both are context managers that restore the original in a `finally`, because a
leaked patch would silently disable network access for the rest of the process.
A URL with no snapshot returns **404 rather than raising**, so a missing page
degrades like a dead link in production instead of aborting the case.

### Design decisions
| Decision | Rationale |
|---|---|
| Stratified sample by logsource category, not uniform | A uniform sample drops the rare non-Windows categories — exactly the ones the corpus expansion (Change 2 / A3) was meant to affect. Sampling that cannot see the effect it is meant to measure is worthless |
| Floor quotas, guarantee >=1 per category, then top up from a leftover pool | Proportional rounding lost cases: a request for 25 returned 24. Caught by a test asserting the requested size, not by inspection |
| All YAML blocks extracted, not just the first | The pipeline can emit several rules. Keeping all of them allows best-of-N to be computed later without paying for a second run |
| Append with `flush()` after each case; resumable by `rule_id` | A 303-case run is long and the economy tier depends on a VPN. A dropped connection must not discard completed work |
| Per-case `TELEMETRY.reset()`, full call list stored per row | Enables per-stage and per-tier cost attribution after the fact, not just a total |
| Errors recorded as rows, never dropped | A case that crashed is still a case. Excluding it would make a fragile configuration look accurate |
| `--arm` label and full config recorded in every row | Two result files can be compared only if each states the configuration that produced it |

### Cost warning surfaced at runtime
In the default hybrid configuration **only economy-tier calls reach Ollama**, so a
run is not free even with the Spark available. Verified per-stage routing:

| Stage | Tier | Backend in hybrid mode |
|---|---|---|
| preprocess | primary | Gemini — **only when an image is attached**; no call for a URL |
| web_enrich | fast | Gemini (skipped entirely under `--no-web-enrich`) |
| poc_analysis | economy | Ollama |
| attack_vector | economy | Ollama |
| analysis | economy | Ollama |
| **generate** | **primary** | **Gemini** |
| review | economy | Ollama |

So a 303-case URL-only run with enrichment disabled issues roughly **303–606
primary-tier Gemini calls** — one per case for rule generation, two when the
generation retry fires — against a 9 RPM limit. Everything else is local.

This corrects an earlier working assumption that a local run costs "time, not
tokens". It also corrects a first draft of this entry, which claimed
attack-vector and analysis were primary-tier and put the figure at ~900 calls;
both are `economy=True` (`stage_attack_vector.py:78`, `stage_analysis.py:61`).
The runner prints a warning before starting, and `LLM_PROVIDER=ollama` remains
the setting for a genuinely zero-cost run.

### Summariser: every metric reported with its own n, against chance
`eval/summarise.py` reports each metric with the number of cases it was computed
over, because the denominators genuinely differ — content scores exist only for
rules that parsed, and E4/E5 are undefined for rules with no ATT&CK tags or
keyword-only detections. A mean without its n is not interpretable.

Every agreement metric is printed next to the null baseline measured in Change 4
(logsource 0.173, ATT&CK F1 0.092, detection F1 0.133) and flagged when it falls
at or below it. Anchoring the numbers this way was done **before** any real
result existed, so a weak result cannot be rationalised after the fact.

### Verification
1. **Dry run over the real manifest** yields **303 usable cases**, matching the
   Change 3 figure exactly. Category mix: process_creation 123, webserver 54,
   file_event 36, none 33, proxy 17, registry_set 10, image_load 10, and 6
   categories with a single case each.
2. **Integration test against the production stage** — the real `PreprocessStage`
   runs under the shim and its extracted text is asserted. If interception ever
   broke, this fails rather than silently falling through to the live network.
3. **Restoration tests**, including the case where the body raises.
4. **Sampling bug found by test, not by reading** — `round()` on proportional
   quotas returned 24 for a requested 25. After the fix, requests for 30/60/100
   return exactly 30/60/100 and the rare categories survive.
5. **Summariser exercised on fixtures built with the real scorers**, not
   hand-written dicts, so the score shape cannot drift from what the runner
   writes. Confirms undefined F1 is excluded rather than averaged as 0.0, and
   that unparsed rules do not count as logsource misses.
6. Full suite **85 passed** (58 prior + 17 runner + 10 summariser), 0.31s,
   fully offline.

### Not yet verified
**No evaluation has been run.** The economy tier is firewalled at the lab, so the
harness is complete but unexercised end to end. Nothing is yet known about
whether Changes 1–3 improved output quality. The first live run should assert
`calls_without_token_data == 0` and `snapshots_missed == 0`; a non-zero value in
either means the harness is degrading silently.

### Limitations to disclose
- Deltas between arms are **descriptive only**. Significance requires a paired
  test over the per-case scores — McNemar for the binary metrics (E1/E3),
  bootstrap CI for the F1 metrics (E4/E5). Neither is implemented.
- Disabling web enrichment buys reproducibility at the cost of measuring a
  configuration that differs from the deployed default.
- A model refusal currently surfaces its parse failure as an `AttributeError`,
  which reads like a harness bug rather than a refusal.

### Status
Defect 7 closed as far as it can be without a live run. The harness is built,
tested and reproducible; producing results is now blocked only on economy-tier
access.

---

## 2026-09-09 — Change 7: retire the E0–E7 metric numbering for S/R/C

### Motivation
Writing the Chapter 5 notes surfaced a documentation defect that would have been
visible to an examiner with `grep`: **three files numbered the same metrics
differently, and four IDs were ambiguous.**

| ID | `OUTLINE.md` | `eval/scorers.py` | `backend/telemetry.py` |
|---|---|---|---|
| E3 | backend compilability | logsource match | — |
| E5 | detection efficacy (Zircolite) | detection field overlap | — |
| E6 | false-positive rate | — | cost |
| E7 | cost *and* latency | — | latency |

This is a thesis-integrity problem rather than a code problem: the artefact would
have contradicted its own written methodology.

### Design decisions
| Decision | Rationale |
|---|---|
| Three families S / R / C rather than patched E-numbers | The static/runtime split *is* the honest project status — static is built, runtime is the unbuilt novelty claim. A reader infers it from the IDs alone |
| `R` (runtime) not `D` (dynamic) | `D1`–`D4` already name the **datasets**. The first draft proposed D1–D2 for metrics, which would have replaced one collision with another. Caught before application |
| `S6` backend compilability retained as an ID despite being unbuilt | It was a real metric in the original outline and is cheaply automatable; dropping the ID would quietly lose a planned contribution |
| `S0` folded into `S1` | Non-empty output and parseable output are near-identical in practice; kept as an ID so refusal-vs-malformed can be split later if needed |
| `ENGINEERING_LOG.md` history **not** rewritten | A dated log edited retroactively stops being evidence. Earlier entries keep their original E-numbers; this entry records the mapping |

### Verification
- Confirmed the numbering was cosmetic before touching anything: the E-numbers
  appeared only in comments, docstrings and print labels. Data keys were already
  semantic (`validity`, `logsource`, `attack`, `detection_fields`;
  `validity_rate`, `logsource_exact`, `attack_f1`, `detection_f1`). No JSONL
  schema change and no test-logic change were required.
- Applied across `thesis/OUTLINE.md` (§5, §6.1), `eval/scorers.py`,
  `eval/summarise.py`, `backend/telemetry.py`, `tests/test_eval_scorers.py`,
  `tests/test_eval_summarise.py`.
- `.venv/bin/python -m pytest tests/ -q` -> **85 passed**, unchanged.
- Rendered `eval/summarise.py` against a synthetic two-arm fixture to confirm the
  new labels print and that differing denominators still surface (n=20 vs n=16).

### Separate correction in the same change
`OUTLINE.md` claimed pySigma exposes **33 validator classes** in two places. The
measured count is **31** (`sigma.validators.core.validators`, pySigma 0.11.23).
Both occurrences corrected. The figure had been asserted, never checked.

### Limitations to disclose
- The renumbering is documentation-only. It improves nothing about the system and
  produces no results; it prevents a defensible-methodology failure, no more.
- Earlier log entries still use E-numbers by design. Anyone reading the log
  chronologically needs the mapping in this entry.

### Status
Metric IDs are now consistent across outline, code and tests. Chapter 5 can be
written without contradicting the artefact.

---

## 2026-09-11 — First live harness run (infrastructure, no change to the system)

### What unblocked it
The lab Spark was reachable again after the admin restored access. Its address had
changed (`10.246.27.160` -> `10.246.14.123`); `uptime` reported 35 days, which
retrospectively **falsifies the earlier diagnosis that the host was powered off**.
A firewall DROP and a dead host produce an identical signature from the client
side, and I asserted the wrong one. Recorded here because the same ambiguity will
recur.

Ollama is not exposed on the network; port 11434 is reachable only through an SSH
tunnel, which does not persist between sessions and must be re-established:
```
ssh -N -f -o ExitOnForwardFailure=yes -L 11434:localhost:11434 dsalgado@10.246.14.123
```

### Result
A 2-case pilot ran `orchestrator.run_sync` end to end for the first time. Both
hard gates were clean:
- `snapshots_missed == 0` — every fetch was served from `eval/snapshots/`, so no
  case silently escaped to the live network.
- `calls_without_token_data == 0` — **this is the live verification C1/C2 had been
  waiting for.** Token extraction was previously built but unexercised; it is now
  confirmed against real Ollama responses. The Gemini thinking-token path remains
  unverified, because that API key is suspended.

`eval/summarise.py` executed against real output for the first time.

### Two defects the run exposed
Neither is caused by this change; both were pre-existing and only became visible
once the pipeline was actually driven over real inputs.

- **Defect 8 — intent misrouting.** Addressed by Change 8 below.
- **Defect 9 — page extraction can yield near-zero text.** `_extract_page_content`
  returned 0 and 12 characters for two of the three pages in the pilot. The
  snapshot builder's >=2000-character threshold is applied to the *combined* text
  of all of a rule's references, so a case containing one rich page and several
  empty ones still enters the dataset. **Open.**

### Status
Harness verified live. Defect 7 is now fully closed. Cost instrumentation is no
longer "built, unverified" on the Ollama path.

---

## 2026-09-13 — Change 8: short-circuit bare-URL input to rule generation

### Motivation (defect 8)
The first live run showed a case fetching **no** snapshot despite having one
available. Tracing it: `classify_intent` (`orchestrator.py:48`) had routed the
input to `question`, and `run_sync:129` returns a conversational answer for
`chat`/`question` **before** the pipeline starts. All seven grounding stages are
skipped, so the page is never retrieved.

The failure is worse than a skipped fetch. `handle_conversational` still receives
RAG context and still emits a plausible-looking Sigma rule — one written from the
**URL string alone**. It looks like a normal result. Nothing in the output marks
it as ungrounded.

Measured on the 30 real CTI reference URLs the evaluation uses:

| Routed intent | Count |
|---|---|
| `generate_rule` (correct) | 13 |
| `question` | 14 |
| `chat` | 3 |

**17 of 30 (57%) of real inputs were never grounded.** The prevalence matters
because `data/sessions.json` shows 28 of 30 real user messages are bare URLs —
this is the dominant usage mode, not an edge case.

Root cause is in the prompt: the four few-shot examples in
`prompts.py:12` (`INTENT_CLASSIFICATION`) **contain no URL at all**. A bare link
has no instruction verb, so the classifier has nothing to anchor on and the
decision is close to arbitrary.

### Design decisions
| Decision | Rationale |
|---|---|
| Short-circuit in code, not another few-shot example | An added example would shift the distribution without bounding it. A deterministic rule is testable offline and cannot regress with a model swap |
| Fix inside `classify_intent` rather than at the call sites | It is invoked from two places — `run_sync:125` and the streaming path at `:209`. Patching the method covers both and cannot drift apart |
| Return **before** any LLM call | Also removes one economy-tier call per URL request. A test asserts this by injecting a client that raises if called |
| Trigger on "bare" URL, not "contains a URL" | "Can you explain what this article says? <url>" is a genuine question. Forcing every URL-bearing message into generation would break refinement and Q&A |
| Threshold: fewer than 10 alphanumeric characters outside the URLs | Tolerates trailing filler ("please", "thanks") while any real sentence exceeds it. The constant is named and commented, not inline |
| Reasoning string states the route was forced | The decision remains auditable in the returned metadata rather than looking like a model judgement |

### Verification
1. **18 offline tests** (`tests/test_intent_routing.py`), no LLM and no network:
   parametrised positives (single URL, multiple URLs, surrounding whitespace,
   trailing filler, trailing newline) and negatives (empty, whitespace, greeting,
   question, prose rule request, refinement, question *about* a URL, refinement
   citing a URL), plus two wiring tests — one asserting no LLM call occurs on the
   short-circuit, one asserting prose still reaches the model.
2. **Re-measured the same 30 URLs: 30/30 (100%) now route to `generate_rule`**,
   from 13/30.
3. **Regression probe, 5/5 still classified correctly by the LLM** — `chat`,
   `question`, `generate_rule`, `refine_rule`, and a genuine question *about* a
   URL. This is the evidence the rule is not over-broad.
4. **Pilot re-run, same two cases, before vs after:**

   | Case | snapshots served | LLM calls | rules produced | tokens | wall time |
   |---|---|---|---|---|---|
   | `5b2bbc47` before | 0 | 2 | 1 | 3,099 | 13s |
   | `5b2bbc47` after | **1** | **5** | **3** | 36,529 | 112s |
   | `0d0d9a8a` before | 3 | 5 | 2 | 38,328 | 79s |
   | `0d0d9a8a` after | 3 | 4 | 3 | 29,317 | 82s |

   Case `5b2bbc47` is the proof: it had previously been answered conversationally
   and is now fetched and processed by the full pipeline. Both cases produced
   parsing rules; both gates stayed at zero.
5. Full suite **103 passed** (85 prior + 18 new), offline.

### Limitations to disclose
- The before/after quality comparison is **n=2**. It demonstrates the mechanism
  changed, and nothing about score improvement. Every number produced by the
  harness before this change was measured on a pipeline that skipped grounding on
  roughly half its inputs and must be treated as invalid.
- Cost moves the wrong way by design: correct grounding costs ~2.5x the LLM calls
  and ~8x the wall time on the affected case. Correctness was bought with compute.
- The 10-character threshold is a heuristic tuned against 35 observed inputs. It
  is defensible as a bound, not as an optimum.
- The underlying prompt weakness is untouched — this constrains the classifier's
  input rather than improving the classifier.
- Not an ablation arm: there is no flag to disable it, so the 57% figure is
  reproducible only by reverting the commit.

### Status
Defect 8 closed. Defect 9 remains open and blocks trusting per-case content
scores, because a case can still enter the dataset with almost no extracted text.

---

## 2026-09-13 — Change 9: assign rule identifiers in code, not in the model

### Motivation (defect 10)
Found by running the app end to end against the Bumblebee DFIR report while
preparing a demo. The generated rule failed pySigma outright:

```
id: 5a3b4c5d-6e7f-8g9h-1i2j-3k4l5m6n7o8p
-> SigmaIdentifierError: Sigma rule identifier must be an UUID
```

`g, h, i, j, k, l, m, n, o` are not hexadecimal. The model produced text with
the *shape* of a UUID and none of the constraints.

The consequence is disproportionate to the cause. `id:` carries no detection
semantics, but pySigma rejects the rule at **parse** time, so the failure
cascades: **S1 records `parses: false`, and S2–S5 are undefined because there is
no parsed rule to score.** A rule whose detection logic may be perfectly sound
contributes a total miss on every static metric. It also short-circuits
`stage_review.py:167`, which skips LLM review entirely when a syntax error is
present, and burns the single permitted regeneration on a cosmetic field.

This is a **measurement-integrity defect before it is a product defect**: it
depresses the headline validity metric for a reason unrelated to the capability
being measured.

### Design decisions
| Decision | Rationale |
|---|---|
| Fix in code, not by strengthening the prompt | `prompts.py:246` already says "id (valid UUID)" and the model ignored it. Generating a random unique identifier is not a language-modelling task — no amount of prompting makes sampling produce guaranteed-hex output |
| Repair after generation rather than pre-seeding an id into the prompt | Pre-seeding spends context tokens on a value the model may still overwrite. Post-hoc repair is unconditional |
| Validate with `uuid.UUID()`, not a regex | The regex would encode a second, independently-wrong definition of the format. The stdlib parser is the same authority pySigma uses |
| Replace only when invalid; never rewrite a good id | A regenerated rule keeps its identifier across the retry, so the id remains stable when it was already legal |
| `id:` matched anchored at column 0 | A nested `id:` inside `detection.selection` is a **log field name**, not the rule identifier. Rewriting it would corrupt the detection logic. Covered by a test |
| `re.MULTILINE` across the whole document | A multi-document YAML with a valid first id must not mask an invalid second one |
| Insert after `title:` when `id:` is absent | Preserves SigmaHQ field order, so the output stays diff-comparable with the gold corpus |
| Count replacements into `context["generation"]["ids_replaced"]` | The substitution rate is itself a finding. Silently correcting it would hide how often the model fails this constraint |

### Verification
1. **Against the real failing rule** captured from the live run:
   `parses: False -> True`, `replaced = True`, 0 errors, 1 remaining warning
   (an unrelated ATT&CK tag issue). The new id is a real UUIDv4.
2. **19 offline tests** (`tests/test_rule_id_normalisation.py`), no LLM, no
   network. Parametrised invalid ids — including the exact observed string —
   and valid ids in bare, quoted and uppercase form. Structural tests assert
   that a YAML round-trip differs in the `id` key **and nothing else**, that a
   nested `id:` field name is untouched, that both documents of a two-rule YAML
   are checked, and that 20 successive calls yield 20 distinct ids.
3. **End-to-end claim asserted directly**: the test feeds the original to
   `SigmaCollection.from_yaml` under `pytest.raises(SigmaError)`, then feeds the
   repaired version and asserts it parses. The fix cannot silently stop working.
4. Full suite **122 passed** (103 prior + 19), offline.

### Limitations to disclose
- **Frequency is unmeasured.** Observed in 1 of 1 live generations, which is not
  a rate. `ids_replaced` is now recorded, so the 60-case run will produce a real
  denominator. Do not cite a percentage before then.
- The rule is no longer reproducible from the same inputs, because the id is
  drawn from a fresh UUIDv4 each run. Acceptable — the field is meaningless by
  construction — but it means byte-exact output comparison across runs must
  exclude `id:`.
- This **repairs the symptom, not the cause**: the generation stage still emits
  invalid identifiers, and the same disregard for a stated format constraint
  presumably affects other fields that are not this cheap to validate. Defect 5
  (`json_mode=True` on the generation stage) is the more likely root cause and
  remains open.
- Any S1 validity figure measured before this commit is depressed by an unknown
  amount for a non-semantic reason and should not be compared with figures after
  it.

### Related observation, NOT fixed (defect 11)
The same run exposed a stage disagreement worth recording. The analysis stage
recommended `process_creation / windows / sysmon` at **0.95 confidence**, and
`logsource_primary` was `process_creation (Sysmon Event ID 1)`. The generated
rule used `category: webserver_access_log` and described an "unauthenticated
SSRF to /rs.js" — not what the report documents. Extraction was sound
(`rundll32.exe`, `tamirlan.dll`, `lsass.exe` via procdump, 23 PoC snippets); the
generation stage followed `attack_vector` and ignored `logsource_suggestions`.

This bears directly on ablation **A5** (is the pipeline decomposition earning
its cost): here one stage's output silently overrode a higher-confidence one.
Logged, not fixed — it needs the 60-case run to establish whether it is
systematic or a single bad case.

### Status
Defect 10 closed. Defects 4, 5, 6, 9 and 11 remain open.

---

## 2026-09-19 — Change 10: snapshot lookup ignores the URL fragment (logged 2026-09-23)

### Motivation (defect 14)
Found during the n=60 baseline run by checking `snapshots_missed` per case rather
than only in aggregate: 4 of 60 cases reported a miss even though every one of
their snapshot files existed on disk.

`eval/manifest.jsonl` stores each reference URL verbatim, fragment included —
`https://wikileaks.org/vault7/#Pandemic` — and `load_cases` used that string as the
key of the URL-to-snapshot map. The pipeline, however, strips the fragment while
extracting links from the input, so the URL it asks for is
`https://wikileaks.org/vault7/`. The two keys never matched and
`_SnapshotRequests.get` answered **404**.

The failure is silent and points in the *correct-looking* direction. The case
still runs, still produces rules, still scores, and still writes a row with
`error: None` and a plausible elapsed time. It is simply generated from less
source material than it should have been — in two cases, from **none**. This is
the same failure mode as defect 8, and the only signal was the
`snapshots_missed` counter, which is the reason that gate exists.

### Design decisions
| Decision | Rationale |
|---|---|
| Drop the fragment, not the query string | A fragment is a client-side anchor and is never sent to the server, so two URLs differing only by fragment name the same page. A query string *is* sent and can select different content (`?tab=readme-ov-file` in case `9aa27839`), so it must survive |
| One function, `snapshot_key()`, used on both sides (`run_eval.py:77`) | Normalising only the lookup would still break if a future manifest stored the stripped form. Applying the same function to the map build (`:183`) and the lookup (`:98`) makes the direction irrelevant |
| `urllib.parse.urldefrag`, not a string split on `#` | The standard library is the authority for URL syntax; a hand-rolled split is a second, independently wrong definition |
| `case["urls"]` keeps the original fragment URL | That is what a user would actually paste, so the input the pipeline sees stays realistic. Only the lookup key is normalised |
| Fix the harness, not the pipeline | Stripping fragments is correct pipeline behaviour. The defect was the harness keying its cache on a form of the URL the pipeline never requests |

### Verification
1. **Collision check across all 437 manifest rows: 0.** No two distinct snapshots
   collapse to the same key once fragments are dropped.
2. **Corpus size unchanged at 303** cases, so `--sample 60 --seed 0` still selects
   the same 60 and resume-by-`rule_id` remained valid for the rerun below.
3. **3 offline tests** (`tests/test_eval_runner.py:121-151`): a fragment URL is
   served from the unfragmented snapshot; normalisation works whichever form
   arrives; and `snapshot_key` strips only the fragment — query strings survive
   and distinct pages keep distinct keys. Full suite **125 passed** (122 prior + 3).
4. **The 4 affected rows were purged and rerun** with the identical command, so
   the final `baseline60.jsonl` is uniformly post-fix. Before (from
   `baseline60.prefix-fix.bak`) vs after:

   | Case | Input | snapshots served / missed | rules | tokens | wall time |
   |---|---|---|---|---|---|
   | `47e0852a` before | `wikileaks.org/vault7/#Pandemic` | **0** / 1 | 2 | 20,238 | 34s |
   | `47e0852a` after | | 1 / 0 | 2 | 37,593 | 76s |
   | `9aa27839` before | `github.com/amlweems/xzbot?tab=...#backdoor-demo` | **0** / 1 | 2 | 23,039 | 45s |
   | `9aa27839` after | | 1 / 0 | 3 | 44,761 | 112s |
   | `b7155193` before | 3 URLs, one with `#atomic-test-7...` | 2 / 1 | 4 | 50,890 | 152s |
   | `b7155193` after | | 3 / 0 | 4 | 36,199 | 110s |
   | `e710a880` before | 3 URLs, one with `#L36` | 2 / 1 | 5 | 58,825 | 166s |
   | `e710a880` after | | 3 / 0 | 6 | 40,332 | 143s |

   Two cases (`47e0852a`, `9aa27839`) had **no source page at all** before the
   fix — their rules were written from the URL string alone.

### Limitations to disclose
- The before/after scores on these 4 cases are **not evidence of a quality
  effect** in either direction. `9aa27839` gained a logsource match and detection
  F1 0.0 -> 0.4; `e710a880` went the other way, detection F1 1.0 -> 0.67. At n=4
  this shows the mechanism changed, nothing more.
- The collision check covers the current manifest only. A future manifest could
  contain two references that differ only by fragment and point at different
  cached content (e.g. a single-page app routing on the fragment). None exist
  today; the check would need repeating after any rebuild.
- Any harness file produced before this change may contain cases like these.
  The earlier `pilot.jsonl`/`postfix.jsonl` do not — both report
  `snapshots_missed == 0`.

### Status
Defect 14 closed.

---

## 2026-09-19 — First full baseline run, n=60 (infrastructure, no change to the system; logged 2026-09-23)

### Setup
| Parameter | Value |
|---|---|
| System state | `73d8446` (Change 9) + Change 10 (harness only) |
| Model | `qwen3-coder:30b` on every tier, Ollama on the lab Spark |
| Sample | `--sample 60 --seed 0` from the 303-case corpus |
| Web enrichment | disabled (`--no-web-enrich`); a silent no-op on Ollama anyway |
| Arm | `baseline` — a label only, no ablation is wired |
| Output | `eval/results/baseline60.jsonl`, committed with this entry as the frozen "before" measurement |

### Five acceptance gates, not two
The first live run (2026-09-11) used two gates. Three were added after defects
12, 13 and 14 each showed a different way a result file can look normal and be
wrong. A file is citable only if **all five** hold:

| Gate | Guards against | This run |
|---|---|---|
| `snapshots_missed == 0` | a case silently generated from the URL string alone (defects 8, 14) | 0 |
| `calls_without_token_data == 0` | incomplete cost figures (C1) | 0 |
| telemetry `n_errors == 0` | stage-level LLM failures swallowed inside the pipeline | 0 |
| every `row["error"]` is `None` | a whole case lost to an exception (defect 13) | 0 |
| no row with `elapsed_s < 30` | rows written while the backend was unreachable (defect 12) | 0 |

**All five pass.** 60 rows, 60 unique `rule_id`s. The run completed with no
tunnel drop and no guard recovery.

### Result
Each metric is reported with its own n, because S3–S5 are undefined when the
first rule does not parse or the gold rule lacks the field. Scores are computed
on the **first** generated rule — the one a user sees.

| Metric | Result | n | Null baseline |
|---|---|---|---|
| S1 valid Sigma | 0.917 (55/60) | 60 | — |
| S2 validator issues per rule | 1.00 | 55 | — |
| S3 logsource exact match | **0.145** (8/55), Wilson 95% CI 0.076–0.262 | 55 | 0.173 |
| S4 ATT&CK exact F1 | 0.123 | 37 | 0.092 |
| S5 detection-field F1 | 0.205 | 53 | 0.133 |
| Rules per case | 3.27 (196 total) | 60 | — |

**S3 is indistinguishable from chance** — the interval contains the null
baseline. S4 and S5 are above their baselines by modest margins.

Cost (C1/C2): 321 LLM calls, **2,227,584 tokens** (mean 37,126 per case),
`thinking_tokens == 0` as expected for this model. Per-case wall time: mean
**102.6 s**, median 89.1 s, range 38.7–320.7 s.

### The 5 cases that failed S1
| Case | Rules extracted | Failure |
|---|---|---|
| `43259cc4` | 0 | 86-character response containing no YAML |
| `ec3a3c2f` | 0 | 86-character response containing no YAML |
| `b014ea07` | 2 | first rule is malformed YAML (`ScannerError`) |
| `36222790` | 3 | first rule is malformed YAML (`ScannerError`) |
| `0d0d9a8a` | 2 | `contains` modifier applied to a null value (`SigmaTypeError`) |

The two zero-rule cases finished in normal time with `error: None` and no
telemetry errors, so they are not defect-12 rows. The pipeline returned a short
non-rule answer; what it said is **not recoverable**, because the harness stores
only the response length when no rule is extracted.

### Defects recorded during this run and its preparation
- **Defect 12 — the harness writes rows while the backend is unreachable.**
  Found 2026-09-13 when the VPN dropped during an earlier attempt. The pipeline
  catches per-stage LLM failures, so a case whose calls *all* failed still wrote
  a row with `error: None`, `n_rules: 0` and 5–8 s elapsed. Because the row
  existed, resume-by-`rule_id` treated the case as done — 14 of 21 rows were
  garbage before it was noticed (kept as `baseline60.jsonl.corrupt.bak`). The
  discriminator is `elapsed_s < 30`. **Open.** Contained for this run by an
  external watchdog that detects a sub-30 s row, stops the run, purges, rebuilds
  the tunnel and resumes; it never had to fire. The proper fix — refusing to
  write a row for a case with zero successful LLM calls — changes harness
  semantics and needs its own change.
- **Defect 13 — an unguarded lazy parse discards the whole request.** Found
  2026-09-14 by reading `backend/pipeline/stage_review.py`. pySigma parses
  conditions lazily, so a malformed condition raises while the `for` header at
  `:306-307` is evaluated, *before* the `try` at `:308`. The exception escapes the
  orchestrator and every rule in the response is lost, including valid ones.
  Observed live once: the Microsoft "Prestige" report failed at 1 min 25 s with
  `Expected end of text, found '*'`, losing all 3 rules. **Open.** In the harness
  it cannot kill a run (each case is wrapped at `run_eval.py:373`) and it would
  appear as a case error; this run recorded none.
- **Defect 14** — fixed as Change 10 above.

### Limitations to disclose
- **One sample, one seed, one model.** n=60 supports "indistinguishable from
  chance" for S3; it does not support fine comparisons between S4/S5 and their
  baselines.
- **S3 at chance is established; its cause is not.** Defect 11 (generation
  ignores the analysis stage's `logsource_suggestions`) is the leading
  hypothesis, but this run does not record the analysis stage's suggestion, so
  it cannot confirm it.
- **The id-replacement rate promised in Change 9 was not measured.** The harness
  does not copy `generation.ids_replaced` into the row, so this run gives no
  denominator. Change 9's frequency limitation still stands.
- The harness keeps neither the response text of a zero-rule case nor a
  per-stage label on LLM calls (every call is recorded as `generate`), which
  prevented diagnosing the two zero-rule cases from the file alone.
- Scoring the first rule is a deliberate choice (it is what a user sees). All
  rules are stored, so best-of-N can be computed later without a rerun.
- Web enrichment was off, and the pretraining-contamination caveat from the
  dataset design applies unchanged.

### Status
First citable result. Defects 4, 5, 6, 9, 11, 12 and 13 remain open.

---

## 2026-09-23 — Change 11: a validator that raises no longer discards the request

### Motivation (defect 13)
Observed live on 2026-09-14: the Microsoft "Prestige" ransomware report failed
after 1 min 25 s with `Expected end of text, found '*'`, and **all three
generated rules were lost** — including any that were valid. The exception
escaped `ReviewStage`, escaped the orchestrator, and ended the request.

### The mechanism, corrected
The earlier write-up (baseline-run entry above, and working notes) attributed
the escape to the condition-resolution loop at `stage_review.py:306-307`. **A
reproduction shows that was wrong.** That loop catches the error correctly and
records it. The escape happens later, in phase 3: `SigmaValidator.validate_rules`
runs pySigma's core validators, one of which re-parses every condition itself
(`sigma/validators/core/condition.py:116`, `condition.parse(False)`). The same
malformed condition raises `SigmaConditionError` again — and phase 3 had no
`try`. The call site (`run`, `:161`) has none either.

Reproduced offline with `condition: selection *`, which yields the exact live
message `Expected end of text, found '*'`.

The evaluation harness was never exposed: its scorer already wraps the same call
(`eval/scorers.py:143-147`). Only the product path lacked the guard.

### Design decisions
| Decision | Rationale |
|---|---|
| Guard phase 3, not the loop the earlier note blamed | The loop was never the problem; guarding it would have changed nothing. Fix where the reproduction shows the raise |
| Catch `Exception`, not only `SigmaError` | pySigma's exception surface is not unified (see Change 1); the scorer makes the same choice for the same reason |
| Record the failure as its own issue, `rule[i].validators` | If validators silently stopped, an empty warning list would read as "passed every validator". Saying the suite did not run keeps the result honest |
| Severity `error` | The rule cannot be trusted if the validators cannot complete; it also triggers the existing single regeneration with the message as feedback |
| Return immediately after recording it | `validate_rules` is all-or-nothing, so there are no partial validator results to keep |

### Verification
1. **Tests written first and seen to fail** with the real `SigmaConditionError`
   (3 failed, 13 passed), then passing after the fix.
2. **3 offline tests** (`tests/test_review_validation.py`): the malformed
   condition is reported rather than raised; the validator-suite failure appears
   as exactly one issue on `rule[2].validators` when checked at index 2; and,
   end to end through `ReviewStage.run`, a response with one valid and one
   malformed rule keeps **both** rules, marks the result invalid, and attributes
   every error to `rule[1]` only. The end-to-end test needs no LLM because the
   syntax-error path returns before the LLM review.
3. Full suite **128 passed** (125 prior + 3), offline.

### Effect on existing results
None. The n=60 baseline recorded zero case-level exceptions, so defect 13 never
fired on that sample and `baseline60.jsonl` remains the valid comparison point.

### Limitations to disclose
- **Frequency is unknown.** One live observation, zero in 60 harness cases. It
  is a robustness fix, not a quality improvement, and should not be presented as
  one.
- A rule with a malformed condition now gets two error messages (the condition
  and the validator suite), and both are passed to the regeneration as feedback.
  Redundant but harmless.
- The orchestrator still has no guard around stages in general. An unexpected
  exception in any *other* stage still ends the request. This change closes the
  one path that was observed.

### Status
Defect 13 closed. Defects 4, 5, 6, 9, 11 and 12 remain open.

---

## 2026-09-23 — Defect 15 measured: the attack-vector stage reproduces its own prompt examples (measurement, no change to the system)

### How it was found
While testing whether Foundation-Sec-8B could run the attack-vector stage (it
could not; the decision since is to keep every stage on `qwen3-coder:30b`),
qwen itself returned, for a Windows "Defrag Deactivation" rule, the attack
vector "Unauthenticated HTTP POST to /saml/login with a crafted SAMLRequest
body". That is the illustrative example in the field description of
`ATTACK_VECTOR_EXTRACTION` (`prompts.py:560`). The source text contains no
"saml" anywhere.

### Method
`eval/probe_attack_vector.py` reruns **only** the stages that feed the
attack-vector prompt (preprocess → PoC analysis → attack vector) through the
real orchestrator's stage objects, on the **same 60 `rule_id`s** as
`baseline60.jsonl`, and stores the full attack-vector output, which the harness
does not keep. Output: `eval/results/av60.jsonl`. 15.1 minutes.

Two criteria were fixed, and covered by 6 offline tests
(`tests/test_probe_attack_vector.py`), **before** the run was looked at:

- **M1 — example leak.** The output contains a marker string that exists only in
  the prompt's examples (`/saml/login`, `SAMLRequest`, `NSC_TASS`, `patch.nss`,
  `remoteVersion`, `BT26-02`, `thin-scc-wrapper`, `sedcp`, the example's patch
  password, `oopsie`) **and** that marker is absent from the text the model was
  given (the source cut to 8000 characters plus the PoC behaviours). Generic
  patterns the prompt also mentions (`$(`, `../../etc/passwd`, `rO0AB`) are
  excluded, because a model may legitimately infer them from a vulnerability
  class.
- **M2 — quote verification.** Each payload signature's `derived_from` is
  specified as a quote from the input. Share found verbatim after lower-casing
  and collapsing whitespace; `inferred_from_class` excluded.

Gates: `snapshots_missed == 0` on all 60. One case (`47a1658b`) failed inside
the stage with a JSON parse error and returned the empty default; it is kept in
the denominator (it cannot leak), and the rate over 59 is given alongside.

### Result
| Measure | Value | Wilson 95% CI |
|---|---|---|
| **M1: cases whose output contains prompt-example content absent from the input** | **13/60 = 21.7%** (13/59 = 22.0%) | 13.1–33.6% |
| … of which in the attack vector itself (vector, entry point, attacker input, signatures) | 11/60 = 18.3% | 10.6–29.9% |
| … only in the incidental-artifacts list | 2/60 | — |
| M1 when the PoC stage found no code | 10/27 = 37.0% | 21.5–55.8% |
| M1 when the PoC stage found code | 3/33 = 9.1% | 3.1–23.6% |
| **M2: `derived_from` quotes found verbatim in the input** | **54/203 = 26.6%** | 21.0–33.1% |
| M2 in leak cases / clean cases | 5/41 / 49/162 | — |

By example: the SAML example (A and the inline example) appears in 12 of the 13
leak cases, the WebSocket example (B) in 6 (they overlap). **12 of the 13 leak
cases name `webserver_access_log` as the primary telemetry, while the gold rule
is a web or proxy rule in only 2 of them** — the rest are Windows process,
file-event and security rules.

### Mechanism (inspected, not yet measured)
For 3 of the 13 leak cases (`92389a99`, `c601f20d`, `29fd07fc`) the first 8000
characters of the text the stage receives were inspected by hand. **In all
three, the entire window is website navigation and boilerplate** — GitHub's
repository chrome, Kaspersky's product menus, Mandiant's marketing blocks — and
the article itself starts after it. The stage cuts the text at 8000 characters
(`stage_attack_vector.py:70`), so the model never saw the write-up, and filled
the gap from the only concrete attack descriptions in its context: the prompt's
examples. The PoC split above fits this: when code snippets are present they give
the model real material even when the page text is boilerplate.

`_extract_page_content` removes `nav`, `header`, `footer` and similar tags
(`stage_preprocess.py:99-101`), but these sites build their menus from generic
elements, which survive.

**The same exposure applies to the analysis stage, which reads only the first
4000 characters** (`stage_analysis.py:53`). That stage produces the indicators,
the ATT&CK mapping and the logsource suggestions, so on these pages those are
also derived from boilerplate. Generation never sees the raw text at all — only
the stage outputs.

### Association with the baseline scores — not established
On the same 60 cases, the baseline run's first rule matched the gold logsource
in **0 of the 13** leak cases against **8 of 42** others (scored cases only).
One-sided Fisher exact test **p = 0.097: not significant at this n.** The
baseline run is also a different execution, so its attack-vector output for
these cases is unknown; the input it received, however, was identical (same
snapshots, same truncation). This is an association worth testing, not a
finding.

### Limitations to disclose
- **M1 is a lower bound** on example contamination: it only detects the invented
  marker strings. A copy that paraphrases the example, or that reuses a generic
  phrase, is not counted.
- **M2 is an upper bound** on invented quotes: a miss means "not verbatim",
  which includes honest paraphrase and quotes altered by text extraction.
- One run at temperature 0; Ollama output is not bit-for-bit repeatable, so the
  rate would move somewhat on a rerun (the smoke run and the full run both
  produced a leak on `c5a178bf`).
- The boilerplate mechanism was confirmed by inspection on 3 of 13 leak cases
  only. How often the 4000/8000-character windows miss the article across the
  corpus is **not yet measured**.
- The PoC stage fetches GitHub **live**, outside the harness's snapshot shim —
  recorded below as candidate defect 16 — so the PoC inputs of this run may differ
  from the baseline run's.

### Candidate defect 16 — the PoC stage bypasses the snapshots
`stage_poc_analysis.py:124` and `:149` call `requests.get` on GitHub raw and API
URLs. The harness replaces `requests` only inside `stage_preprocess`, so these
fetches go to the live network and are invisible to the `snapshots_missed`
gate. Cases whose references include GitHub are therefore not fully offline-
reproducible. **Open.**

### Status
Defect 15 confirmed as systematic: roughly one case in five. Candidate
mechanism: the fixed-size input windows are filled with page boilerplate.
Defects 4, 5, 6, 9, 11, 12, 15 and 16 are open. No system code changed.

---

## 2026-09-23 — Change 12: the attack-vector and analysis stages read the whole source

### Motivation (defect 15)
The defect-15 measurement (previous entry) found the attack-vector stage
reproducing its own prompt examples, and traced it on inspected cases to a fixed
input window filled with site navigation. Measured across all 303 cases,
offline: the extracted text fits entirely inside the analysis stage's
4000-character window in **23/303 (8%)** cases and inside the attack-vector
stage's 8000 in **66/303 (22%)**. Median length is 19,158 characters, p95
59,167, maximum 79,800. For most inputs, both stages were working from the
opening of the page — which on many sites is navigation — and never from the
write-up itself.

### Design decisions
| Decision | Rationale |
|---|---|
| One named limit, `SOURCE_TEXT_MAX_CHARS = 100_000`, in `base_stage.py` | Two unrelated magic numbers become one stated, citable bound shared by both stages |
| 100,000 characters | Covers the longest text in the corpus (79,800), about 25k tokens with the template. Unbounded input would make prompt size depend on whatever a page contains |
| `PipelineStage.source_text()` logs every cut | A page longer than the bound cannot silently lose its end the way the old windows lost everything after the start. Zero cuts occurred in the measurement below |
| Rely on the server's context, and check it | The Spark's Ollama 0.34.1 loads `qwen3-coder:30b` with a **262,144-token** context (`ollama ps`, confirmed during the run). The code sets none, so this is a preflight check, not a guarantee — added to the run recipe |
| Leave other slices alone | `combined_text[:500]` in the analysis stage is a RAG *query* and a failure fallback, not model input; the PoC and enrichment caps bound different inputs. One change at a time |
| Measurement script uses the stage's own method | `eval/probe_attack_vector.py` rebuilt the model input with a hard-coded 8000; left unchanged, its leak check would have tested against text the model no longer receives |

### Verification
1. **5 offline tests** (`tests/test_source_window.py`), written first and seen
   to fail (3 of 5) against the old windows: a marker placed 30,000 characters
   into the source reaches the prompt of both stages; the bound covers the
   longest corpus text; text past the bound is cut *and* the cut is logged;
   text inside it is not reported as cut. Full suite **139 passed**.
2. **Defect-15 measurement rerun** on the same 60 `rule_id`s, same model, same
   criteria: `eval/results/av60_window.jsonl` against `av60.jsonl`. Gates: 0
   snapshots missed, 0 stage failures (1 before), 0 cuts logged. Paired
   comparison, exact McNemar test on the discordant cases:

   | Measure | Before | After | Paired |
   |---|---|---|---|
   | Example content **in the attack vector itself** (vector, entry point, input, signatures) | 11/60 (18.3%) | **4/60 (6.7%)**, CI 2.6–15.9% | 8 fixed, 1 new, **p = 0.039** |
   | Example content anywhere in the output | 13/60 (21.7%) | 10/60 (16.7%) | 7 fixed, 4 new, p = 0.55 |
   | … of which only in the incidental-artifacts list | 2 | 6 | — |
   | `derived_from` quotes found verbatim | 54/203 (26.6%) | 64/250 (25.6%) | unchanged |
   | Web-server telemetry chosen when the gold rule is not web/proxy | 23/48 | 21/48 | 4 fixed, 2 new, p = 0.69 |
   | Median model input | 8,529 chars | 22,358 chars | — |
   | Time for preprocess + PoC + attack vector | 15.1 min (median 13.6 s) | 19.0 min (median 16.6 s) | +26% |

### Interpretation
- **The harmful form of defect 15 is largely fixed.** Copying into the fields
  that anchor generation fell from 11 to 4 cases, and the paired test clears
  0.05. What remains is mostly Example B's patch filenames listed as
  "incidental artifacts" — noise sent to a blacklist, not a detection anchor.
- **The web-telemetry bias is a separate problem, and the window did not touch
  it.** Almost half of the non-web cases (21/48) are still told their primary
  telemetry is a web-server log. Two of the three worked examples and most of
  the inline examples in `ATTACK_VECTOR_EXTRACTION` are web exploits, and the
  field is defined as where "the initial exploit" would be visible — whereas
  many gold rules in this corpus detect post-exploitation behaviour on the host.
  **Hypothesis, not measured.** Recorded because it bears directly on S3.
- **Quote fidelity is not a window problem either**: about a quarter of quotes
  are verbatim before and after, so the model paraphrases what it cites.

### Limitations to disclose
- Only the **attack-vector stage** is measured here. The analysis stage's window
  grew tenfold (4000 → 100,000) and its effect on the indicators, ATT&CK mapping
  and logsource suggestions — and therefore on S1–S5 — is **unmeasured** until
  the 60-case harness rerun.
- One run per condition. Ollama output at temperature 0 is not bit-for-bit
  repeatable, so part of the case-level churn (1 new core leak, 4 new
  anywhere-leaks) is run-to-run variation rather than an effect of the change.
- The boilerplate itself is still in the text; the article is now *included*,
  not *isolated*. Extraction quality (defect 9) is untouched.
- The PoC stage still fetches GitHub live (candidate defect 16), so PoC inputs
  may differ between the two runs.
- Cost moves the wrong way by design: +26% wall time on these stages, and
  larger prompts on the analysis stage as well.

### Status
Defect 15's harmful form reduced (p = 0.039); residual incidental-list noise and
a separate web-telemetry bias remain. Next: the 60-case harness rerun to measure
the effect on S1–S5.

---

## 2026-09-23 — Housekeeping: archived stages removed, stale worktree retired (no change to behaviour)

From a read-only audit of the repository (import graph from every entry point:
the web app, the evaluation scripts, the ingestion scripts and the tests).

- **Removed `backend/pipeline/archive/`** — five stages from the original linear
  pipeline (`stage_extract`, `stage_ttp_map`, `stage_logsource`, `stage_validate`,
  `stage_optimize`) and their README. Nothing imported them, no document referred
  to them, and their own README declared them safe to delete. They remain in git
  history. Verified: full suite **139 passed**; the orchestrator and agent import.
- **Retired the worktree `.claude/worktrees/kind-davinci`** (last worked on March
  2026, never part of main). All its commits were already in main. Its 16
  uncommitted files were first committed onto its own local branch
  (`claude/kind-davinci`, `c871f69`) so nothing is lost: 13 were identical to
  versions already in history and 3 were early drafts that main has since
  superseded (every class and prompt template in them exists in main).

Not removed, by decision: `backend/pipeline/schemas.py` is imported by nothing,
but may be reused for the assistant's report contract (plan H6). Every result
file under `eval/results/` stays.

---

## 2026-09-23 — Evidence files committed; a clarification on defect 12's count

Two result files that earlier entries cite as evidence were on disk but not in
git, because `.gitignore` excludes `*.bak`. They are now committed under their
**original names** (force-added), so the citations resolve for anyone reading
the repository:

| File | Cited by | Content |
|---|---|---|
| `eval/results/baseline60.jsonl.corrupt.bak` | baseline-run entry, defect 12 | 21 rows from the 2026-09-13 attempt, written while the backend was unreachable |
| `eval/results/baseline60.prefix-fix.bak` | Change 10, before/after table | the n=60 run before the 4 defect-14 rows were purged and rerun (4 missed snapshots) |

**Clarification on "14 of 21 rows were garbage"** (baseline-run entry). The
number is right, but that entry's one-line discriminator, `elapsed_s < 30`,
catches only 13 of them. Re-reading the committed file:

- 13 rows (5.5–7.8 s) had every LLM call fail and recorded 0 tokens — the
  signature the entry describes.
- The 14th, case `43259cc4`, was the case in progress when the VPN dropped: it
  hung for **12,989.5 s** (3.6 h) with one failed LLM call, yet still recorded
  4 rules and 26,087 tokens. The sub-30 s rule does not catch it; the telemetry
  gate `n_errors == 0` does, as does the watchdog's upper bound of 1000 s.

This is the case for keeping all five gates rather than the time rule alone: the
two failure shapes need different gates.

Two further files remain uncommitted on disk, deliberately: `baseline60.2026-09-13.jsonl`
(9 clean rows from the abandoned attempt) and `smoke.jsonl` (the 2-case preflight);
nothing cites them. Nothing under `eval/results/` is deleted.

---

## 2026-09-23 — Security: the Gemini API key was exposed in public git history (key now deleted)

### Finding
During the repository audit, a scan of the old worktree found the **complete
Gemini API key** — identical to the one in `.env` — inside `rest_list.txt`, a
console log from the Windows period of the project. It was committed in
`3b29a42` ("Full project upload for migration to Mac") and deleted in `7271080`;
both commits are on the pushed `main`, and both GitHub repositories that carry
this project are public. The key had been reported suspended since 2026-09-11
(`403 CONSUMER_SUSPENDED`); public exposure is the likely reason — Google
disables keys it finds on public GitHub. The key was deleted by the user on
2026-09-23, so the copy in history is now inert.

### Why an earlier check missed it
An earlier `git log --all -S` search concluded the key was in no commit. That was
wrong: `rest_list.txt` is **UTF-16** text (PowerShell output). Git sees its NUL
bytes, classifies it as binary, and neither `-S` nor `git grep` (even with `-a`)
matches an ASCII pattern against two-byte characters. The finding came from
macOS `grep`, which decodes UTF-16 with a byte-order mark.

### Verification that nothing else is exposed
Every blob in the repository's history was scanned, decoding UTF-16 and
NUL-heavy blobs first (17 of them): Google API keys, OpenAI-style keys, GitHub
tokens, private-key headers and `OLLAMA_API_KEY` assignments. **One hit only —
this file.** The Ollama key added on 2026-09-23 lives only in the gitignored
`.env`.

### Decisions
- **History is not rewritten.** With the key deleted there is nothing left to
  protect, and a rewrite would mean force-pushing both public repositories.
- Lesson recorded for future scans: decode before searching; a clean
  `git log -S` is not evidence of absence for non-UTF-8 files.

### Effect on the thesis
None on the measurements: every run since 2026-09-11 has been all-local on
Ollama. It does mean the Gemini thinking-token path of C1 stays unverified, and
contribution 2 (cloud/local routing) stays blocked unless a new key is created.

---

## 2026-09-23 — Housekeeping: `schemas.py` removed (no change to behaviour)

The housekeeping entry above kept `backend/pipeline/schemas.py` pending a
decision. Checked against the real pipeline before deciding:

- Imported by nothing (import graph from every entry point) — so nothing
  validated any data against it.
- It had drifted from what the pipeline actually produces. `PipelineMetadata`
  declared 8 fields; the dict `orchestrator._format_output` really returns has
  15. Ten real fields were absent — including `attack_vector` and
  `coverage_check` — and three declared fields no longer exist. There was no
  model for the attack-vector output at all, although that stage anchors the
  rest of the pipeline.

A schema that nothing enforces and that describes a different system misleads
more than it documents. Removed; it remains in git history. The assistant's
report (plan Phase 3) will get its own contract, one the code actually checks.
Also removed the file, and the `archive/` directory deleted earlier, from the
README's project tree.

Verified: no remaining references in code or documentation; full suite **139
passed**; `backend.main` imports. Pydantic stays a dependency (`backend/main.py`
uses it for the API models).
