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
In the default hybrid configuration **only economy-tier calls reach Ollama**;
attack-vector extraction, analysis and generation all use the Gemini *primary*
tier. A 303-case run would issue roughly 900 primary-tier calls against a 9 RPM
limit. This corrects an earlier working assumption that a local run costs "time,
not tokens". The runner prints the warning before starting and the docstring
states that `LLM_PROVIDER=ollama` is required for a genuinely zero-cost run.

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
