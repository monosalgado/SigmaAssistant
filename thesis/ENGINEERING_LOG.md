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

---

## 2026-09-23 — The web server binds to this machine only (security hardening)

The documented run commands in `README.md` and `run_mac.sh`, and the
`python backend/main.py` entry point (`backend/main.py:382`), started the server
on `0.0.0.0` — every network interface. On a shared network (campus, café,
conference Wi-Fi) anyone could reach the API directly: it has no
authentication, so a stranger could run the pipeline on this machine's
resources and read the stored sessions and saved rules. The existing CORS
restriction does not prevent this — CORS governs what *web pages in a browser*
may call, not direct requests from another host.

All three now bind to `127.0.0.1`. `ALLOWED_ORIGINS`, which `backend/main.py`
reads, is now documented in `.env.example` (commented out, so the local-only
default applies).

Verified: `bash -n run_mac.sh`; `backend/main.py` compiles and imports; with
`ALLOWED_ORIGINS` unset the CORS list is still
`['http://localhost:8000', 'http://127.0.0.1:8000']`; full suite **139 passed**.
No change to pipeline behaviour, so no measurement is needed.

Left for the documentation rewrite (plan H5b): the setup documents are still
Gemini-first, and `.env.example` still lists `gemini` as the only supported
`LLM_PROVIDER`.

---

## 2026-09-23 — Change 13 (plan 1.1a): every LLM call records which stage made it

### Motivation
Each result row lists its LLM calls, but every call recorded
`operation: "generate"`. The only way to tell the attack-vector call from the
analysis call was their position in the list, and that shifts whenever the PoC
stage finds code or a regeneration runs. The per-stage prompt sizes reported on
2026-09-23 had to be restricted to the 18 cases with exactly four calls for this
reason. Phase 1's diagnosis of the logsource failure needs to attribute tokens,
time and failures to stages without guessing.

### Design decisions
| Decision | Rationale |
|---|---|
| A context variable set by `stage_scope()` and read by `LLMTelemetry.record()` | The clients stay untouched: the Ollama and Gemini clients already call `record()`, and the stage is picked up there. No signature change ripples through the clients |
| Set in `PipelineStage.llm_call`, around the client call | One place covers every stage, including a failed call and the hybrid client's fallback to Gemini |
| Context variable, not a global | The web server runs requests on worker threads; each thread keeps its own value, so concurrent requests cannot mislabel each other |
| The orchestrator's two direct calls are labelled too (`intent_classification`, `conversational`) | They bypass `llm_call`. Calls outside any stage (e.g. translation) record `None`, which says so rather than guessing |
| New field `stage` on `LLMCall`, default `None` | Older result files without the field remain readable |

### Verification
Tests written first; the three wiring tests were seen to fail before the stages
set the label. **7 offline tests** in `tests/test_telemetry.py`: no stage outside
a scope; labelled inside; restored after an exception; survives `as_dicts()`
(what the harness writes); a real stage through the **real** `OllamaLLMClient`
(only its network call faked) records its name; a *failed* call is still
attributed to its stage; the orchestrator's intent call is labelled. Full suite
**146 passed**; `backend.main` imports. No change to what the pipeline outputs.

---

## 2026-09-23 — Change 14 (plan 1.1b): pipeline crashes reach the harness (defect 17)

### Motivation (defect 17)
Found while starting plan task 1.1. The harness called
`agent.analyze_attack`, which wraps `orchestrator.run_sync` in
`except Exception` and returns the error as ordinary response text
(`backend/agent.py:36`: `"Error during analysis: <e>"`). The harness's own
exception handler therefore never saw a pipeline crash. A crashed case was
written as a normal row: `error: None`, zero rules, the error message as its
"response".

### This corrects two earlier claims
- The baseline-run entry states that a pipeline exception "would appear as a
  case error; this run recorded none". **It would not have appeared.** Gate 4
  ("every `row["error"]` is `None`") was vacuous for pipeline crashes in
  `baseline60.jsonl`; "zero case exceptions" there is not evidence that none
  occurred.
- The two zero-rule cases of that run (`43259cc4`, `ec3a3c2f`) both returned an
  **86-character** response. The orchestrator's no-rule fallback is 88
  characters, so it was not that; `"Error during analysis: "` (23) plus a
  63-character exception message fits exactly. **Consistent with two identical
  swallowed crashes, not proven** — the response text was not kept (plan 1.1c
  fixes that). The baseline's S1 figure (55/60 valid) is unaffected either way;
  what changes is the *reason* two of its five failures are recorded as
  "no rule".

### Design decisions
| Decision | Rationale |
|---|---|
| The harness calls `agent.orchestrator.run_sync` directly | `analyze_attack` is a print, this same call and the catch-all. Calling `run_sync` measures the identical pipeline, and a crash reaches the harness's handler with its full traceback |
| No change to `backend/agent.py` | The web app returns the agent's dict straight to the browser (`backend/main.py:215`); adding a traceback there would leak stack traces to users. The web app's behaviour is untouched |
| Snapshot counts recorded in a `finally` | Gate 1 stays computable for crashed rows too; previously a crash left the row without them |
| Loop body moved into `run_case()` | Makes one case testable with a stand-in pipeline, offline. Pure extraction otherwise; `main()` still writes one row per case and counts successes and failures from `row["error"]` |

### Verification
Tests written first. After extracting `run_case` *unchanged* (still calling
`analyze_attack`), the crash test **failed** with the row reporting
`error: None` — the defect reproduced. After switching to `run_sync`, 3 offline
tests pass (`tests/test_eval_runner.py`): a normal response is scored; a crash
becomes a case error carrying its traceback, with no scores; snapshot counts
survive a crash. The stand-in agent copies the real agent's catch-all, so a
regression to `analyze_attack` would fail the test. Full suite **149 passed**;
`--dry-run` still selects the same 60 of 303 cases.

### Status
Defect 17 fixed. From the next run on, gate 4 means what it says.

---

## 2026-09-23 — Change 15 (plan 1.1c): each result row keeps the pipeline's intermediate results

### Motivation
`baseline60.jsonl` recorded the final rules and their scores, but not what the
stages concluded on the way. It could say *that* logsource matched gold in only
8 of 55 cases, not *why*: whether the analysis stage suggested the wrong source,
the attack-vector stage pointed elsewhere, or generation ignored a correct
suggestion (defect 11). Nor could it support the invalid-id rate promised in
Change 9, or say what the two zero-rule cases actually returned. The pipeline
already computes all of this and returns most of it in `pipeline_metadata`; the
harness discarded it.

### Design decisions
| Decision | Rationale |
|---|---|
| A named tuple of fields, `DIAGNOSIS_FIELDS`, copied into `row["pipeline"]` | Explicit about what is kept: attack vector, attack summary, indicators, ATT&CK mappings, logsource suggestions and primary, suggested log sources, coverage check, review's validation issues, PoC snippet count, generation log, retry flag. Enrichment sources are left out — always empty on the all-local setup |
| The generation stage appends one entry per call to `context["generation_log"]` (`{"rules", "ids_replaced"}`) | A regeneration *replaces* `context["generation"]`, so its `ids_replaced` alone would lose the first call. The log keeps every call and gives the invalid-id rate its full denominator |
| `pipeline_metadata` gains `generations` and `generation_retried` | The web API returns the same dict; the frontend reads only named keys (`indicators`, `ttp_mappings`, `validation_issues`), so nothing new appears in the UI |
| `response_text` stored only when no rule was extracted | That is the case where nothing else can be inspected. With rules present, `rules_yaml` already holds them and the full text would roughly double the file |
| `pipeline_metadata` of `None` gives an empty dict | Conversational answers return `None`; the row must still be written |

### Verification
Tests written first; 6 of 7 were seen to fail, the generation test for the right
reason (the stage ran; only the log was missing). **7 offline tests**:
`tests/test_diagnosis_fields.py` (every generation call is logged across a
regeneration; the output exposes the log and retry flag; defaults when nothing
was generated) and `tests/test_eval_runner.py` (the row keeps the diagnosis
fields and drops the excluded one; the response text is kept when no rule is
extracted and not duplicated when rules exist; missing metadata does not break
the row). Full suite **156 passed**; `backend.main` imports.

### Limitations
- Not yet exercised against the live model — the baseline-v2 run (plan 1.5) is
  the first. The fields come from the same dict the web UI already renders, so
  the risk is low, but it is untested live.
- Rows grow by the size of these fields (a few KB each); acceptable at n=60.

### Status
Plan task 1.1 complete: stage labels (Change 13), crashes reach the harness
(Change 14), intermediate results kept (Change 15).

---

## 2026-09-23 — Change 16 (plan 1.2): a case with a failed LLM call stops the run instead of being written (defect 12)

### Motivation (defect 12)
Every stage catches its own failed LLM call and continues on an empty default.
With the backend unreachable a case therefore "completed" in seconds with zero
rules, and its row was written; because resume skips any `rule_id` already in
the output, the case was never rerun. 14 of 21 rows of the 2026-09-13 attempt
were such rows. Until now only an external watchdog script caught this, by
purging suspicious rows after the fact.

### The rule — broader than the plan's first wording
The plan said "refuse to write a row for a case with zero successful LLM
calls". Re-reading the committed evidence showed that is too narrow. The 14
bad rows have two shapes: 13 where every call failed within ~6 s, and one
(`43259cc4`) with **1 failed call of 5** that hung for 12,990 s and still wrote
rules. A zero-successes rule misses the second. The rule implemented is:

> **A row is written only if every LLM call of the case succeeded.** Otherwise
> the run stops at that case without writing its row, naming the case, the
> failed stages and the first error; rerunning the same command resumes from
> that case. The process exits with status 2, so a wrapper can tell "stopped"
> from "finished".

A pipeline **crash** whose LLM calls all succeeded is still written, as an
error row (Change 14): that is a finding about the pipeline, not about the
connection.

### Design decisions
| Decision | Rationale |
|---|---|
| Decide from the recorded calls (`llm_calls[].ok`), not from elapsed time | Time was a proxy with two thresholds (under 30 s, over 1000 s) and caught the two shapes by different rules. The failed call is the cause itself |
| Stop, rather than skip and continue | A failed call almost always means the backend is down; continuing would fail every remaining case. Stopping loses nothing, since the unwritten case reruns on resume |
| Loop moved into `run_cases()` | Testable offline with a scripted stand-in pipeline that records successful and failed calls through the real telemetry |
| The message states which stages failed | Uses the stage labels from Change 13 |

### Verification
Tests written first. After extracting the loop *unchanged*, the three stop tests
**failed** — the failed case's row was written — reproducing the defect. **5
offline tests** (`tests/test_eval_runner.py`): a clean run writes every case;
all calls failing stops without writing the row and never starts the next case;
one failed call of five also stops; a crash with every call successful is
written as an error row and the run continues; the stop message says how to
resume. Full suite **161 passed**; `--dry-run` unchanged.

**Against the real evidence** (committed files, no fakes):
`baseline60.jsonl.corrupt.bak` → **14 of 21 rows refused** — exactly the 13 fast
rows plus the one that hung — each with `APIConnectionError`.
`baseline60.jsonl` and `baseline60.prefix-fix.bak` → **0 of 120 refused**.

### Consequences
- Gate 3 (`n_errors == 0`) now holds by construction for every row a run writes.
  The five gates are still checked on every file, since they cost nothing.
- The external watchdog's purge logic is obsolete. What remains useful is
  relaunching after a reconnect when the run exits with status 2 — plan 1.4.

### Limitation
A case that fails *deterministically* on one LLM call (for example a request the
server always rejects) would stop the run at the same place every time. That is
visible, not silent, and has not been observed; it would need an explicit
decision if it happens.

### Status
Defect 12 fixed.

---

## 2026-09-23 — Live check of Changes 13 and 16; defect 16 measured; a contamination finding

### Changes 13 and 16, checked live
With the model deliberately unreachable (no VPN, no tunnel), a one-case run of
the real harness (`--sample 60 --seed 0 --limit 1`) **exited with status 2 and
wrote no row**, reporting `5 of 5 LLM calls failed (stages: analysis,
attack_vector, generation, poc_analysis); first error: APIConnectionError`.
That exercises the stop rule (Change 16) end to end, and shows the stage labels
(Change 13) arriving through the real Ollama client, not only through the
test's stand-in.

### Defect 16 — the PoC stage fetches GitHub live, outside the snapshots
`stage_poc_analysis.py:118-165` takes up to three GitHub file links
(`github.com/<owner>/<repo>/blob/...`, fetched from `raw.githubusercontent.com`)
and up to two gists (`api.github.com`) from anywhere in the text. The harness
replaces `requests` only in the preprocess stage, so these fetches go to the live
network, invisible to the `snapshots_missed` gate. Measured offline by applying
the stage's own patterns to the snapshot text of every case:

| | All 303 cases | 60-case sample |
|---|---|---|
| Cases that trigger live GitHub fetches | **43** | **10** |
| File fetches / gist fetches | 72 / 9 | 18 / 2 |

Those cases are not reproducible offline, and their PoC input can change as the
repositories change. **Open.**

### Finding: some cases put a detection rule in front of the pipeline
Checking what those fetches retrieve showed that some are **detection rules, not
exploit code**: rules from the SigmaHQ repository itself, Rapid7's own Sigma rule
for CVE-2024-3400 (case `f130a5f1`, whose gold rule covers the same CVE), The DFIR
Report's Sigma rules for Bumblebee (`994cac2b`), Azure Sentinel detections, a
nuclei template. The input itself can carry a rule too: some cases' reference
URLs *are* rule files or rule repositories, and some pages print a Sigma rule in
the article.

| Route by which a detection rule reaches the pipeline | All 303 | Sample of 60 |
|---|---|---|
| The PoC stage downloads a rule-like file | 13 | 4 |
| An input URL is a rule file or rule repository | 10 | 1 |
| A Sigma rule is printed in the page text | 7 | 1 |
| **Any of these** | **23 (7.6%)** | **5** |

Sample cases affected: `7b501acf`, `994cac2b`, `a62298a3`, `e710a880`, `f130a5f1`.

This is **not a defect in the product** — an analyst whose source includes a rule
is well served by the pipeline reading it. It is a threat to the **validity of
the evaluation**: on these cases the task is partly "adapt a rule that is
already there", which can inflate the scores. In baseline v1 the flagged cases of
the sample scored higher (logsource exact 0.50 vs 0.13), but on two cases that is
an anecdote, not evidence.

Definitions used, to be disclosed with any number: "rule-like file" = a GitHub
blob path in the SigmaHQ organisation, under a `sigma`/`sigma-rules` directory,
in Azure Sentinel's `Detections`, in `nuclei-templates`, or ending in
`.yml`/`.yaml`; "Sigma rule in the text" = `logsource:`, `detection:` and
`condition:` within 3,000 characters. The `.yml` criterion over-counts — case
`e710a880` downloads a YAML file of TTPs, not necessarily a detection rule — so
23 is an upper bound under this definition.

### Status
Nothing changed in the code. How to handle both findings is a methodological
decision (plan 1.3a, 1.3b), taken before baseline v2 runs.

---

## 2026-09-23 — Change 17 (plan 1.3a): the PoC stage's GitHub fetches are served from snapshots (defect 16)

### Motivation (defect 16)
The PoC stage fetched GitHub files and gists live during evaluation, outside the
page snapshots: 43 of 303 cases (10 of 60) were not reproducible, and their input
drifted as repositories changed. Measured before storing anything, **10 of the 45
linked files already returned 404** — the drift is real, not hypothetical. Chosen
approach (decision A, user, 2026-09-23): snapshot the fetches, as the pages are,
rather than block them, so the evaluation keeps measuring the pipeline that
actually runs.

### Design decisions
| Decision | Rationale |
|---|---|
| `github_fetch_targets(text)` extracted from the stage and shared with the builder | What gets stored is, by construction, what the stage asks for. The stage's patterns, caps (3 files, 2 gists) and order are unchanged |
| `eval/build_poc_snapshots.py` fetches each unique URL once | Bodies go to `eval/snapshots/github/` (gitignored, like the pages); `eval/github_manifest.jsonl` is committed with status, size, SHA-256 and fetch time per URL |
| A 404 is recorded and replayed as a 404 | The file was gone at snapshot time; replaying that is faithful. A network error is *not* recorded, so a rerun retries it |
| Idempotent | URLs already in the manifest are never refetched |
| Harness shim for the PoC stage's `requests`, like the page shim | A URL in the manifest is served from disk; one not in it gets 404 and increments `poc_snapshots_missed`, so a live fetch cannot happen unnoticed |
| New per-row counters `poc_snapshots_served` / `poc_snapshots_missed` | Gate 1 now requires both `snapshots_missed == 0` and `poc_snapshots_missed == 0` |
| The defect-15 measurement script uses the same shim | Its two earlier files fetched live; disclosed in its docstring |

### Verification
Tests written first. **12 offline tests**: `tests/test_poc_github_targets.py`
(file links become raw URLs capped at three; gists capped at two; no links, no
targets; a ref containing a dot such as `v1.2` is *not* matched — existing
behaviour, pinned and noted in the plan's Inbox rather than changed) and
`tests/test_poc_snapshots.py` (the builder records every URL with its status and
does not refetch; a stored file is served with its content; gist JSON is served;
a recorded 404 is replayed and not counted as a miss; an unknown URL is a counted
miss; `requests` is restored after an exception; and the **real** `PoCAnalysisStage`
reads the snapshot, with the stored content reaching the model's prompt). Plus a
runner test that crashed rows keep the PoC counters. Full suite **173 passed**.

On the real corpus: the shared function reproduces the pre-refactor measurement
exactly (43 cases, 72 file + 9 gist fetches, 45 + 5 unique URLs). The builder
stored **40** bodies (575 KB) and recorded **10** 404s, 0 failures; all 50 targets
of the 303 cases are in the manifest; a second run fetched nothing.

### Disclosure for earlier results
`baseline60.jsonl`, `av60.jsonl` and `av60_window.jsonl` were produced with live
GitHub fetches, so the PoC input of their 10 affected cases may differ from the
snapshot. From baseline v2 on, it is fixed.

### Status
Defect 16 fixed.

---

## 2026-09-23 — Change 18 (plan 1.3b): contaminated cases are flagged and reported separately

### Motivation
The previous entry found that in 23 of 303 cases (5 of 60) a detection rule
reaches the pipeline — through a PoC download, a reference that is itself a rule
file, or a Sigma rule printed in the page. Chosen handling (decision a, user,
2026-09-23): **keep the cases, flag them, and report them separately**, with the
headline on the clean cases. Dropping them would lose data and change the
sample; only disclosing them would leave "did the input contain the answer?"
without a measured answer.

### Design decisions
| Decision | Rationale |
|---|---|
| The definition lives in one pure function, `eval/contamination.py` | Three named routes, each returned with its detail (the URL or file), so any flag can be checked by hand. The docstring states the definition and that the `.yml` criterion over-counts |
| A committed list, `eval/contamination.jsonl`, written by `eval/flag_contamination.py` | Every case appears — clean or flagged — with its reasons. Deterministic (snapshots + the PoC stage's own fetch targets, no network, no LLM), reviewable, and citable |
| The harness attaches each case's flag to its row | A case missing from the list is recorded as `None` — unknown, never assumed clean |
| The summariser reports all / clean / flagged | Older result files have no flag field; the committed list is applied by `rule_id`, so earlier runs can be split too |

### Verification
Tests written first. **14 offline tests**: `tests/test_contamination.py` (an
ordinary article is clean; a Sigma rule in the page is flagged; the three keys
far apart are not; a reference that is a rule file, or into the SigmaHQ repo, is
flagged; PoC downloads from SigmaHQ or Sentinel detections are flagged; exploit
code is not; each reason carries its detail), `tests/test_eval_summarise.py`
(split by the row's own flag; older rows split by the committed list; a case in
neither place is unknown), and `tests/test_eval_runner.py` (the row carries the
flag; an unflagged case records `None`). Full suite **187 passed**.

The committed list reproduces the earlier measurement **exactly**: reference 10,
in text 7, input 17, PoC 13, **union 23 of 303**; the same 5 sample cases
(`7b501acf`, `994cac2b`, `a62298a3`, `e710a880`, `f130a5f1`). `--dry-run` reports
5 of 60 flagged, none without a flag.

### Baseline v1, split
| | All 60 | Clean (55) | Flagged (5) |
|---|---|---|---|
| S1 valid Sigma | 0.917 | 0.909 | 1.000 |
| S3 logsource exact | 0.145 (n=55) | 0.140 (n=50) | 0.200 (n=5) |
| S4 ATT&CK F1 | 0.123 (n=37) | 0.120 (n=34) | 0.167 (n=3) |
| S5 detection F1 | 0.205 (n=53) | 0.208 (n=49) | 0.167 (n=4) |

**The headline does not depend on the contaminated cases**: on the clean cases
every metric moves by at most 0.008. The flagged subset is too small (n=3–5) to
support any conclusion about it. The earlier "0.50 vs 0.13" was an anecdote on 2
cases and does not hold on 5.

### Status
Plan 1.3 complete: defect 16 fixed (Change 17), contamination flagged and
reported (Change 18).

---

## 2026-09-23 — Change 19 (plan 1.4a): the summariser checks whether a result file is citable

### Motivation
Every run's gates were computed by hand, in one-off scripts, after the fact.
That is error-prone — this log already records one such check (defect 12's
count) needing a second look — and it could not know which checks an older
file never recorded.

### Design
`check_gates(rows)` in `eval/summarise.py` returns each check with a status and
a verdict; `summarise.py` prints them for every file.

| Check | Fails when |
|---|---|
| page snapshots all served | any `snapshots_missed` > 0 |
| PoC GitHub snapshots all served | any `poc_snapshots_missed` > 0 (Change 17) |
| token data on every call | any call without token counts |
| no failed LLM calls | any telemetry error |
| no case-level errors | any `row["error"]` |
| no suspiciously fast cases (< 30 s) | the defect-12 signature |
| no duplicate cases | a `rule_id` appears twice (a resume mishap) |

Three outcomes: **CITABLE**; **CITABLE WITH CAVEATS (n not recorded)** when a
check could not be evaluated for that file; **NOT CITABLE** on any failure or an
empty file. A check is NOT RECORDED only when no row has its field. Case-level
errors are marked NOT RECORDED for files written before Change 14 (detected by
the absence of the `pipeline` field, added directly after it), because crashes
were invisible to the harness then (defect 17).

### Verification
Tests written first. **5 offline tests** (`tests/test_eval_summarise.py`): a clean
file is citable; each of the six failure types is detected and makes the file
not citable; duplicates fail; an older file reports the two checks it did not
record and gets the caveated verdict; an empty file is not citable. Full suite
**192 passed**.

Against the real files, matching every earlier hand check:
- `baseline60.jsonl` → **CITABLE WITH CAVEATS (2 not recorded)**: PoC fetches
  were live (before Change 17) and crashes were invisible (before Change 14).
- `baseline60.jsonl.corrupt.bak` → **NOT CITABLE**: failed LLM calls in 14 of 21
  rows (exactly defect 12's count), 13 of 21 under 30 s, 1 missed page.
- `baseline60.prefix-fix.bak` → **NOT CITABLE**: 4 missed pages (defect 14).

### A qualification of an earlier claim
The baseline-run entry (2026-09-19) says all five gates pass. Under the checks
as they stand now, baseline v1 is citable **with two caveats**, which should be
stated with its numbers: its PoC inputs were fetched live, and a pipeline crash
would not have been recorded as one.

---

## 2026-09-23 — Change 20 (plan 1.4b): a one-command pre-run checklist

### Motivation
Before every run the same checks were done by hand from memory: is the tunnel
really forwarding (a running `ssh` is not evidence — a dropped tunnel keeps its
listener), does the model return token counts, is the server context large
enough, do the tests pass, does a small run come out clean. Skipping one has cost
runs before (a stale tunnel on 2026-09-13/14). Since Change 12 there is a new
risk: prompts reach ~25k tokens and the code sets no context size, so a server
that loaded the model with a small context would truncate silently.

### Design
`eval/preflight.py` runs five steps in order and **stops at the first failure,
printing the fix**; exit status 0 only if all pass.

| Step | Passes when |
|---|---|
| tunnel | `GET /api/version` returns 200 (the fix printed is the tunnel command with keepalives) |
| model | a one-line chat completion returns positive prompt and completion token counts |
| context | `ollama ps` on the Spark shows the model with CONTEXT >= 32,768 (run after `model`, so it is loaded) |
| tests | the offline suite passes |
| smoke | a 2-case run (`--sample 2 --seed 7 --arm preflight`) exits 0 and `check_gates` (Change 19) says **CITABLE** |

The smoke run writes a fresh file under `eval/results/preflight/` (gitignored:
scratch, not evidence), so resume never skips it. `ollama ps` is parsed at the
header's fixed column positions, since the PROCESSOR column contains a space.

### Verification
Tests written first. **6 offline tests** (`tests/test_preflight.py`): context read
from the real `ollama ps` line captured on 2026-09-23 (262,144); a model not
loaded has no context; token counts must be present and positive; all steps
passing exits 0; the first failure stops the run (later steps never execute); a
step that raises is a failure, not a crash. Full suite **198 passed**.

Live, off the VPN: the real script failed at **tunnel**, printed the rebuild
command, ran nothing further, and exited **1**. The passing path (steps 2–5)
needs the VPN; its first real run is the start of plan task 1.5.

---

## 2026-09-23 — Change 21 (plan 1.4c): a relaunch wrapper replaces the external watchdog

### Motivation
The 2026-09-19 baseline ran under a watchdog script kept in `/tmp` — so it was
lost between sessions, and uncommitted. Its main job was to spot garbage rows
after the fact and purge them. Since Change 16 the harness refuses such rows
itself and exits with status 2, so the remaining job is small: bring the tunnel
back and continue.

### Design
`eval/run_resilient.py` runs `eval/run_eval.py` with the arguments given after
`--` and reacts to its exit status: **0** finished; **2** (stopped at a failed LLM
call, usually a VPN or tunnel drop) → rebuild the SSH tunnel with keepalives,
confirm it answers HTTP, rerun the same command — resume continues at the
unwritten case; **anything else** → stop, since a harness failure is a bug that
repeating will not fix. At most 5 relaunches. Before every run the tunnel must
answer; if it cannot be brought back within ~10 minutes (VPN down), the wrapper
gives up with status 3 rather than start a run that would stop immediately.

### Verification
Tests written first. **5 offline tests** (`tests/test_run_resilient.py`): a
finished run is not relaunched; status 2 is relaunched after a tunnel check
before every run; it gives up after the relaunch limit (first run + 3 relaunches
with a limit of 3); any other status is not retried; no run starts without a
working tunnel. Full suite **203 passed**.

Live, off the VPN, with one attempt: the real tunnel function tried to rebuild,
returned False after 13 s, and left no `ssh` process behind. The success path —
rebuilding after a real drop mid-run — needs the VPN; its first use is plan 1.5.

### Status
Plan task 1.4 complete (Changes 19–21). The run recipe is now two commands:
`eval/preflight.py`, then `eval/run_resilient.py -- <run_eval arguments>`.

---

## 2026-09-23 — Thesis notes brought up to date (documentation, no code change)

The user asked whether notes for writing the thesis were being kept. Checked: this log
was complete, but the chapter notes had fallen behind — `CH5_NOTES_EVALUATION.md` had not
changed since 2026-09-09 (before the first real run), there were no notes for Chapters 6
or 7, and the defence and literature notes existed only in the assistant's private notes.

Done:
- `thesis/CH5_NOTES_EVALUATION.md` updated in place: PoC snapshots and contamination in
  the dataset section; the Ollama token path now verified; runner changes (Changes 13–18);
  measured cost; the gates, verdicts and run recipe; status; open items; and a new §5.9,
  "Validity problems found by running the evaluation" (defects 12, 14, 16, 17 and the
  contamination finding), framed as a methodology finding.
- `thesis/CH6_NOTES_RESULTS.md` started, following the outline's §6: baseline v1 with its
  caveats and clean split; ablations and routing (unmeasured / blocked); the pipeline
  defects as findings (§6.4); the Foundation-Sec negative result (§6.5).
- `thesis/CH7_NOTES_LIMITATIONS.md` started: 31 limitations collected from this log's
  "Limitations to disclose" sections and the Chapter 5 notes, grouped by what they limit,
  each with its source; plus collected future work.
- `thesis/LITERATURE_NOTES.md` added (moved and updated; positioning marked as not current).
- The plan's definition of done now includes updating the chapter notes whenever a change
  or finding affects a thesis claim, so they cannot fall behind again.

Two things found while writing, recorded in the notes rather than hidden: the
Foundation-Sec probe ran from uncommitted scratch scripts (plan Inbox), and the
contamination definition was written during an exploratory measurement before being
formalised — unlike the defect-15 markers, it was not fixed in advance (CH7 item 31).

---

## 2026-09-24 — Baseline v2 (plan 1.5): the current pipeline, the first fully citable run

### What was run
- `eval/results/baseline60_v2.jsonl`, arm `baseline_v2`. The **same 60 cases** as baseline
  v1 (stratified sample, seed 0 — the set was checked to be identical before launch; rows
  are paired by `rule_id`). `qwen3-coder:30b` on every stage, all-local, web enrichment off,
  page and PoC GitHub inputs served from snapshots, contamination flags attached.
- Recipe as designed in Changes 19–21: `eval/preflight.py` passed all five checks (tunnel,
  model, context 262,144, 203 tests, 2-case smoke CITABLE; 4 min 37 s), then
  `eval/run_resilient.py -- --sample 60 --seed 0 --arm baseline_v2 --no-web-enrich`.
- **What differs from v1 (2026-09-19) — this is not a single-variable comparison:**
  pipeline Change 11 (`663f005`, validator guard) and Change 12 (`f9b64f1`, both stages read
  the whole source up to 100,000 characters); the PoC stage's GitHub inputs now come from
  the 2026-09-23 snapshots instead of live fetches; harness Changes 13–21 (recording, stop
  rule, gates — not meant to change pipeline behaviour); and run-to-run variation, since
  temperature 0 is not bit-for-bit repeatable on Ollama.

### Gates
**CITABLE** — all seven checks pass, 0 of 60 rows failing any of them. The first result
file with no caveat on its citability (v1: CITABLE WITH CAVEATS, 2).

### A network outage during the run, and what the guards did
- At case 52 of 60 (`a1507d71`, Securelist "Operation TunnelSnake") the connection to the
  Spark went silent while the analysis stage was waiting for an answer. The OpenAI client
  gave up (its defaults: 600 s per request, 2 retries); the pipeline carried on with an
  empty analysis ("0 indicators, 0 TTPs") and still generated 2 rules. **Change 16 refused
  that row** and stopped the run with status 2. Before Change 16 it would have been
  written and scored.
- Relaunch 1: the tunnel check passed, then the calls failed with connection errors →
  status 2 again. Relaunch 2: the tunnel did not answer for 5 rebuild attempts (~5 min).
  The VPN route to the Spark was unchanged throughout (GlobalProtect, `utun4`).
- Once the Spark answered again (~13:31 EDT), **the tunnel was rebuilt by hand**; the
  wrapper's next check found it and the run continued. Case 52 then passed in 166 s, so the
  failure was not specific to the case. The cause of the outage is unknown — reading the
  Spark's Ollama log needs admin rights.
- Checked afterwards: the wrapper's own rebuild call works when the network is up (the
  identical command on spare port 11435 returned in 0.7 s with a working tunnel). Its
  failures were the outage. Its success path is verified in isolation, not yet inside a run.
- Time: first row 14:25 UTC, last row 17:53 UTC; about 41 minutes of that was the outage
  and the two failed relaunches. Sum of per-case time: **169 min** (v1: 103 min).

### Results as the summariser prints them (unpaired means)

| Metric | v1 | v2 | Null baseline |
|---|---|---|---|
| S1 valid Sigma | 0.917 (n=60) | 0.950 (n=60) | — |
| S2 issues per rule | 1.00 (n=55) | 1.11 (n=57) | — |
| S3 logsource exact | 0.145 (n=55) | **0.123** (n=57) | 0.173 |
| S4 ATT&CK F1 | 0.123 (n=37) | 0.175 (n=40) | 0.092 |
| S5 detection-field F1 | 0.205 (n=53) | 0.239 (n=56) | 0.133 |
| Rules per case | 3.27 | 4.15 | — |
| Tokens per case | 37,126 | 53,803 | — |
| Seconds per case (mean / median) | 102.6 / 89 | 169.3 / 142 | — |

Clean cases only (55): S3 0.113, S4 0.189, S5 0.238. Flagged cases (5; 3–4 per metric):
too few for any conclusion.

### Paired comparison — the numbers to cite
Same cases; each metric only on cases scored in **both** runs. Exact McNemar for S1/S3;
paired bootstrap 95% CI of the mean difference (10,000 resamples, seed 0) for the rest.

| | n | v1 | v2 | Difference | Test |
|---|---|---|---|---|---|
| S1 valid | 60 | 55 | 57 | 3 only v1, 5 only v2 | p = 0.73 |
| S3 logsource exact | 52 | 8 | 5 | 5 only v1, 2 only v2 | p = 0.45 |
| S4 ATT&CK F1 | 35 | 0.119 | 0.133 | +0.014, CI [−0.048, +0.090] | 31 of 35 unchanged |
| S5 detection F1 | 51 | 0.200 | 0.203 | +0.003, CI [−0.074, +0.078] | 38 of 51 unchanged |
| Tokens per case | 60 | 37,126 | 53,803 | **+16,676 (+45%)**, CI [+11,705, +21,553] | higher in 50 of 60 |
| Seconds per case | 60 | 102.6 | 169.3 | **+66.7 (+65%)**, CI [+42.2, +99.0] | longer in 50 of 60 |
| Rules per case | 60 | 3.27 | 4.15 | +0.88, CI [+0.43, +1.38] | |

**The unpaired means mislead.** Unpaired, S4 rises 0.123 → 0.175; on the same cases it is
+0.014 with an interval that spans zero. The gap is composition: 5 cases are scored only in
v2 (their first rule parsed in v2, not in v1) and happen to score high (mean 0.467), 2 only
in v1 (mean 0.200). Same for S5 (+0.034 unpaired, +0.003 paired). Differences between runs
must be read paired; the summariser's own note says so.

### Reading
- **No change in rule quality is detectable at n = 60** from v1 to v2 on S1–S5. Change 12
  cut example copying into the attack vector (11 → 4, p = 0.039, measured on that stage
  alone), but that has not turned into measurably closer agreement with the human rules.
- **S3 is still at chance** (0.123, n = 57, against 0.173). Phase 2 is still needed, and v2
  is the reference it starts from.
- **The cost is measured and significant:** +45% tokens and +65% time per case.
- Not claimed: that the changes have *no* effect — 60 cases cannot detect small ones; the
  S4/S5 intervals still allow about ±0.08.

### Measured for the first time (earlier entries deferred these to baseline v2)
- **Defect 10 rate:** 186 of 417 generated rules (45%) had their `id` replaced by code
  (invalid or missing — the record does not separate the two), in 44 of 60 cases.
  Change 9 is doing a lot of work.
- **Regeneration:** 42 of 60 cases needed a second generation call (review errors or
  coverage gaps); 102 generation calls in total.
- **Example copying persists in the full run:** case 52 (a Windows kernel rootkit report)
  got the attack vector "memory_corruption via http, entry point /saml/login", which is the
  prompt's Example A. Not counted systematically here; the probe's markers can be run over
  v2's recorded attack vectors (plan 2.1).

### Limitations to disclose
- v1 → v2 bundles several changes (above); a difference could not be attributed to one of
  them, and none was found.
- The paired tests were computed with a scratch script using scipy/numpy, which are
  installed in the environment but not declared. Before any of these p-values is cited, a
  committed script must reproduce them (proposed next: `eval/compare_runs.py`, standard
  library only, tests first).
- One manual intervention during the run (the tunnel rebuild).

### Status
Plan 1.5 done; **Phase 1 complete**. `baseline60_v2.jsonl` replaces v1 as the reference.
Next in the plan: 2.1, the logsource diagnosis (offline, from v2's recorded suggestions).

---

## 2026-09-24 — Plan 2.1: where the log source goes wrong (diagnosis, offline)

### Question
S3 (logsource exact match) is at chance: 0.123 on baseline v2 against a null baseline
of 0.173. The plan asked where it goes wrong — the analysis stage's suggestion, the
attack-vector stage's telemetry, or the rule ignoring a correct suggestion (defect 11).

### Method
`eval/diagnose_logsource.py` (21 offline tests, `tests/test_diagnose_logsource.py`,
written first; full suite 224 passed), run on `eval/results/baseline60_v2.jsonl`. No
LLM, no network. Every number below is printed by that script.
- **First, which field fails.** S3 needs category, product and service to agree. In v2's
  57 scored cases the rule's category matches gold in 16, the product in 26, and a wrong
  `service` alone explains only 1 case (v1: 0). So the category is compared.
- **Definitions fixed before any bucket count was computed** (script docstring and
  tests): rule and gold category read from the row's S3 score, same normalisation as the
  scorer; top suggestion = first of the analysis stage's `logsource_suggestions`;
  offered = the first three (all the generation prompt shows). Each case falls in exactly
  one bucket.

### Result — pre-registered buckets (n = 57)

| Bucket | Cases | Meaning |
|---|---|---|
| right_suggested | 15 | analysis top suggestion right, rule right |
| right_rescued | 1 | suggestion wrong, rule right |
| **overridden** | **14** | **suggestion right, rule wrong — defect 11** |
| ranked_low | 7 | gold offered as suggestion 2 or 3, rule wrong |
| followed_wrong | 11 | gold not offered, rule = the wrong top suggestion (4 have no gold category) |
| wrong_elsewhere | 9 | gold not offered, rule differs from the suggestion |

- **The analysis stage's top suggestion has the right category in 29 of 57 cases**
  (51%); the gold category is among the three offered in 36.
- **The generation stage keeps a correct top suggestion in 15 of 29 and overrides it in
  14.** It rescues a wrong one once. Defect 11 is now measured: about half of the
  correct suggestions are lost at generation.
- The gold category appears in **some** rule of the response in 29 of 57 cases, in the
  first rule (what S3 scores) in 16.
- Web labels when the gold rule is not a web rule (46 cases): attack-vector telemetry web
  in 16, analysis top suggestion web in 4. The pre-registered rule-side measure (category
  `webserver` or `proxy`) gives 3 — **an undercount**: it does not recognise
  `webserver_access_log`, which is not a Sigma category (see below). Counting it from the
  script's confusion list, the rule names web telemetry in 16 of the 46, the same as the
  attack-vector stage.

### Result — post-hoc measures (added after the first run; not pre-registered)
Found by reading the confusion list, then added to the same committed script with their
own tests, labelled post-hoc in its output.
- **The rule's category is the attack-vector stage's telemetry label, verbatim, in 24 of
  the 41 wrong rules** — and in 10 of the 14 overridden cases.
- **17 of the 41 wrong rules use a category that no rule in the local SigmaHQ corpus
  uses** (37 categories there): `webserver_access_log` 15, `web_proxy` 1,
  `email_gateway` 1. These are labels from the attack-vector stage's own 13-value
  vocabulary, which is not Sigma's. Such a rule can never match.
- **Had the rule used the analysis stage's top suggestion verbatim, S3 would be 0 of
  57.** The suggestion's `service` is `sysmon` in 44 cases (and `webserver_access_log` in
  8), while SigmaHQ's Sysmon-based rules carry only category and product. So "make the
  rule follow the suggestion" (plan 2.2 as worded) would fail as it stands.

### Mechanism (inspected in the prompts, not measured)
- **The generation prompt ranks the attack vector above the analysis stage.** Its rule 2:
  "At least one rule MUST target the PRIMARY ATTACK VECTOR … the logsource of that rule
  must match the telemetry where that traffic is observed. Initial-access detection is
  MANDATORY when an exploit is described." The attack-vector summary near the top of the
  prompt includes "Primary telemetry: <label>"; the analysis suggestions are appended to
  the Sysmon reference block (`stage_generate.py:273`).
- **Two vocabularies.** The attack-vector stage chooses from 13 labels of its own
  (`webserver_access_log`, `web_proxy`, `network_ids`, `email_gateway`, …), not Sigma
  categories; the generation stage copies them into `logsource.category`.
- **The analysis prompt's only example** suggests `category: process_access`,
  `product: windows`, `service: sysmon` — the likely source of the 44 `sysmon` services
  (the same pattern as defect 15: a worked example copied).
- Plausible, not shown: "initial access is mandatory" also pushes the initial-access rule
  first, while many gold rules detect post-exploitation on the host — consistent with the
  gold category appearing in a later rule more often than in the first.

### What this means for the order of 2.2–2.4 (a proposal; the user decides)
1. **One vocabulary** — the attack-vector stage's telemetry must be expressed in Sigma
   categories before it reaches generation (17 unmatchable categories). New task.
2. **The suggestion's service** — the analysis example teaches `service: sysmon`; fix it
   before the suggestion can be used as a constraint (0 of 57 otherwise).
3. **2.2, precedence** — make the (corrected) suggestion the instruction for the rule's
   logsource, and resolve the conflict with generation rule 2 (14 overridden, 10 of them
   by the attack-vector label).
4. **2.3, web bias** — still 16 of 46 non-web cases labelled web by the attack-vector stage.
5. **2.4, boilerplate** — not indicated: the analysis stage gets the category right in
   about half the cases with the whole page; nothing here points to boilerplate.
Ceiling to keep in mind: had the rule always taken the top suggestion's *category*, the
category would be right in 29 of 57, not 16 — a bound on what the generation-side fixes
(1–3) can reach on category alone; exact match also needs product and service.

### Limitations to disclose
- Category only; product is a second failure (the top suggestion's category and product
  both agree with gold in only 18 of 57) and is not diagnosed here.
- The post-hoc measures were chosen after seeing the data; they describe this run and
  motivate changes, they are not a test of a hypothesis.
- One run, n = 57; the buckets are counts, with no inference attached.
- "Used by no SigmaHQ rule" is judged against the local corpus copy (`data/sigma`), not
  the full Sigma taxonomy specification.

### Status
Plan 2.1 done. The next change waits for the user's choice of order.

---

## 2026-09-24 — Change 22 (plan 2.2a): the attack-vector telemetry reaches later stages in Sigma's vocabulary

### Motivation (plan 2.1)
The attack-vector stage chooses `primary_telemetry` from 13 labels of its own. The
analysis and generation stages read it through `format_vector_summary` and copied it:
in baseline v2 the rule's category was the label verbatim in 24 of 41 wrong rules, and
17 of 41 used a category no SigmaHQ rule uses (`webserver_access_log` 15). The analysis
stage also put the label in its suggestion's `service` (8 cases).

### Design decisions
| Decision | Why |
|---|---|
| Translate in the summary the later stages read, not in the attack-vector prompt | The stage's *choices* stay the same (the web bias is step d, measured separately); only the words change. One variable. |
| 7 labels map to a Sigma category: `webserver_access_log`→`webserver`, `web_proxy`→`proxy`, `firewall`, `dns`, `process_creation`, `file_event`, `registry_event` | Each target is used by SigmaHQ rules (checked against the local corpus, pinned by a test). `dns` → `dns` (network DNS logs), not `dns_query` (Windows Sysmon): the stage's list is network-oriented. |
| 6 labels have no single Sigma category (`waf`, `network_ids`, `cloud_audit`, `email_gateway`, `auth_log`, `other`) → described in plain words, "(no single Sigma logsource category)" | Such logsources are defined by product/service or do not exist; no snake_case text is left to copy. Sigma's `authentication` category appears only in one deprecated rule, so `auth_log` is not mapped to it. |
| The raw label is kept in `context["attack_vector"]` and in evaluation rows | Plan 2.1's diagnosis reads it; the record should say what the stage chose. |
| The taxonomy retrieval query still uses the raw label | Keeps retrieval unchanged, so the measurement isolates what the model reads. |

### Verification (offline)
Tests written first, seen failing: **18 tests** (`tests/test_telemetry_vocabulary.py`)
— the table covers exactly the 13 labels the prompt offers (parsed from the prompt); each
mapped label is shown as its Sigma category and its own text disappears; unmapped labels
are described in words with no backtick or underscore; an unknown label is shown in
words; a missing one as "unknown"; the stored attack vector is unchanged; mapped
categories are used by SigmaHQ rules (skipped without `data/sigma`). Full suite **242
passed**.

### Measurement plan (fixed before the run)
Same 60 cases, recipe as baseline v2, arm `p2a_vocabulary`, file
`eval/results/p2a_vocabulary60.jsonl`; compared paired with baseline v2.
- Primary: first rules whose category no SigmaHQ rule uses (v2: 17 of 57 scored).
- Secondary: S3 (and S1, S4, S5) paired; the 2.1 buckets rerun with
  `eval/diagnose_logsource.py`.
- Not predicted: the effect on S3. Most of the 17 had a non-web gold rule, so a real
  category name can still be the wrong one; this change removes an impossibility, it
  does not choose better.

### Status
Code and tests done; the measurement run follows.

---

## 2026-09-24 — Change 23: a committed paired-comparison script (`eval/compare_runs.py`)

### Motivation
The baseline v1 → v2 paired tests came from a scratch script using scipy/numpy, which
the project does not declare; the log said they were not citable until a committed
script reproduced them. With one run per Phase 2 change (user decision), every change
needs this comparison.

### Design
Standard library only (`math.comb`, `random`). Cases matched by `rule_id`; each metric
on the cases scored in both runs. S1/S3: exact McNemar (two-sided binomial on the
discordant cases, capped at 1). S4, S5, tokens, seconds, rules: mean difference with a
paired bootstrap 95% interval (10,000 resamples, seed 0, percentile with linear
interpolation as numpy's default). Reports cases present in only one file.

### Verification
Tests first, seen failing: **11 tests** (`tests/test_compare_runs.py`) — McNemar against
hand-computed values, including 8 vs 1 → p = 0.0390625, the logged Change 12 result;
linear-interpolation percentiles; a reproducible bootstrap; only cases scored in both
runs are paired; and a regression test that reproduces the baseline v1 → v2 comparison
from the committed result files. Full suite **253 passed**.

Reproduction: every count, mean, difference and p-value logged for v1 → v2 is
reproduced exactly. The intervals differ in the last digits (another random generator);
**cite these, from the committed script**:

| | Scratch (logged) | Committed |
|---|---|---|
| S4 difference, 95% CI | [−0.048, +0.090] | **[−0.048, +0.086]** |
| S5 difference, 95% CI | [−0.074, +0.078] | **[−0.072, +0.075]** |
| Tokens per case | [+11,705, +21,553] | **[+11,752, +21,451]** |
| Seconds per case | [+42.2, +99.0] | **[+42.0, +98.9]** |
| Rules per case | [+0.43, +1.38] | **[+0.42, +1.38]** |

No conclusion changes. The limitation logged with baseline v2 (paired tests from a
scratch script) is resolved.

---

## 2026-09-24 — Correction: the baseline v2 interruption was two separate events

The baseline v2 entry (above) described one network outage and said the VPN route "was
unchanged throughout". Both are wrong. The user reported reconnecting the VPN, and the
GlobalProtect client logs (read-only, on this laptop) show what happened:

```
10:11:55  IPSec tunnel creation finished with Gateway vpn.usf.edu.
13:24:48  (no answer from the gateway from here on — "tunnel downtime 54117 ms")
13:25:42  Tunnel is down due to keep-alive timeout.
          ("Too many outstanding keepalive and no response from GP gateway")
13:26:10  Select a gateway that you want to manually connect.   (auto-restore stops here)
13:31:10  IPSec tunnel creation finished with Gateway vpn.usf.edu.   (the user reconnected)
```

The reconnect gave back the same interface (`utun4`) and address, which is why the
route check during the run did not show it.

**Event 1 — one LLM call hung (cause unknown).** Case 52's first analysis call never
answered and ended in a client timeout (600 s per attempt, 2 retries). The network was
up: the case's other calls, made *after* that timeout, succeeded (the stop message counts
1 failed call of 4), and the VPN did not fail until 13:24:48. On the rerun the case passed
in 166 s. Hypothesis, not shown: a generation that did not stop — the Ollama client sets no
output limit (`max_tokens`), so a repetition loop runs until the timeout. The Spark's
Ollama log needs admin rights to check.

**Event 2 — the VPN dropped** (13:24:48–13:31:10): the USF gateway stopped answering the
tunnel's keep-alives. Not a session time limit — no logout or lifetime message, and 3 h 13
min after connecting is not a round number — but this is one event. The client's automatic
restore ends at "select a gateway … manually", so **a drop needs the user to reconnect**;
the relaunch wrapper gives up after ~12 minutes.

Unchanged: the stop rule refused the affected rows both times, and the file is CITABLE.
Corrected in CH5 §5.6 and CH7 item 33. Two findings go to the plan's Inbox (an output cap
for LLM calls; how long the wrapper should wait for a manual VPN reconnect).

---

## 2026-09-24 — The Change 22 run paused at 33 of 60: the Spark's Ollama is shared

At case 34 (`research.checkpoint.com` "Stealth Falcon", CVE-2025-33053) the analysis call
waited more than 40 minutes with the VPN and tunnel working. Read-only checks on the
Spark at 17:23 showed:
- another account (`kbanstola`, 2 sessions) running a project (`SOC_Companion`) whose
  processes use the GPU;
- **four clients connected to the same Ollama server** (`127.0.0.1:11434`), one of them
  our SSH tunnel;
- Ollama showing our model as "Stopping…" (unloading, as when another request needs a
  different model or setting), GPU at 92–94%.

So requests from another user's application compete with ours for one model server.
This is the likeliest explanation of the hung call here and of the one in baseline v2
(case 52) — **not shown**: Ollama's own log needs admin rights.

Checked, read-only, whether contention could have silently cut prompts (a model reloaded
with a smaller context would truncate without an error): in every recorded call of
baseline v2 (323) and of this run (177), characters per prompt token stay between 3.8 and
4.9, no prompt stops at a round limit, and the largest is ~22k tokens of a 262,144 window.
**No sign of truncation.**

Decision (user): stop the run and resume when the Spark is quieter. Stopped at 17:26; the
file holds 33 complete rows (the refused case 34 was never written). The resume will
continue at case 34 **on the same code (`48f022e`)** — no pipeline change lands until this
run is complete.

### Limitations to disclose
- The Spark is shared: time per case (C2) partly measures other users' load, and runs
  can stall while others use the server. Token counts are unaffected.
- A run interrupted and resumed spans two periods; the per-case results do not depend on
  it (each case runs whole on one code version), the timing might.

---

## 2026-09-24 — Defect 19: an unbounded generation loops and never finishes (correcting the "shared Spark" explanation)

### What happened
The Change 22 run was resumed at 18:12 with the Spark idle (GPU 0%, no model loaded, the
other user's clients idle). Case 34 (`9a2d8b3e`, Check Point "Stealth Falcon") stalled
again in the same analysis call: 3 attempts × 600 s, then the stop rule; the wrapper
relaunched and it stalled a third time. The run was stopped at 18:48 (33 rows, intact).

### Diagnosis (a scratch probe — a diagnostic, not a measurement)
The case was run through the real pipeline (same code, same snapshots), and the analysis
stage's LLM request was sent **streamed, with an output cap of 30,000 tokens**, to see
whether tokens flow or never arrive:
- first token after **5.3 s** — the request was not queued behind anyone;
- tokens flowed at ~40/s and never stopped: **116,776 characters in 722 s**, ended by the
  cap (`finish_reason = length`), JSON never closed;
- the output lists 13 real ATT&CK techniques, then **336 invented sub-techniques in
  sequence: `T1562.001`, `.004`, `.006` … `T1562.339`** (the real T1562 has about a dozen).
  88% of the output is the loop.

In baseline v2 the same call ended normally (4,637 tokens, 92 s). Under Change 22's
slightly different prompt the model falls into the loop on every attempt (at least five,
across two runs, and the probe) — at temperature 0 a retry repeats it.

### Mechanism
No LLM call sets an output limit (`OllamaLLMClient.generate` passes no `max_tokens`), and
the analysis prompt asks for a list of technique mappings with no maximum length. A loop
therefore runs until the client timeout (600 s) on each of its 3 attempts. The stop rule
(Change 16) treats the timeout as an infrastructure failure, so the run halts at the same
case every time — the risk recorded as CH7 item 28, now observed.

### Corrections to earlier entries
- "The Change 22 run paused at 33 of 60: the Spark's Ollama is shared" named contention as
  the likeliest cause of the case-34 stall. **Wrong for case 34**: it is this loop. The
  shared server remains a fact and a timing limitation (CH7 item 37).
- Likely, not shown: the hung analysis call of baseline v2's case 52, and the two analysis
  calls that took ~690 s but produced only ~4,200 tokens (`b7155193` in v2, `ad7085ac` in
  this run — a first attempt timing out, then a normal retry) were the same kind of loop.

### What the product does today
In the web app a user would wait ~30 minutes, and the pipeline would then continue on an
empty analysis and still show rules — the defect-12 pattern, in production.

### Status
Open. A fix is a pipeline change (it breaks the Change 22 code freeze), so it waits for the
user's decision. The probe is a scratch script; if its numbers are cited, a committed
version must reproduce them.

---

## 2026-09-24 — Change 22's stopped run: what the 33 finished cases show (interim, descriptive)

`eval/results/p2a_vocabulary60.jsonl` (33 rows, stopped by defect 19; committed as
evidence). All seven gates pass on its rows. Compared with baseline v2's rows for the
same 33 cases, using only committed scripts (`compare_runs.py`, `diagnose_logsource.py`
on the v2 subset). **Interim and descriptive:** 33 of 60 cases, no test is claimed; the
pre-registered measurement is the full rerun (with Change 24), which supersedes these rows.

| | v2, same cases | Change 22 |
|---|---|---|
| Wrong rules whose category no SigmaHQ rule uses (pre-registered primary) | 12 | **1** (`security`) |
| Rule category right | 4 / 32 | 7 / 31 |
| Correct top suggestion overridden | 10 | 4 |
| Rule category = the attack-vector label verbatim | 16 | 5 |
| Rule on web telemetry (`webserver`/`proxy`) when gold is not web | 2 | 9 |
| S3 exact, paired | 2 / 30 | 4 / 30 (2 gained, 0 lost; p = 0.50) |
| S4, S5, tokens, seconds (paired) | — | differences within noise |

Reading:
- The change does what it was built for: impossible categories nearly vanish (12 → 1).
- Part of them become right; part become a real but wrong category — `webserver_access_log`
  is now `webserver` on host rules. The attack-vector stage's web bias is unchanged (web
  telemetry on 9 non-web cases in both runs); it now reaches the rule under a valid name.
  That is step (d).
- The analysis stage copies the new wording too: its top suggestion's `service` is
  `webserver` in 4 cases (was `webserver_access_log`). Step (b).
- S3 barely moves: product and service are still wrong in most cases.
- The partial file's unpaired means (S4 0.068, S5 0.156) are far below v2's full-run means
  only because these 33 cases are harder — v2 scores 0.127 and 0.136 on the same cases.
  Another instance of why runs are compared paired.

---

## 2026-09-24 — Change 24 (defect 19): every LLM answer has a bounded length; a cut answer is the model's failure

### Motivation
Defect 19: an answer that loops never finishes. With no output limit, each attempt ran to
the 600 s client timeout; the stop rule (Change 16) read the timeout as an infrastructure
failure and halted the run at the same case every time. In the web app the user would wait
~30 minutes and then get rules built on an empty analysis.

### Design decisions
| Decision | Why |
|---|---|
| Every Ollama call asks for at most **16,384** output tokens (`OUTPUT_TOKEN_LIMIT`) | Above every answer that finished in baseline v2 (longest 12,374 tokens, pinned by a test), so it binds only on answers that would not have finished. At ~40 tokens/s a looping attempt now ends in ~7 min instead of 10. |
| A cut answer (`finish_reason = "length"`) is retried up to **2** times | The same number of attempts the OpenAI client gives a timeout today; two of the ~690 s analysis calls in the logs show a retry can escape a loop. |
| If every attempt is cut → `OutputLimitReached`, an ordinary exception | The stage handles it as it handles any error today: it uses its empty default. No new behaviour in the stages. |
| A cut attempt is recorded with `output_limited = True` and `ok = True` | The call worked; the model did not finish. **The stop rule stays for infrastructure failures** (connection, timeout, server errors). A model failure is a result of the pipeline and is measured with the case — the case is written and scored as what the pipeline produced. |
| The summariser prints "answers cut at limit: N calls in K cases" | Visible in every report; not a citability gate, because it is a finding, not a measurement fault. |
| Not changed: the analysis prompt's unbounded technique list; invented technique IDs | Both change finished answers too, so each gets its own measured step (plan, below). |

### Verification
Tests first, seen failing: **10 tests** (`tests/test_output_limit.py`) — every call asks for
the limit; a finished answer returns after one call; a response without `finish_reason`
counts as finished; a cut answer is retried and a finished retry is used; cut on every
attempt → `OutputLimitReached` after 3 attempts, each recorded `output_limited`, none as
failed; the error is an ordinary `Exception`; telemetry counts cut calls; a cut answer does
not trigger the stop rule; the summariser reports it and the verdict stays CITABLE; the
limit exceeds the longest finished answer in the committed baseline v2 rows. Full suite
**263 passed**.

Live, on the Spark: a non-streamed call with `max_tokens = 5` returned `finish_reason =
"length"`, 5 completion tokens — Ollama's OpenAI endpoint honours the limit and reports it.

### Limitations to disclose
- The limit's value rests on one reference run's longest answer (12,374 tokens).
- At temperature 0 a retry may repeat a loop (case `9a2d8b3e` did, every time): the limit
  bounds the time, it does not prevent the loop.
- Under heavy load on the shared Spark, 16,384 tokens could take longer than the 600 s
  timeout; that attempt would then count as a timeout (infrastructure) again.

### Next
The Change 22 measurement restarts from scratch on Changes 22 + 24:
`eval/results/p2a_vocabulary60_r2.jsonl`, arm `p2a_vocabulary_r2`. Measurement plan as fixed
for Change 22 (primary: first rules whose category no SigmaHQ rule uses, v2 17/57;
secondary: S3 paired, the 2.1 buckets), plus the count of answers cut at the limit.

---

## 2026-09-24 — Change 22 measured (plan 2.2a, run on Changes 22 + 24)

`eval/results/p2a_vocabulary60_r2.jsonl`, arm `p2a_vocabulary_r2`, code `07cb664`, the same
60 cases, started 19:51, 166.8 min, no relaunch, no manual step. **CITABLE** (all seven
gates). Answers cut at the output limit: **2 calls in 2 cases**, both rescued by the retry —
`9a2d8b3e` (the case that stopped the first run: first attempt cut at 16,384 tokens after
349 s, retry finished at 5,188 tokens) and `a1507d71` (**baseline v2's case 52**, whose hang
was unexplained — the same kind of loop). The loop is not deterministic after all: it hit
case `9a2d8b3e` on five attempts earlier in the day, once here.

### Pre-registered measures (plan fixed in the Change 22 entry), against baseline v2
Committed scripts: `compare_runs.py baseline60_v2.jsonl p2a_vocabulary60_r2.jsonl` and
`diagnose_logsource.py` on each file.

| Measure | v2 | Change 22 | Note |
|---|---|---|---|
| **Primary: wrong rules whose category no SigmaHQ rule uses** | **17** of 57 scored | **1** of 53 (`security`) | the change's purpose |
| S3 logsource exact, paired (n = 52) | 6 | **11** | 5 gained, 0 lost; exact McNemar **p = 0.062** |
| S1 valid first rule, paired (n = 60) | 57 | 53 | 5 lost, 1 gained; p = 0.22 (below) |
| S4 ATT&CK F1, paired (n = 35) | 0.171 | 0.190 | +0.019, 95% CI [−0.019, +0.067] |
| S5 detection F1, paired (n = 51) | 0.213 | 0.243 | +0.030, 95% CI [−0.023, +0.090] |
| Rules per case | 4.15 | 3.67 | −0.48, CI [−0.98, −0.05] |
| Tokens / seconds per case | — | — | no difference (CIs span zero) |

2.1 buckets (category level): **overridden 14 → 3** (defect 11: generation now keeps the
analysis stage's category far more often); right_suggested 15 → 18; ranked_low 7 → 12;
followed_wrong 11 → 14; wrong_elsewhere 9 → 6. Rule category right 16/57 → 18/53.

### Where the web bias went (non-web gold cases: v2 46, now 46)
Attack-vector telemetry web 16 → 18 (the stage was not changed); **analysis top suggestion
web 4 → 11**; generated rule web (`webserver`/`proxy`) 3 → 18. In v2 most web-biased rules
carried the non-Sigma label, so they did not count as web; now the label reads "Sigma
logsource category `webserver`", and the analysis stage follows it. **The web bias now
flows through legitimately named categories** — step (d) is where it has to be fixed.
The analysis suggestion copies the new wording as its `service` (`webserver` 10 times;
was `webserver_access_log` 8) — step (b).

### The S1 drop (5 lost first rules), inspected
None involves a cut answer. 3 are malformed YAML in the first rule (e.g. an unquoted value
containing `Content-Disposition: form-data; …`); 2 are the generation stage's JSON failing
to parse ("Invalid control character", "Invalid \escape") → no rules at all — the known
risk of `json_mode` on generation (defect 5). Consistent with run-to-run variation at
p = 0.22; recorded because S2–S5 are computed only on rules that parse.

### Reading
- Change 22 did what it was designed for: impossible categories 17 → 1, and generation
  overrides a correct suggestion far less (14 → 3).
- S3 moved in one direction only (6 → 11 on the same cases, no case lost), p = 0.062 — not
  significant at 0.05 with n = 52. Unpaired, S3 is 0.208 (11/53) against a chance level of
  0.173 (≈ 9 of 53 expected): above chance for the first time, not distinguishably so.
- What still limits S3: the web bias (now visible), the suggestion's service, and product.
  Steps (b) and (d) target exactly these.

### Limitations to disclose
- The run is on Changes 22 + 24. Change 24 changed nothing in 58 cases (no cut answer) and
  rescued 2; it is not a confound for the categories.
- The primary measure's counts are not tested paired here (`compare_runs.py` does not
  compute it); 17 → 1 is reported as counts.
- p = 0.062 must not be written as a significant improvement.

### Status
Plan 2.2a done. Reference for the next step: this file. Next: 2.2b, the analysis
suggestion's `service`.

---

## 2026-09-25 — Change 25 (plan 2.2b): a suggested log source with a category carries no service

### Motivation
The analysis stage's top suggestion carried a service in every case — `sysmon` 35 of 53 and
`webserver` 10 after Change 22 — and it matched the human rule's service in **0 of 53**
(`diagnose_logsource.py`, the measure added below). Source: the COMBINED_ANALYSIS prompt's
reference table ("windows/sysmon", "linux-windows/apache-iis") and its only example
(`"service": "sysmon"`). Consequence for plan step (c): a rule that followed the suggestion
verbatim would score 0 of 53 on S3.

### What SigmaHQ does (measured on the local corpus, 3,691 rules)
| Rules | Count | Carry a service |
|---|---|---|
| with a category | 2,880 | **12** |
| without a category | 811 | **792** (`windows`/`security` 168, `windows`/`system` 74, `aws`/`cloudtrail` 56, `linux`/`auditd` 53, …) |
1,593 `process_creation` rules, none with a service; 82 `webserver` and 55 `proxy` rules,
none with a product or service. `service: sysmon` appears in 4 rules, all without a
category. In the 60-case sample, 52 gold rules have a category and no service; 5 have no
category and a service (`security` 3, `http` 1, `sslvpnd` 1).

### Design (the user's decision: "use service only when it doesn't have a category")
| Decision | Why |
|---|---|
| A suggestion with a category → service removed, old value kept in `service_dropped` | Sigma's convention (12 exceptions in 2,880); the record lets the future assistant explain what it removed |
| No category → the service stays | There it *is* the log source (792 of 811) |
| No category and a (product, service) pair no SigmaHQ rule uses → `service_to_confirm` | User: when unsure, ask the analyst. Recorded only; shown to the analyst in Phase 3, **not** to the rule writer, so it cannot change the rules |
| Known pairs from `data/sigma/rules` (73 pairs, committed as `backend/pipeline/sigma_known_services.json`, rebuilt by `scripts/build_sigma_known_services.py`) | The directory the retrieval index uses; `rules-emerging-threats` (the scored answers) is excluded — 8 pairs appear only there, e.g. `fortios`/`sslvpnd` |
| In code, after the model answers — not a prompt edit | Changes exactly this field; a prompt edit could shift other answers (as Changes 9 and 22) |
| The generation prompt shows each suggestion with only the fields present (`process_creation/windows`, not `…/None`) | Nothing to copy |
Not changed: the prompt's table and example still say `sysmon` (the model may keep writing
it; code removes it). Indirect effect, disclosed: the taxonomy retrieval query is built
from the suggestion's fields, so it no longer contains "sysmon".

### Verification
Tests first, seen failing: **24 tests** (`tests/test_logsource_service.py`) — the rule
itself, placeholders (`-`, `none`, `n/a`…) not counted as a category, case-insensitive
matching, the input not modified, the analysis stage applying it, the generation prompt
showing only present fields and no flags, the committed list holding 73 pairs and being
reproducible from `data/sigma/rules` without the emerging-threats-only pairs. Plus 1 test
for the new diagnosis measure. Full suite **288 passed**.

### Measurement plan (fixed before the run)
Same 60 cases; arm `p2b_service`, `eval/results/p2b_service60.jsonl`; compared paired with
**`p2a_vocabulary60_r2.jsonl`** (the Phase 2 reference; runs are cumulative).
- Primary: the top suggestion's service equals the gold rule's (`diagnose_logsource.py`,
  "Change 25 measure") — **0 of 53** in the reference.
- Secondary: S3 had the rule copied the top suggestion verbatim (0 of 53); S3 paired; the
  2.1 buckets; how many suggestions are marked `service_to_confirm`.
- Expected, stated before the run: little or no change in S3 — in the reference run every
  rule with the right category and product already had the right service (11 of 11); the
  rule writer mostly ignores the suggestion's service. The change matters for step (c) and
  for what the analyst will see.

---

## 2026-09-25 — Change 25 measured (plan 2.2b)

`eval/results/p2b_service60.jsonl`, arm `p2b_service`, code `3be14d0` (Changes 22 + 24 + 25),
same 60 cases, 198.0 min, no relaunch, no manual step. **CITABLE**. Answers cut at the output
limit: **6 calls in 4 cases, all in the analysis stage** (`9a2d8b3e` cut on all 3 attempts →
the stage fell back to an empty analysis, the case was written and scored with 4 valid rules,
as Change 24 designed; `ad7085ac`, `32b5db62`, `7b544661` rescued by the retry).

### Pre-registered measures, against `p2a_vocabulary60_r2.jsonl` (paired)
| Measure | Before | After | Note |
|---|---|---|---|
| **Primary: top suggestion's service = gold's** | **0 / 53** | **51 / 58** | the change's purpose |
| S3 had the rule copied the top suggestion verbatim | 0 / 53 | **15 / 58** | the ceiling step (c) can aim at |
| S3 exact, paired (n = 53) | 11 | 8 | 3 lost, 0 gained; p = 0.25 |
| S1 valid first rule, paired (n = 60) | 53 | 58 | 5 gained, 0 lost; p = 0.062 |
| S4 / S5, paired | 0.190 / 0.239 | 0.151 / 0.212 | −0.039 / −0.026, CIs span zero |
| Seconds per case | 166.8 | 198.0 | +31, CI [−3, +69]; the loops (~350 s per cut attempt) |
| Rules per case | 3.67 | 4.20 | +0.53, CI [+0.12, +1.03] |
Buckets: overridden 3 → 6; right_suggested 18 → 18; followed_wrong 14 → 16. S3 per field:
category 18/53 → 18/58, product 22/53 → 30/58, service 33/53 → 36/58.

### The three S3 losses, inspected
- `f8e9aa1c`, `7b544661`: the top suggestion was right both days (`process_creation/windows`);
  today the rule writer wrote **`category: email`** — the attack-vector stage's telemetry was
  "email gateway logs" — a category no SigmaHQ rule uses (non-Sigma categories 1 → 3:
  `email` 2, `security` 1). The override pattern step (c) targets.
- `9aa27839` (gold `process_creation/linux`): the suggestion said `windows` both days; yesterday
  the rule writer corrected it to `linux`, today it followed `windows` and added `service: sshd`.
- Nothing shows the service change caused these; with one run and p = 0.25 they are not
  distinguishable from run-to-run variation. The expectation stated before the run ("little
  or no change in S3") held within noise, in the unfavourable direction.

### Finding: the analysis stage never proposes a log source without a category
0 suggestions were marked `service_to_confirm`: the analysis stage suggested a category-based
source every time. The 6 gold rules that are defined by a service (`windows`/`security` 3,
`http`, `globalprotect`, `sslvpnd`) all got category suggestions (e.g. `process_creation/windows`
for a Windows Security rule), so their service was removed — the 7 remaining service misses.
Likely cause, not shown: the analysis prompt's reference table lists only category-based
sources. Recorded in the plan's Inbox; not in the agreed order.

### Status
Plan 2.2b done. `p2b_service60.jsonl` is the reference for step (c).

---

## 2026-09-25 — Change 26 (plan 2.2, step c): the generation prompt recommends the analysis stage's log source for the first rule

### Motivation
Defect 11. After Change 25 the rule writer still overrode a correct top suggestion in 6 of 58
cases (2 of them by inventing `category: email` from the attack vector's "email gateway logs"),
and the first rule used the top suggestion's log source in only **24 of 58**. Mechanism
(2.1): the prompt's attack-vector section says "anchor at least ONE rule on this"; rule 2 made
an initial-access rule MANDATORY with "the telemetry where that traffic is observed"; the
analysis suggestion sat inside the Sysmon reference block.

### Principle (user, 2026-09-25)
"I don't want things hardcoded … I want them to think." Code does **not** set, rewrite or
reorder a rule's log source — a rule's detection fields belong to its log source, so forcing
the field would raise S3 without a better rule. The model decides; code only records.

### Design
| Decision | Why |
|---|---|
| New prompt section right after the attack vector: "Log Source for the First Rule (recommended by the analysis stage)" — the top suggestion as YAML, with its confidence and reasoning | Precedence by position and form; the reasoning lets the model weigh it |
| Instruction 1: the first rule *should* use it, **unless the evidence shows that log source cannot observe the behaviour** — then choose the one that can and **say why in the rule's `description`** | The model thinks; a departure is explained (also what the analyst will read) |
| Rule 2 keeps the attack-vector rule, adds "This rule does not have to be the first rule" | The initial-access rule and the coverage check stay; the conflict with instruction 1 goes |
| The analyst's confirmation (`user_confirmed`) replaces the suggestion in that section | The assistant flow |
| Unchanged: the suggestion list in the reference block; the coverage check; no enforcement | One change |

### Verification
Tests first, seen failing: **10 tests** (`tests/test_first_rule_logsource.py`) — the block's
YAML, confidence and reasoning; a category-less source keeps its service; internal flags not
shown; the analyst's confirmation wins; no suggestion said plainly; the section sits between
the attack vector and the payload signatures; instruction 1's escape clause and explanation;
rule 2 not necessarily first; the generation stage's real prompt carries it. Plus 1 test for
the new diagnosis measure. Full suite **298 passed**.

### Measurement plan (fixed before the run)
Same 60 cases; arm `p2c_first_rule`, `eval/results/p2c_first_rule60.jsonl`; paired against
**`p2b_service60.jsonl`**.
- Primary: the first rule's log source equals the top suggestion (`diagnose_logsource.py`,
  "Change 26 measure") — **24 of 58** in the reference.
- Secondary: S3 paired (reference 8 of 58; the ceiling if the first rule always followed the
  suggestion is 15 of 58); the overridden bucket (6); S1, S4, S5; rules per case; how many
  rules state a reason for departing (read by hand, not scored).
- Expectation, stated before the run: compliance up; S3 up at most to ~15; the web bias
  remains (the analysis suggests web in 10 cases) — step (d).

---

## 2026-09-25 — Change 26 measured (plan 2.2, step c)

`eval/results/p2c_first_rule60.jsonl`, arm `p2c_first_rule`, code `469f8a0` (Changes 22 + 24 +
25 + 26), same 60 cases, 202.6 min, no relaunch, no manual step. **CITABLE**. Answers cut at
the output limit: 7 calls in 5 cases, **all in the analysis stage** (13 of 13 over two runs).

### Pre-registered measures, against `p2b_service60.jsonl` (paired)
| Measure | Before | After | Note |
|---|---|---|---|
| **Primary: first rule's log source = top suggestion** | **24 / 58** | **44 / 57** | the change's purpose |
| S3 exact, paired (n = 56) | 9 | **14** | 5 gained, 0 lost; exact McNemar p = 0.062 |
| S5 detection F1, paired (n = 54) | 0.210 | **0.285** | **+0.075, 95% CI [+0.008, +0.146]** — the first quality interval to exclude zero |
| S4 ATT&CK F1, paired (n = 37) | 0.111 | 0.105 | −0.006, CI [−0.018, 0.000]; 36 of 37 unchanged |
| S1 valid first rule | 58 | 57 | p = 1.0 |
| Tokens / seconds per case | — | — | no difference |
Buckets: overridden 6 → 2; wrong_elsewhere 7 → 1; followed_wrong 16 → 21; right_suggested
18 → 22. Categories no SigmaHQ rule uses: 3 → 0. S3 had the rule copied the suggestion:
16/57 — the rule writer (14/57) is now close to the ceiling the suggestion sets.

### Cumulative, against baseline v2 (not pre-registered as a test)
S3 paired **7 → 14 of 55, 7 gained, 0 lost, exact McNemar p = 0.016**; S5 +0.070, CI [+0.004,
+0.143]; S4 −0.031, CI spans zero. **Caveat:** Phase 2 has now run four paired comparisons
(Changes 22, 25, 26, and this cumulative one); under a Bonferroni-style correction for four
tests the threshold is 0.0125, which 0.016 does not pass. Strong, one-directional (no case
lost), not conclusive on its own.

### Is S3 above chance yet? — not shown
Unpaired S3 is 14/57 = 0.246 against a null of 0.173 (≈ 9.9 of 57 expected). No committed
tool tests one file against the null; a one-sample exact binomial test is needed before the
Phase 2 exit decision (plan).

### The departures (12 first rules not on the suggestion), read by hand
- **0 of 12 explain the departure** in the description, as instruction 1 asked (keyword
  search plus reading). This model does not follow the "say why" part as phrased.
- 6: an initial-access web rule first despite a `process_creation` suggestion — the
  attack-vector pull remains (step d).
- 5: web suggestions whose **product is "linux-windows/apache-iis"** — the analysis prompt's
  reference-table cell copied into the field; no gold web rule has a product (step 2.6).
- 1: `firewall/-` → `firewall/fortios`.

### Reading
- Precedence by prompt works: the first rule now follows the analysis stage in 44 of 57
  cases, overrides nearly vanish, and S3 rises with no case lost. Nothing is enforced.
- Detection fields improve (S5) — plausible, not shown: a rule written for the recommended
  log source picks fields from that log source.
- S3 is now limited by the **suggestion** (ceiling 16/57): the remaining gains have to come
  from the analysis stage (steps d, 2.6).

### Status
Plan 2.2 done. `p2c_first_rule60.jsonl` is the reference for step (d).

---

## 2026-09-25 — Housekeeping H7: the unused `LOG_SOURCE_SUGGESTION` prompt removed

Approved by the user in the Inbox triage. The prompt (72 lines, `backend/pipeline/prompts.py`)
was referenced nowhere — the analysis stage uses `COMBINED_ANALYSIS` — and carried its own
reference table with `sysmon` as the service for every Windows category. Removed after the
step (c) run finished, so no run spans the change; it cannot affect behaviour (never called).
Full suite 298 passed.

---

## 2026-09-25 — Change 27 (plan 2.3, step d): the attack-vector prompt's web bias (code done; not yet run)

### Motivation
After Change 26 the first rule follows the analysis stage, so the remaining S3 gains depend on
the suggestions, which follow the attack-vector stage. That stage labelled **18 of 46** non-web
cases with web telemetry (`p2c_first_rule60.jsonl`). Read by hand: some are genuine web
exploits whose gold rule detects the host follow-up (e.g. WSUS, CVE-2025-59287), but **4 of the
18 vectors contain Example A's text** — "Pandemic Registry Key", a Windows implant, became
"Unauthenticated HTTP POST to /saml/login with oversized/malformed SAMLRequest"; a browser
exploit became "HTTP POST to browser". Causes in the prompt: two of three worked examples were
web exploits; Example A was written from one real past case (Citrix, `NSC_TASS` — the rule in
`data/saved_rules.json`); the inline examples led with the same SAML request; and
`primary_telemetry` was "where the initial exploit would be visible", even for reports that
describe no exploit.

### Design — prompt only, the model still decides (user, 2026-09-25)
| Edit | Why |
|---|---|
| Example A replaced by **malware delivered by email, seen on the host** (ISO → LNK → rundll32 → DLL → Run key; invented names `Remit_8841.iso`, `qx7loader.dll`, `QxUpdate`) | Examples now 1 web (B, unchanged), 2 host (A, C); the most-copied real-case text is gone |
| `primary_telemetry` = "where the attacker activity this text describes would be most directly visible" — for an exploit of a network service, where the request arrives; for malware, intrusion or host activity, usually host telemetry; "decide from what the text actually describes" | The old definition forced an "initial exploit" onto every report |
| `initial_access_vector`: if the text does not say how the attacker got in, describe the first action it does describe — "never invent a network request the text does not mention" | "HTTP POST to browser" |
| Inline examples: the SAML request → "user opens a LNK file from an ISO email attachment"; pattern example `SAMLRequest=asdf` → `-enc JAB` | Same imbalance in miniature |
| Probe markers: `email_iso_lnk` group added (`remit_8841`, `qx7loader`, `qxupdate`); the old `saml` group kept to count residual copying | Copying of the new example is measured the same way |
Unchanged: Example B (web) and C (local), the 13-label vocabulary, every other stage.

### Verification
Tests first, seen failing (6 of 7): **7 tests** (`tests/test_attack_vector_prompt.py`) — the
real-case strings are gone; the examples are 1 web and 2 host; every example is valid JSON with
all 15 fields; one example has no network exploit (email, host telemetry); the new
`primary_telemetry` definition; the "never invent" clause; the markers cover the new example.
Full suite **305 passed**. Not run on the Spark (user: no run tonight).

### Measurement plan (fixed before the run)
Same 60 cases; arm `p2d_web_bias`, `eval/results/p2d_web_bias60.jsonl`; paired against
**`p2c_first_rule60.jsonl`**.
- Primary: non-web gold cases whose attack-vector telemetry is web (`diagnose_logsource.py`,
  "attack-vector telemetry web") — **18 of 46** in the reference.
- Secondary: example text copied into the recorded attack vector (a committed counter over the
  rows, to be written and run on the reference file **before** the run — plan); analysis top
  suggestion web (10); rule web (16); S3 paired (reference 14/57); the buckets; S1, S4, S5.
- Risk stated before the run: genuine web exploits could lose their web label; the web gold
  cases (webserver/proxy, 11 of 57) are watched separately for losses.

---

## 2026-09-26 — A committed counter for copied example text, run before Change 27's run

`eval/count_example_copies.py` (7 offline tests, `tests/test_count_example_copies.py`,
written first; full suite 312 passed). It applies the defect-15 criterion
(`probe_attack_vector.leaked_markers`: an invented example-only marker present in the output
and absent from the input) to a finished run's recorded attack vectors, offline. Input = the
case's extracted text (preprocessed from the snapshots) plus the bodies of the GitHub files the
PoC stage fetched — a superset of what the stage saw, so the count is a **lower bound**.
"In the vector itself" = initial access vector, entry point, attacker-controlled input, payload
signatures; "anywhere" also includes the incidental list and the reasoning.

### Before Change 27 (the pre-registered secondary measure's reference)
| Run | Copied anywhere | In the vector itself |
|---|---|---|
| `baseline60_v2.jsonl` | 11 of 60 (`saml` 6, `websocket_nginx` 8) | **4** (all `saml`) |
| `p2c_first_rule60.jsonl` (reference for step d) | 10 of 60 (`saml` 6, `websocket_nginx` 6) | **4** (all `saml`) |
The same four cases both times: `f6a711f3`, `47e0852a` (with the example's `NSC_TASS` cookie),
`29fd07fc`, `a1507d71` (the rootkit report). **Cross-check:** the defect-15 probe, a different
method (it reruns the stage and keeps the exact model input), measured 4 of 60 "in the vector
itself" after Change 12 — the same figure.

---

## 2026-09-26 — S3 tested against chance: a committed one-sample test (eval only; written during the step (d) run)

### Why
Phase 2's exit criterion is "S3 significantly above the null baseline (0.173)". Paired tests
compare two runs; nothing tested one run against chance. Written while the step (d) run was in
progress — measurement code only (`eval/summarise.py`), no pipeline file touched.

### Design (fixed before looking at any number)
- **Exact binomial test, one-sided** ("is S3 above 0.173?"), alpha 0.05, plus a 95% **Wilson**
  interval; standard library only (`math.comb`). The null is treated as fixed (it is measured
  over many mismatched gold pairs, Change 4) — disclosed.
- **Pre-registered use:** applied **once, to the final Phase 2 run**, for the exit decision.
  Values on earlier runs are descriptive (testing every run would reintroduce the
  multiple-comparison problem).
- The summariser prints, under S3: k/n, the Wilson interval, the p-value, and the smallest k
  that would give p < 0.05 at this n.

### Verification
Tests first, seen failing: **10 tests** (`tests/test_chance_test.py`) — p-values and Wilson
intervals against anchors computed once with scipy (hard-coded; scipy is not a declared
dependency and is not imported), including 56/1024 by hand and the Wilson interval the
Chapter 6 notes already cite for baseline v1 (0.076–0.262, reproduced); the "needed k" helper;
the summary fields. Full suite **322 passed**.

### Descriptive values on the finished runs
| Run | S3 | 95% Wilson | one-sided p | p < 0.05 needs |
|---|---|---|---|---|
| baseline v1 | 8/55 | 0.076–0.262 | 0.758 | ≥ 15/55 |
| baseline v2 | 7/57 | 0.061–0.232 | 0.884 | ≥ 16/57 |
| Change 22 (`p2a…_r2`) | 11/53 | 0.120–0.335 | 0.304 | ≥ 15/53 |
| Change 25 (`p2b…`) | 9/58 | 0.084–0.269 | 0.693 | ≥ 16/58 |
| Change 26 (`p2c…`) | 14/57 | 0.152–0.371 | 0.104 | ≥ 16/57 |
S3 is **not yet shown to be above chance**; after Change 26 it is two first rules short of the
threshold at n = 57.

---

## 2026-09-26 — Correction: two "non-web gold" denominators were copied, not read from the tool

Found while measuring Change 27. `diagnose_logsource.py` counts "web labels when the gold rule
is not a web rule" over the cases whose **first rule parses** (S3 is scored), so the
denominator changes from run to run. Two entries reused baseline v2's figure (46) instead of
the tool's output:
| Entry | Written | Tool output |
|---|---|---|
| "Change 22 measured" — "non-web gold cases: v2 46, now 46" | now 46 | **now 44** (`p2a_vocabulary60_r2.jsonl`) |
| "Change 27 … (code done)" — reference "18 of 46" | 18 of 46 | **18 of 48** (`p2c_first_rule60.jsonl`) |
The numerators (16, 18, 11, 18) are right, and no conclusion changes. The same two figures are
corrected in the plan (2.2a, 2.3) and the Chapter 6 notes (§6.4.3). From now on, every
denominator is quoted from the tool's output.

---

## 2026-09-26 — Change 27 measured (plan 2.3, step d)

`eval/results/p2d_web_bias60.jsonl`, arm `p2d_web_bias`, code `17c448c` (Changes 22 + 24 + 25 +
26 + 27), same 60 cases, 184.8 min, no relaunch, no manual step. No pipeline or harness file
changed during the run (`git diff 17c448c HEAD -- backend/ eval/run_eval.py
eval/run_resilient.py` is empty). **CITABLE.** Answers cut at the output limit: 6 calls in 2
cases, **both in the analysis stage** (`9a2d8b3e` again, 3 of 3; `a35c97c8`, 3 of 3 — its first
rule still scored S3 without a suggestion).

### Pre-registered measures, against `p2c_first_rule60.jsonl`
| Measure | Before | After | Tool |
|---|---|---|---|
| **Primary: attack-vector telemetry web, non-web gold** | **18 / 48** | **14 / 45** | `diagnose_logsource.py` |
| Example text copied into the vector itself | 4 / 60 (all old Example A, `saml`) | **2 / 60 (both the new Example A, `email_iso_lnk`)** | `count_example_copies.py` |
| Example text copied anywhere in the vector record | 10 / 60 (`saml` 6, `websocket_nginx` 6) | 7 / 60 (`websocket_nginx` 5, `email_iso_lnk` 2, `saml` 0) | same |
| Analysis top suggestion web, non-web gold | 10 / 48 | 7 / 45 | `diagnose_logsource.py` |
| Generated first rule web, non-web gold | 16 / 48 | **8 / 45** | same |
| S3 exact, paired (n = 54) | 13 | 13 | 2 gained, 2 lost; exact McNemar p = 1.0 |
| S1 valid first rule, paired (n = 60) | 57 | 56 | p = 1.0 |
| S4 ATT&CK F1, paired (n = 35) | 0.119 | 0.167 | +0.048, 95% CI [−0.029, +0.133] |
| S5 detection F1, paired (n = 52) | 0.291 | 0.287 | −0.004, 95% CI [−0.076, +0.067] |
| Tokens / seconds per case | — | — | no difference (CIs span zero) |
Buckets: right_suggested 22 → 22; right_rescued 0 → 1; overridden 2 → 0; ranked_low 11 → 10;
followed_wrong 21 → 20; wrong_elsewhere 1 → 3. Change 26's measure (first rule = top
suggestion) 44/57 → 47/56. Post-hoc (not pre-registered): the suggestion's ceiling (S3 had
the rule copied it) 16/57 → 11/56; one first rule uses a category no SigmaHQ rule uses
(`security`).
**Stated risk (web gold cases watched for losses): did not occur** (read case by case, not
from a committed tool): the 9 `webserver` gold cases kept web telemetry in both runs; the 2
`proxy` gold cases moved from `network_ids` to host labels (their rules were already
`process_creation`); none of the 11 web gold cases scored S3 in either run.

### Read case by case (post-hoc; not from a committed tool — the counts below are readings)
- **Half of the primary drop is the denominator.** Across all 60 rows the telemetry changed
  between web and non-web in 4 cases: 3 left web (`24c4d154`, `29fd07fc`, `47e0852a`), 1 became
  web (`c5a178bf`, a gold rule without a category). The other −2 are two web-labelled cases
  whose first rule no longer parses (`846b866e`, `a62298a3`), so they left the count. The
  tool's 18/48 → 14/45 compares different case sets — the same trap as unpaired means.
- **The 2 S3 gains are 2 of the 3 relabelled cases** (`24c4d154`, `29fd07fc`: web →
  `process_creation`, now right). `29fd07fc` was one of the 4 cases carrying the old SAML
  example text.
- **The 2 S3 losses are the new definition at work, not copying**: Kapeka (`64a871dd`) and
  TidePool (`7b544661`) — "a dropper drops a DLL" → telemetry `file_event`; the analysis and the
  rule followed; the gold rule is `process_creation`. A defensible reading of "where the
  activity is most directly visible" that the gold does not share.
- **The new example is copied into look-alike reports.** Qakbot (`0033cf83`) and Emotet LNK
  (`1f32d820`): the vector's initial access is the example's sentence word for word ("User
  opens a LNK file from an ISO email attachment, which executes rundll32.exe to load a
  malicious DLL"), and the invented `qx7loader.dll` / `QxUpdate` appear **in the generated
  rules of both cases** — detection strings for files that do not exist. In the reference run
  the old example's strings (`/saml/login`, `SAMLRequest`, `NSC_TASS`) were in the generated
  rules of 4 cases (`f6a711f3`, `47e0852a`, `29fd07fc`, `a1507d71`). Both cases' S3 was right,
  so S3 does not see it.
- The parse changes (2 first rules now parse, 3 no longer do) are YAML-level and in different
  cases; S1 p = 1.0 — run-to-run variation, recorded because S2–S5 are computed only on rules
  that parse.

### Cumulative, against baseline v2 (not pre-registered as a test)
S3 paired 6 → 13 of 55 (8 gained, 1 lost), exact McNemar p = 0.039; S5 +0.066, CI [−0.027,
+0.164]; S4 0.000. This is Phase 2's fifth paired comparison (Bonferroni-style threshold
0.01): not conclusive. After Change 26 the same comparison gave 7 → 14, p = 0.016, and S5's
interval excluded zero; it no longer does.
S3 against chance (descriptive; the test is pre-registered for the final Phase 2 run only):
13/56, 95% Wilson [0.141, 0.358], one-sided p = 0.160; p < 0.05 needs ≥ 16/56.

### Reading
- Change 27 did what an edit to the examples can do for the vector: the old real-case text is
  gone from every vector (in-vector `saml` 4 → 0), and first rules on web telemetry for non-web
  gold halved (16 → 8), with no web gold case lost.
- **S3 did not move** (13 = 13). The attack-vector web bias is no longer what limits S3; the
  analysis suggestion is (category, and the `product` of web suggestions —
  "linux-windows/apache-iis" in `20c6ed1c` and `0d0d9a8a`) — plan 2.6.
- **Defect 15 moved, it did not go away.** With this model, a concrete worked example is copied
  into answers for reports that resemble it; replacing the example changed *which* reports
  (web exploits → email malware) and how many (4 → 2), and the copied names still reach rules.
  Stays open.

### Limitations to disclose
- The primary measure and its web-label siblings are counted over cases whose first rule
  parses, so their denominators differ between runs; they are reported as counts, not tested
  paired (as for Change 22). A paired, all-rows version would need a committed tool.
- Copies into generated rules were found with a one-off search; not a committed measure.

### Status
Plan 2.3 done. Next: 2.6 (plan order). Open for the user: whether and when to treat defect 15
at its cause (options in the plan).

---

## 2026-09-26 — Change 28 (plan 2.6): the analysis prompt's log-source table is generated from SigmaHQ's rules (code done; run next)

### Motivation
After Change 27 the web bias no longer limits S3; the analysis stage's suggestion does. Its
reference table was hand-written: 13 rows, "Product" cells that mixed product and service
(`windows/sysmon`, `linux-windows/apache-iis`, `aws/azure/gcp`), and **no log source without a
category** — so gold rules defined by a service (Windows Security, zeek/http) were never
suggested (0 of 5 in these 60 cases). In the step (d) run, **19 top suggestions are not a log
source SigmaHQ uses, and all 19 come from those cells** (read case by case: 16
`webserver` + "linux-windows/apache-iis" verbatim, 1 `webserver` + "linux", 2 with `sysmon` as
the product). No SigmaHQ web rule has a product.

### Design (user, 2026-09-26: complete table; the model still chooses)
- **Generated, not written**: `scripts/build_sigma_logsource_table.py` →
  `backend/pipeline/sigma_logsource_table.json` (committed; SigmaHQ commit `dc3880459`). Built
  from `data/sigma/rules` — the rules the retrieval index uses — **never
  `rules-emerging-threats`, which holds the gold rules (checked: 0 of 437 manifest rule ids are
  in the main set)**. Same loader as Change 25's known-services list; a test pins that the
  table's service rows are exactly that list.
- **Complete**: all **35 categories** (with the products their rules use; "(none)" where the
  rules carry no product) and all **75 sources without a category** (product + service), each
  with the 5 fields its rules match on most (modifiers stripped). No threshold (user: include
  the one-rule sources). Rows alphabetical, so order says nothing about frequency; no counts.
- **Prompt, Part 3**: the two forms of a Sigma log source explained in general terms
  (category + product with no service / product + service without a category) — no single
  example pair to copy (the defect-15 lesson) — then the two tables; "write the names as they
  appear; '(none)' means leave that field empty". The output example's suggestion now has
  `"service": null`, and `logsource_primary` reads "process_access / windows" (was
  "process_access (Sysmon Event ID 10)"; free text, nothing parses it).
- **`on_table(suggestion, table)`** (spec check, `sigma_logsource.py`): used to measure only;
  nothing is enforced. Available to Phase 3.5's quality guard.
- Size: the tables are ~6,600 characters against ~1,000 before (an estimated ~1,400 more
  prompt tokens per analysis call — to be measured by the run's token counts).
Unchanged: every other stage and prompt, Change 25's normalisation, Change 26's first-rule
section.

### Verification
Tests first, seen failing: **31 tests** (`tests/test_logsource_table.py`) — building from a
fixture rule set (products per category, "no product" kept as such, the service form,
category rules naming a service listed under the category only, fields without modifiers
ranked by use and capped, keyword detections, unreadable files, alphabetical order);
rendering; `on_table` in both forms (11 cases, incl. the invented product); the committed
table (35 categories, `webserver`/`proxy` without product, Windows Security / zeek/http /
CloudTrail present, fortios/sslvpnd absent) and its equality with a fresh build; the prompt
(old cells gone, both tables in, both forms explained, example without service or Sysmon); the
stage puts the committed tables in its prompt (stub client, no LLM).
A new committed measure, **`eval/compare_suggestions.py`** (9 tests,
`tests/test_compare_suggestions.py`): the top suggestion against the gold log source over
**all rows** — gold from `eval/manifest.jsonl`, so a case counts whether or not its first rule
parses (avoids this morning's denominator trap), paired, exact McNemar. Full suite **362
passed**.

### Measurement plan (fixed before the run)
Same 60 cases; arm `p2e_table`, `eval/results/p2e_table60.jsonl`; paired against
**`p2d_web_bias60.jsonl`**. Reference values computed before the run with the committed tool:
| Measure (`compare_suggestions.py`, all 60 rows) | Reference (step d) |
|---|---|
| **Primary: top suggestion = gold log source** | **13 / 60** |
| Top suggestion on the table | 39 / 60 |
| Top suggestion without a category | 0 |
| No suggestion at all | 2 |
| = gold, gold defined by a service | 0 / 5 |
| = gold, web gold (webserver/proxy) | 0 / 12 |
| = gold, other category gold | 13 / 43 |
Secondary: S3 paired (`compare_runs.py`; reference 13 of 56 scored); Change 26's measure
(first rule = top suggestion, 47/56); the buckets; S1, S4, S5; tokens and seconds (expected to
rise with the longer prompt); answers cut at the limit.
**Reachable, not predicted:** 4 of the 5 service-based gold rules are on the table
(`fortios`/`sslvpnd` is emerging-threats only, so the table cannot offer it).
**Risks stated before the run:** (1) a longer table could dilute attention or pull
suggestions toward rare sources — watched as losses among "other category" gold (13); (2)
service-based suggestions could replace a correct category — watched via "without a
category" and the losses; (3) the new fields column could change what generation writes (S5).

---

## 2026-09-26 — The copy counter now counts copies that reach the generated rules (eval only; written during the Change 28 run)

For the shared defect-15 run (plan), before its changes are written. `eval/count_example_copies.py`
gains **`in_rules`**: an example marker in the case's generated rules and absent from its input
(the same criterion). 6 new tests, written first (`tests/test_count_example_copies.py`, 13 in
all); full suite **368 passed**. No pipeline file touched.
**Why retrieval is not a source:** generation also reads retrieved documents, so a marker in a
rule could in principle come from one. `--check-retrieval` (committed) scans the local
retrieval collections: **no marker in any of them** (sigma_rules 3,104 documents, mitre_attack
691, cwe_kb 944, sigma_taxonomy 332, sysmon_info 18; run 2026-09-26). A marker in a rule that is
absent from the input can only have come from the prompt's examples.

| Run | In the vector itself | In the generated rules |
|---|---|---|
| `baseline60_v2.jsonl` | 4 (`saml`) | **4** — the same 4 cases |
| `p2c_first_rule60.jsonl` | 4 (`saml`) | **4** — the same 4 cases |
| `p2d_web_bias60.jsonl` | 2 (`email_iso_lnk`) | **2** — the same 2 cases |
This reproduces the one-off search in "Change 27 measured" (now citable) and adds a finding:
**every example copied into the vector also reached the rules** (10 of 10 case-runs). The
attack vector feeds generation, so an invented string there becomes a detection string.

---

## 2026-09-26 — Audit: does anything steer results toward the answers? Held-out confirmation added (plan 2.9); the chance test moves to it

### The audit (user's question: "none of this is hard-coding the results?")
- **The pipeline cannot see the gold.** No file under `backend/` reads the manifest, `eval/`, or
  `rules-emerging-threats` (searched). Everything the pipeline reads — the retrieval index,
  Change 25's service list, Change 28's table — comes from `data/sigma/rules`, which holds **0
  of the 437** manifest rule ids.
- **Nothing is chosen per case.** Change 28's table is complete and generated; no row was
  added because a test case needed it.
- **Where code changes a model answer** (all of Phase 1–2; checked in `stage_generate.py`,
  `stage_review.py`, `orchestrator.py`, `stage_analysis.py`):
  | Change | What code does | Scored? |
  |---|---|---|
  | 8 | routes a bare URL to rule generation instead of asking the intent classifier | routing, not rule content |
  | 9 | replaces invalid rule ids | ids are not scored |
  | 24 | stops an answer at 16,384 tokens | bounds time; the cut answer is scored as a failure |
  | 25 | drops `service` from a suggestion that has a category (Sigma's convention; user's rule; value kept in `service_dropped`) | acts on the suggestion, not the rule — the rule writer still chooses its log source |
  Changes 22, 26, 27, 28 are prompt or context only (22's label → category translation is a
  fixed vocabulary map, written once, not per case). Checks that only report back: pySigma
  validation and the ATT&CK tactic check (`stage_review.py`) produce issues that go to the
  review model or trigger a regeneration — the model makes the fix; code edits no tag or
  detection.
- **The real risk is not hard-coding but tuning to the test set.** Every Phase 2 change was
  found by reading failures in the same 60 cases (seed 0) it was then measured on. The fixes
  are general, but gains measured on the cases that motivated them can be optimistic.

### Held-out confirmation (plan 2.9; user, 2026-09-26)
After the last run on the 60 tuning cases: 60 new cases, drawn by a committed script
(stratified, seed 0) from the **242 corpus cases that appear in no result file** (61 distinct
cases have ever been run, across 23 result files; a new seed alone would share 13–15 of the
60). The case list is committed before any run on it; no one reads held-out outputs and no
pipeline file changes until both runs are done. Runs: the final Phase 2 pipeline, and baseline
v2's code (`5627e91`, to be confirmed) on the same cases, for a paired before/after on unseen
cases. Page snapshots exist for all 242 (checked); PoC GitHub snapshots to be checked at
preflight.

### Revision of a pre-registration (made before any held-out result exists)
"S3 tested against chance" (this log, 2026-09-26) pre-registered the one-sided binomial test
for **"the final Phase 2 run"**. It is revised to: applied **once, to the final pipeline's
held-out run** (2.9). Reason: the final run on the 60 would be on the cases the changes were
tuned on. The test, its alpha (0.05), its null (0.173) and its one-sidedness are unchanged; the
value on the last tuning run is reported descriptively, like every earlier one.

---

## 2026-09-26 — Change 28 measured (plan 2.6): the suggestions improve; the rule writer adds its own product

`eval/results/p2e_table60.jsonl`, arm `p2e_table`, code `c190477` (Changes 22 + 24–28), same 60
cases, 160.8 min, no relaunch, no manual step; no pipeline or harness file changed during the
run. **CITABLE.** Answers cut at the limit: 1 call in 1 case (`e710a880`, rescued by the retry).

### Pre-registered measures, against `p2d_web_bias60.jsonl`
| Measure (`compare_suggestions.py`, all 60 rows, paired) | Before | After | Test |
|---|---|---|---|
| **Primary: top suggestion = gold log source** | **13** | **23** | 12 gained, 2 lost; **exact McNemar p = 0.013** |
| Top suggestion on the table | 39 | 59 | 21 gained, 1 lost; p < 0.001 |
| Top suggestion without a category | 0 | 0 | — |
| No suggestion at all | 2 | 1 | — |
| = gold, gold defined by a service (5) | 0 | 0 | — |
| = gold, web gold (12) | 0 | **9** | — |
| = gold, other category gold (43) | 13 | 14 | — |
| Measure (`compare_runs.py`, paired) | Before | After | Test |
|---|---|---|---|
| S3 exact (n = 53) | 12 | 13 | 2 gained, 1 lost; p = 1.0 |
| S1 valid first rule (n = 60) | 56 | 55 | p = 1.0 |
| S4 ATT&CK F1 (n = 34) | 0.191 | 0.164 | −0.027, 95% CI [−0.088, +0.025] |
| S5 detection F1 (n = 51) | 0.286 | 0.272 | −0.014, 95% CI [−0.086, +0.050] |
| Tokens / seconds per case | — | — | no difference (CIs span zero) |
`diagnose_logsource.py` (over parsed first rules; denominators 56 → 55): Change 26's measure,
first rule = top suggestion, **47/56 → 35/55**; per field category 23 → 22, product 32 → 31,
service 49 → 43; buckets right_suggested 22 → 21, overridden 0 → 1, ranked_low 10 → 10,
followed_wrong 20 → 20, wrong_elsewhere 3 → 2. Post-hoc: S3 had the rule used the top
suggestion 11/56 → 20/55. The attack-vector stage was unchanged, and its numbers match step (d):
web telemetry on non-web gold 14/45; example copies in the vector 2 → 1, in the rules 2 → 1
(`0033cf83`, the same case as in step d).
S3 against chance (descriptive): 14/55, 95% Wilson [0.158, 0.383], p = 0.082; p < 0.05 needs
≥ 15/55.
Risks stated before the run: (1) dilution — "other category" 13 → 14, no sign of it; (2) the
service form replacing a right category — the service form was never used; (3) S5 — no
detectable change.

### Where the gain went (read case by case; post-hoc)
- **The rule writer adds a product the suggestion does not have.** 10 cases have a right top
  suggestion and a first rule that does not score: **8 are web gold**, and in **6** of them the
  rule adds a product (and often a service) — `fortigate`, `iis`/`owa`, `sitecore`/`shell`,
  `http`/`web`, and twice `webserver` as the product; in 2 the first rule does not parse. The
  other 2: `e710a880` (does not parse) and `a62298a3` (an initial-access web rule first,
  `sysaid`/`httpd`). The model reads Sigma's `product` as the attacked application; in Sigma it
  is the platform that writes the log, and SigmaHQ's web rules have none (13 of 13 `webserver`,
  29 of 29 `proxy` rules in the main set). The rule writer never sees the table.
- **The service form is never suggested** (0 of 60). The 4 reachable service-based gold rules
  (Windows Security ×3, zeek/http) get host categories (`process_creation`…) or `webserver`,
  which are plausible choices; the table alone did not change that.
- The 2 suggestion losses: `29fd07fc` → `file_event`; `b7155193` → none: the analysis answer
  failed to parse ("Invalid \escape") — defect 5, here in the analysis stage.
- Case `9a2d8b3e`, which looped in the analysis stage in all three previous runs, finished
  without a cut answer; 1 cut call in the run (6 in step d, 7 in step c). One run: not a finding.

### Cumulative, against baseline v2 (not pre-registered as a test)
S3 paired 6 → 14 of 54 (9 gained, 1 lost), exact McNemar p = 0.021 — the sixth paired
comparison in Phase 2 (Bonferroni-style threshold 0.0083): not conclusive. S5 +0.053, CI
[−0.029, +0.144]; S4 −0.020, CI spans zero.

### Reading
- **The pre-registered primary moved: the complete table makes the analysis stage's log source
  right far more often** (13 → 23 of 60, p = 0.013), almost entirely on web gold (0 → 9), and
  its suggestions are now real SigmaHQ log sources in 59 of 60 cases.
- **S3 did not follow, because the next stage rewrites the product.** The same throughline as
  defect 11 (§6.4.4): a stage gets it right, a later stage changes it. It now matters beyond
  S3: a rule converted to a SIEM query with an invented product would target the wrong index.
- Proposed next (user's decision): tell the rule writer what the table says about the
  recommended log source's absent fields, and what `product` means in Sigma — prompt only.

### Limitations to disclose
- The case readings above (the 6 added products, the service-form cases) are post-hoc.
- The primary is significant at 0.05 as this step's single pre-registered primary; it is one
  run, on the tuning cases (plan 2.9).

---

## 2026-09-26 — Change 29 (plan 2.6b): the rule writer is told what the recommended log source leaves out, and what `product` means (code done; run next)

### Motivation
Change 28's run: the analysis stage's suggestion became right for 9 of 12 web gold cases
("webserver", no product), but S3 did not move because the rule writer added a product. The
committed measure written for this step (below) counts it on that run: **of the 50 first
rules that keep the suggested category, 15 add a field the suggestion lacks — 14 a product**,
13 of them `webserver` rules given the attacked software (`fortigate`, `mikrotik`,
`barracuda`, `globalprotect`, `confluence`, `manageengine_supportcenter_plus`…, and `webserver`
itself 3 times). SigmaHQ's 13 `webserver` and 29 `proxy` rules carry no product. The rule
writer never sees the table. (In step d the count is 0 — the old web suggestions carried
the invented "linux-windows/apache-iis" product themselves.)

### Design (user, 2026-09-26: go ahead; prompt only, the model still decides)
- **`absent_fields_note(suggestion, table)`** (`sigma_logsource.py`), appended to the
  "Log Source for the First Rule" block after the confidence line: what SigmaHQ's rules leave
  out of the recommended log source, **from the committed table** — a category source has no
  service; a category whose rules name no product (web server, proxy…) has none either; the
  service form has no category; a category suggested without the product its rules do use
  gets them listed ("name a product: linux, macos or windows"), not forbidden. A log source
  the table does not know gets nothing. The analyst's confirmation gets no note.
  E.g. "In SigmaHQ's rules this log source has no `product` and no `service`: leave them out."
- **One bullet in generation instruction 5**, next to the existing `service:`/`version:`
  bullets: "`product:` names what produces the log (the operating system, platform or
  appliance whose log it is), not necessarily the software the attack targets. Leave it out
  when that log source has none." ("not necessarily": for application logs the targeted
  application is what writes the log.)
Unchanged: the analysis stage (its prompt and table), every other stage, Change 26's section.

### Verification
Tests first, seen failing: **19 tests** (`tests/test_first_rule_absent_fields.py`) — the note
for each form (no product, product present, missing product named, service form, unknown
sources silent); the block (note after the confidence line; no table → as before; analyst
confirmation → no note); the prompt bullet; the generation stage passes the committed table
(stub client); the measure. Change 26's 10 tests pass unchanged. Full suite **387 passed**.

### Measurement plan (fixed before the run)
Same 60 cases; arm `p2f_product`, `eval/results/p2f_product60.jsonl`; paired against
**`p2e_table60.jsonl`**.
- **Primary: S3, paired** (`compare_runs.py`) — reference run 14/55 scored.
- Mechanism (`diagnose_logsource.py`, "Change 29 measure", committed before the run): first
  rules on the suggested category that add a product / a service / either — reference **14 /
  8 / 15 of 50**.
- Secondary: Change 26's measure (first rule = top suggestion, 35/55); S3 per field (product
  31/55, service 43/55); `compare_suggestions.py` as a consistency check (the analysis stage is
  unchanged; 23/60); S1, S4, S5; copies (`count_example_copies.py`; 1 in the vector, 1 in the
  rules); cut answers.
- **Reachable, not predicted:** 6 web gold cases lost S3 only to an added product in the
  reference run (2 more first rules did not parse).
- **Risk stated before the run:** the `product` bullet could make the rule writer drop a
  correct product (e.g. `windows`) — watched via the product field and the S3 losses.

---

## 2026-09-26 — Measures for the shared run (Changes 30–32), written during the Change 29 run (eval only)

Fixed before the changes they measure are written (user, 2026-09-26: prepare the shared run
while 2.6b runs). No pipeline or harness file touched; the run imports none of these files.
- **Change 30 (defect 15 at its cause):** `eval/probe_attack_vector.py` gains a
  **`placeholders`** marker group — the exact placeholders the rewritten examples will use
  (`<attachment>`, `<loader>`, `<run-key value>`, `<endpoint>`, `<parameter>`, `<patch file>`,
  `<patch password>`, `<patch helper>`, `<patch script>`, `<vendor binary>`, `<setuid
  binary>`); a placeholder in an answer is a copy by the usual criterion. The old markers stay
  (they should fall to 0). `count_example_copies.py` also counts **payload patterns absent from
  the input** (`ungrounded_patterns`; `inferred_from_class` excluded) — an upper bound on
  invented patterns, since a real string written as a regex also counts. 3 tests, written
  first and seen failing.
- **Changes 31 (ATT&CK ID check) and 32 (at most 10 techniques):** new
  `eval/count_techniques.py` — per case the technique IDs the analysis stage **wrote** (after
  Change 31: kept `ttp_mappings` + recorded `ttp_dropped_ids`), the ones ATT&CK does not have,
  rules tagged with such an ID, and cut answers; summary: median / max / cases over 10. Valid
  IDs: `backend/pipeline/attack_technique_ids.json`, to be built from the local ATT&CK
  collection (691 IDs: 216 techniques, 475 sub-techniques; `T1562.339` absent) after the run.
  **8 tests — written together with the code, not seen failing first** (a lapse in the
  tests-first rule). Checked instead by deliberate bugs: 4 mutations of the code; 3 were
  caught, the fourth (">10" → "≥10") was not, so a boundary test (exactly 10 is not over 10)
  was added and catches it.
Full suite **398 passed**.

---

## 2026-09-26 — Correction: generation and review do not run at temperature 0; prompt review written

Found while reviewing the prompts (user's request; `thesis/PROMPT_REVIEW.md`). The notes and
several entries say the pipeline runs at "temperature 0". It does for the attack-vector, PoC
and analysis stages; **generation calls the model at 0.3 and review at 0.2**
(`stage_generate.py`, `stage_review.py`, unchanged since before baseline v1). Those two stages
write and rewrite the rules S3–S5 score, so part of the case-level churn between two runs is
sampling — how much is unmeasured. No result changes; every paired comparison already treats
churn as noise. The defect-19 explanation is unaffected (the loops are in the analysis stage,
which does run at 0). Chapter 7 item 15 corrected.

The prompt review itself (no pipeline change) is in `thesis/PROMPT_REVIEW.md`: five patterns
with their evidence — the hand-written examples outweigh everything else (143 of 150 tactic
tags in the Change 28 run use the example's underscore style, against 3,021 of 3,021 hyphenated
in SigmaHQ's main set and 389 of 389 in the gold rules; pySigma flags each); model-made results
handed on as facts ("strings a real attacker MUST produce"); competing absolute orders; the
review rewriting the scored rules without the log-source decision (unmeasured — rows keep only
the reviewed rules); YAML inside JSON. Five prompts are unused. Its candidate changes are
proposals for the user; the counts in it come from one-off scripts over committed result files
and need committed measures before being cited.

---

## 2026-09-26 — Change 33's measure (prompt review item 1, added to the shared run by the user)

User, 2026-09-26: the rule writer's example fix joins the shared run (Changes 30–33). Its
measure, written first and seen failing: **`eval/count_rule_conventions.py`** (5 tests) —
multi-word tactic tags by style, pySigma "Invalid MITRE ATT&CK tagging" issues, rules with the
old example id, cases with a duplicate id, rules still carrying the new placeholder id.
| Run | Tactic tags underscore / hyphen | pySigma tag issues | Old example id | Cases with a duplicate id |
|---|---|---|---|---|
| `baseline60_v2.jsonl` | 152 / 14 | 158 | 2 | 0 |
| `p2d_web_bias60.jsonl` | 140 / 18 | 140 | 0 | 0 |
| `p2e_table60.jsonl` | 137 / 6 | 136 | 2 | 1 |
**Correction to the previous entry:** its "143 of 150" came from a one-off count that also
matched text outside the `tags` field; the committed measure gives **137 of 143** on the same
run. The review document is corrected; the conclusion is unchanged.

---

## 2026-09-26 — Change 29 measured (plan 2.6b): S3 rises; the rule writer no longer adds a product

`eval/results/p2f_product60.jsonl`, arm `p2f_product`, code `e692701` (Changes 22 + 24–29), same
60 cases, 160.5 min, no relaunch, no manual step; no pipeline or harness file changed during
the run. **CITABLE.** Answers cut at the limit: 1 call in 1 case.

### Pre-registered measures, against `p2e_table60.jsonl`
| Measure | Before | After | Test / tool |
|---|---|---|---|
| **Primary: S3 exact, paired (n = 55)** | **14** | **21** | **8 gained, 1 lost; exact McNemar p = 0.039** (`compare_runs.py`) |
| Mechanism: first rules on the suggested category that add a product / a service / either | 14 / 8 / 15 of 50 | **0 / 0 / 0 of 53** | `diagnose_logsource.py`, "Change 29 measure" |
| First rule = top suggestion (Change 26's measure) | 35 / 55 | **53 / 56** | same |
| S3 per field: product / service | 31 / 43 of 55 | 38 / 50 of 56 | same |
| Top suggestion = gold, all 60 rows (consistency: the analysis stage is unchanged) | 23 | 23 | 1 gained, 1 lost; p = 1.0 (`compare_suggestions.py`) |
| S1 valid first rule (n = 60) | 55 | 56 | p = 1.0 |
| S4 ATT&CK F1 (n = 37) | 0.151 | 0.149 | −0.002, 95% CI [−0.041, +0.045] |
| S5 detection F1 (n = 53) | 0.274 | 0.303 | +0.029, 95% CI [−0.024, +0.085] |
| Tokens / seconds per case | — | — | no difference |
Buckets: right_suggested 21 → 22, overridden 1 → 0, wrong_elsewhere 2 → 0, followed_wrong 20 → 23.
Post-hoc: S3 had the rule used the top suggestion verbatim 20/56 — S3 (21/56) is now at the
ceiling the suggestion sets. **Stated risk (dropping a correct product): not seen** — the
product field is right more often (31 → 38).

### The changed cases (read case by case)
- **All 6 cases "reachable" in the plan were gained** — the web gold rules that lost S3 only to
  an added product (`20c6ed1c` sitecore/shell, `b014ea07` and `fce2c2e2` webserver, `a2e97350`
  fortigate, `f0500377` http/web, `181f49fa` iis/owa): each first rule is now `webserver` with
  no product and no service.
- `a62298a3`: the first rule now follows the `process_creation` suggestion instead of an
  initial-access web rule (`sysaid`/`httpd`).
- `29fd07fc` gained and `64a871dd` lost with their **suggestions**, which swapped between
  `process_creation` and `file_event` from one run to the next — the analysis stage's own
  run-to-run variation (its code is unchanged), cancelling out in the consistency check.

### Cumulative, against baseline v2 (not pre-registered as a test)
S3 paired **6 → 21 of 54, 16 gained, 1 lost, exact McNemar p < 0.001** (0.0003) — the seventh
paired comparison in Phase 2; it passes a Bonferroni-style threshold for seven (0.0071). S5
+0.082, 95% CI [−0.011, +0.181]; S4 −0.023, CI spans zero.
S3 against chance (descriptive; the pre-registered test is for the held-out run, plan 2.9):
21/56 = 0.375, 95% Wilson [0.260, 0.506], one-sided p < 0.001 — above chance on the tuning
cases for the first time.

### Reading
- A generated note — what SigmaHQ's rules leave out of the recommended log source — and one
  sentence on what `product` means removed the added products entirely (15 → 0) and moved S3
  by exactly the cases it could reach. Nothing is enforced; the model chose.
- Phase 2's log-source chain now holds end to end: the rule follows the suggestion in 53 of 56
  cases, so S3 is limited by the analysis stage's suggestion (23 of 60 right).
- `[DISCLOSE]` All of this is on the 60 tuning cases; the claim waits for the held-out run.

### Other counts on this run (the shared run's reference)
Copies (`count_example_copies.py`): in the vector 1, in the rules 1 (`0033cf83`), anywhere 6;
payload patterns absent from the input 62 in 34 cases. Conventions
(`count_rule_conventions.py`): tactic tags underscore / hyphen 141 / 8, pySigma tag issues 145,
old example id 1 rule, cases with a duplicate id 0.

---

## 2026-09-26 — The shared run: Changes 30–33 (defect 15 a+b, plan 2.7, plan 2.8, prompt review item 1) — code done; run next

User decisions (2026-09-26): 2.6b runs alone first (done), then one run carries four changes,
each with its own committed measure; their effect on S3–S5 is reported as joint (Chapter 5,
"Attribution"). All tests were written before the code (the Change 31/32 measures' tests with
their code — see "Measures for the shared run"), most while the Change 29 run was in progress;
the pipeline edits were made after it finished.

### The four changes
| Change | What | Code / prompt |
|---|---|---|
| **30** — defect 15 at its cause (options a + b) | The attack-vector examples keep their structure but every invented value becomes a placeholder (`<attachment>.iso`, `<loader>.dll`, `<run-key value>`, `/<endpoint>`, `<parameter>`, `<patch file>`, `<patch password>`, `<patch helper>`, `<patch script>`, `<vendor binary>`, `/usr/bin/<setuid binary>`), also in the inline field examples; a note says the examples are invented, their values are placeholders, and nothing in them may be reused — "take every value from the input text or the PoC code". Generic tool names (`rundll32.exe`, `Upgrade: websocket`) stay | prompt |
| **31** — plan 2.7, ATT&CK ID check | `backend/pipeline/attack_ids.py`: the analysis stage's technique IDs that ATT&CK does not have are dropped and recorded (`ttp_dropped_ids`, carried to the rows); never repaired. Valid IDs: `attack_technique_ids.json`, **691** IDs built by `scripts/build_attack_technique_ids.py` from the local ATT&CK collection (216 techniques, 475 sub-techniques) | code (validation + record) |
| **32** — plan 2.8 | Analysis prompt, technique part: "5. List at most the 10 most relevant techniques, most relevant first" | prompt |
| **33** — prompt review item 1 | The rule writer's example: tactic tag `attack.credential-access` (hyphen), id `<new UUID>` (not a UUID, so Change 9 replaces a copy); instruction 11 asks for SigmaHQ's hyphenated tactic names | prompt |
Unchanged: every other prompt and stage; the Change 28 table and Change 29 note.

### Verification
New tests: Change 30 — 5 (`tests/test_attack_vector_placeholders.py`; no old example value left,
only counted placeholders, all of them present, the note, the structure kept); Change 27's
marker test updated (its example names left the prompt by design; it now checks the
placeholders). Change 31 — 9 (`tests/test_attack_id_check.py`; kept in order / dropped and
recorded, invalid sub-technique not repaired, blank and non-dict entries, the committed list
of 691, the check and its measure read one file, the stage, the rows). Change 32 — 3
(`tests/test_technique_limit.py`). Change 33 — 6 (`tests/test_generation_example.py`; no
underscore tactic anywhere in the prompt, the example's tags, instruction 11, the old id gone
and the new one not a UUID, a copy replaced by Change 9, the example still a complete rule).
All seen failing before the code except the ones that pin what is kept. Full suite **426
passed**.

### Measurement plan (fixed before the run)
Same 60 cases; arm `p2g_shared`, `eval/results/p2g_shared60.jsonl`; paired against
**`p2f_product60.jsonl`**. References computed on it with the committed tools:
| Change | Measure (tool) | Reference |
|---|---|---|
| 30 | example text in the vector / in the rules / anywhere, incl. placeholders (`count_example_copies.py`) | 1 / 1 / 6 (placeholders 0) |
| 30 | payload patterns absent from the input — upper bound (same) | 62 in 34 cases |
| 31 | technique IDs written that ATT&CK does not have; rules tagged with one (`count_techniques.py`) | 0 in 0 cases; 0 |
| 32 | techniques written per case: median / max / cases over 10 (same) | 5 / 18 / 12 |
| 32 | cases with an answer cut at the limit (same) | 1 |
| 33 | tactic tags underscore / hyphen; pySigma tag issues (`count_rule_conventions.py`) | 141 / 8; 145 |
| 33 | rules with the old example id; cases with a duplicate id; placeholder ids left (same) | 1; 0; 0 |
| joint | S3 paired (`compare_runs.py`) | 21 of 56 scored |
| joint | top suggestion = gold, all rows (`compare_suggestions.py`) | 23 / 60 |
| joint | S1, S4 (n = 38), S5 (n = 54) (`summarise.py`); first rule = top suggestion, added fields (`diagnose_logsource.py`) | 56/60, 0.158, 0.298; 53/56, 0/53 |
**Expected little change for 31 and 32 on this reference** (said before the run): invented IDs
were 90–192 in 1–4 cases per run up to step (d), all in answers that ran away (lists of
102–111 techniques); since Change 28 there are none and lists stop at 18 — post-hoc, two runs,
cause unknown. The two changes stay as guards; their measures will show whether that holds.
**Risks stated before the run:** (1) placeholder examples may teach the attack-vector stage
less, so its answers — and the suggestions built on them — could get worse (watched: the
suggestion measure, web labels on non-web gold 15/46, S3); (2) the stage may copy placeholders
literally (counted); (3) the 10-technique cap could cut gold techniques (S4; in the Change 25
data 21 of the 24 gold techniques found were in the first 10); (4) none expected on S4 from the
hyphen tags (S4 compares techniques only).

---

## 2026-09-26 — The shared run measured (Changes 30–33): each change did its job; the joint scores held

`eval/results/p2g_shared60.jsonl`, arm `p2g_shared`, code `a6e9157` (Changes 22 + 24–33), same
60 cases, 154 s per case, no relaunch, no manual step; no pipeline or harness file changed during
the run. **CITABLE.** No answer cut at the limit.

### Pre-registered measures, against `p2f_product60.jsonl`
| Change | Measure (tool) | Before | After |
|---|---|---|---|
| **30** | example text in the vector / in the rules / anywhere (`count_example_copies.py`) | 1 / 1 / 6 | **0 / 0 / 0** (no placeholder copied) |
| 30 | payload patterns absent from the input — upper bound (same) | 62 in 34 cases | 62 in 35 cases |
| **31** | technique IDs written that ATT&CK does not have (`count_techniques.py`) | 0 | 1 in 1 case (`0033cf83`: `T1086`, not in the current ATT&CK data) — **dropped and recorded** |
| 31 | rules tagged with such an ID (same) | 0 | 0 |
| **32** | techniques written per case: median / max / cases over 10 (same) | 5 / 18 / 12 | **10 / 10 / 0** |
| 32 | cases with an answer cut at the limit (same) | 1 | 0 |
| **33** | tactic tags underscore / hyphen (`count_rule_conventions.py`) | 141 / 8 | **0 / 144** |
| 33 | pySigma "Invalid MITRE ATT&CK tagging" issues (same) | 145 | **2** |
| 33 | rules with the old example id / cases with a duplicate id / placeholder ids left (same) | 1 / 0 / 0 | 0 / 0 / 0 |
| joint | **S3 exact, paired (n = 49)** (`compare_runs.py`) | 18 | 20 — 3 gained, 1 lost; p = 0.625 |
| joint | S1 valid first rule (n = 60) | 56 | 52 — 7 lost, 3 gained; p = 0.344 |
| joint | S4 ATT&CK F1 (n = 33) | 0.146 | 0.138 — −0.008, 95% CI [−0.071, +0.049] |
| joint | S5 detection F1 (n = 48) | 0.300 | 0.286 — −0.014, 95% CI [−0.092, +0.067] |
| joint | top suggestion = gold, all rows (`compare_suggestions.py`) | 23 | 23 — 4 gained, 4 lost; p = 1.0 (web gold 9 → 6, other 14 → 17) |
| joint | first rule = top suggestion; added fields (`diagnose_logsource.py`) | 53/56; 0 | 50/52; 0 |
Also: rules per case 4.00 → 3.65 (95% CI [−0.78, +0.03]); tokens and seconds no difference; S2
(mean pySigma issues per rule, `summarise.py`) **0.77 → 0.00** — see the reading. Attack-vector
web telemetry on non-web gold 15/46 → 12/43.
**Stated risks:** (1) placeholders teaching less — the suggestion measure is unchanged overall
(23 = 23), but web gold suggestions fell 9 → 6 (3 cases; within the analysis stage's run-to-run
swaps seen before, not established either way); (2) placeholder copies — none; (3) the cap
cutting gold techniques — S4 no detectable change; (4) S4 from the tags — none.

### Read case by case (post-hoc)
- **S1: 3 of the 7 lost first rules are defect 5** — the generation answer failed to parse
  ("Invalid \escape", a backslash in a Windows path inside the JSON string), on both attempts,
  so those cases have no rules (`c5a178bf`, `b014ea07`, `ec3a3c2f`). The log has 6 such escape
  failures (the Change 29 run: 1). None of Changes 30–33 touched backslashes or the output
  format; the cluster is recorded, not attributed. The other 4 are ordinary YAML errors, of the
  kind that swap between runs (3 were gained the same way).
- **Change 32's cap became a quota:** asked for "at most the 10 most relevant", the analysis
  now lists exactly 10 in most cases (median 5 → 10). The rules did not follow: technique tags
  on the first rule, median 1 before and after, mean 1.47 → 1.62 (one-off count).
- **S2 was mostly the tag style.** With the hyphenated tags, pySigma's issues per rule fall from
  0.77 to 0.00: S2 in every earlier run mostly measured the example's outdated tag convention.

### Cumulative, against baseline v2 (not pre-registered as a test)
S3 paired **6 → 22 of 50 (18 gained, 2 lost), p < 0.001**; S5 +0.087, 95% CI [−0.017, +0.193];
S4 −0.024, CI [−0.067, 0.000]; rules per case −0.50, CI [−1.03, −0.03]. S3 against chance
(descriptive; the test is for the held-out run): 22/52 = 0.423, 95% Wilson [0.299, 0.558].

### Reading
- Each change did what it was built for, on its own measure: copies of the examples 0 (defect
  15 at its cause), tags in SigmaHQ's style (pySigma issues 145 → 2), technique lists bounded
  (over 10: 12 → 0), invented IDs checked. None moved S3, S4 or S5 detectably — as expected for
  31–33, and for 30 its purpose was rule quality (no invented names in rules), not S3.
- Open: the quota effect of "at most 10"; the defect-5 cluster (prompt review P5, YAML in
  JSON); web gold suggestions 9 → 6 (watch in the held-out run).
- **This is the last planned run on the tuning cases.** Next: plan 2.9, the held-out
  confirmation, where the pre-registered chance test is applied.

---

## 2026-09-26 — Phase 2 frozen; the held-out cases drawn; the confirmation's plan fixed before any run (plan 2.9)

### Freeze (user, 2026-09-26)
The Phase 2 pipeline is **frozen at `a6e9157`** (Changes 22 + 24–33); no pipeline or harness file
changes until both held-out runs are done. Open items — the "at most 10" quota, the defect-5
cluster, the prompt review's candidates, the retrieval findings — go to the next phase: they
concern rule quality rather than the log source, and a later confirmation can use the 182
corpus cases still unused after this draw.

### The draw — `eval/draw_heldout.py`, once
6 tests written first (`tests/test_draw_heldout.py`; seen failing): used ids from every result
file (backups included), no used case drawn, reproducible, manifest lines kept verbatim, the list
written once (the script refuses to overwrite it), and the committed list (60 distinct manifest
cases, none in the tuning results). Run once: corpus 303 cases (the harness's own filter); 61
ever run, in any result file; **242 never run; 60 drawn** with the harness's stratified sampler,
seed 0 → **`eval/manifest_heldout.jsonl`**, committed before any run on it. Composition:
`process_creation` 24, `webserver` 12, `file_event` 7, no category (service-based) 6, `proxy` 3,
`registry_set` 2, `image_load` 2, one each of `registry_event`, `dns_query`, `ps_script`,
`registry_add`. Inputs checked offline: all 60 load; page snapshots on disk; all 4 GitHub code
links have recorded snapshots. Only the categories above were looked at — no output exists.

### Measurement plan (fixed before any held-out run)
**Runs** (same flags as every Phase 2 run, `--no-web-enrich`; no `--sample` — the file holds the 60):
1. **Final pipeline** — code `a6e9157` (the working tree at the commit of this entry; no pipeline
   file differs), arm `heldout_final`, `eval/results/heldout_final60.jsonl`,
   `--manifest eval/manifest_heldout.jsonl`.
2. **Baseline v2's code** — commit `5627e91`. Confirmed as baseline v2's code: no pipeline,
   harness or scorer file differs between it and the commit that recorded baseline v2's result
   (`8327c9b`), and `eval/scorers.py` is unchanged since, so both arms are scored by identical
   code. Run from a separate checkout of `5627e91` with the local, uncommitted data linked in;
   arm `heldout_v2`, `eval/results/heldout_v2_60.jsonl`.
Run 1 first, then run 2. **Nobody reads either run's rows or scores until both are finished**
(progress lines only). Both must be CITABLE.
**Primary — Phase 2's exit test (pre-registered 2026-09-26 as "S3 against chance", revised the same
day to apply here):** S3 of run 1 against the null 0.173 — exact binomial, one-sided, alpha 0.05,
with the 95% Wilson interval (`summarise.py`). Applied once.
**Secondary — did Phase 2 improve unseen cases?** Run 2 → run 1, paired (`compare_runs.py`): S3
(exact McNemar), S1, S4, S5, cost; `compare_suggestions.py`; the diagnosis. Reported next to the
tuning-set result (baseline v2 → shared run: S3 6 → 22 of 50) — descriptive, no test of the
difference.
**Failures, decided now:** in run 1 a cut answer is a scored model failure (Change 24); an
infrastructure failure stops and resumes the run. Baseline v2's code predates Change 24: an
unbounded answer runs to the call's timeout and its harness stops at that case. **If run 2 stops on
the same case three times, that case is removed from run 2 by a documented manual step, reported as
a baseline failure, and left out of the paired comparison (both arms).** The primary test on run 1
is unaffected.

### Baseline v2's checkout, prepared (no run yet)
`git worktree add --detach ../SigmaAssistant-baseline-v2 5627e91` (outside the repository;
`git worktree remove` undoes it). Linked in, read-only use: `.env`, `data/chroma_db`, `data/sigma`,
`eval/snapshots`. Its harness gets the inputs by absolute path from this repository —
`eval/manifest_heldout.jsonl`, `eval/github_manifest.jsonl`, `eval/contamination.jsonl`; the latter
two (and `eval/manifest.jsonl`) are unchanged since `5627e91`, so **both arms get identical inputs;
only the code differs**. Checks: its own suite, **203 passed** — the count baseline v2's preflight
reported, an independent confirmation that this is baseline v2's code; both harnesses' dry runs
load the same 60 cases (2 flagged as contaminated, reported apart as usual).

---

## 2026-09-27 — Held-out run 2 stopped on one case; the pre-registered rule applied

The overnight chain (one background command, kept awake with `caffeinate`): **run 1 (final
pipeline) finished 60 of 60** (preflight passed 22:40; 156.8 min; wrapper exit 0). Run 2 (baseline
v2's code, `5627e91`) passed its preflight (01:23; 203 tests; smoke CITABLE), wrote 14 rows
(01:28–02:28), then **stopped at case `54e57ce3` six times** — the first stop and five relaunches,
each after about 33 minutes — every time on the analysis call ("APITimeoutError: Request timed
out"); the wrapper gave up (exit 2) at 05:17. No other case failed. At 06:13 the Spark answered
(HTTP 200) and the VPN was up: an infrastructure cause is not indicated; an unbounded answer on
code without Change 24's output limit is (the case that plan anticipated).
**Rule fixed before the run** (entry "Phase 2 frozen…"): a case run 2 stops on three times is
removed from run 2 by a documented manual step, reported as a baseline failure, and left out of the
paired comparison (both arms). Applied: `eval/manifest_heldout_without_54e57ce3.jsonl` = the
held-out list minus that line (59 cases; written by a one-off script with assertions, committed
before the resume). Run 2 resumes on it — same output file, so its 14 rows are kept. No row or score
of either run has been read. The primary test on run 1 (all 60) is unaffected.

### Run 2 resumed; a second case stopped three times — the rule applied as written (decided before any score was read)
The resume (preflight passed 06:14; resumed 06:19) ran 44 of its 45 cases normally. The last,
**`af688c76`**, stopped on the analysis call (timeout) at its first attempt and at relaunches 1 and 2
— **three stops** (the watcher that was to trigger the manual step fired at 10:11) — then **finished
at relaunch 3**, before the manual step was taken (wrapper exit 0; run 2 = 59 rows).
**Decision, made before reading any row or score of either run:** the pre-registered rule says a
case that stops three times is removed and left out of the paired comparison; `af688c76` stopped
three times, so **it is excluded, like `54e57ce3`**. Keeping it because a row happened to appear on
the fourth attempt would be deciding after the fact. For transparency the paired comparison is also
reported **with** it, labelled as a sensitivity check.
Files: `eval/results/heldout_v2_60.jsonl` — all 59 rows as written (kept unchanged);
`eval/results/heldout_v2_rule.jsonl` — the same minus `af688c76` (58 rows; written by a one-off
script with assertions: 59 unique held-out ids, `54e57ce3` absent). The paired comparison uses the
latter; the primary test on run 1 uses all 60 rows.

---

## 2026-09-27 — Held-out confirmation measured (plan 2.9): Phase 2's exit criterion is met on unseen cases

Run 1 — `eval/results/heldout_final60.jsonl` (final pipeline, frozen `a6e9157`; arm `heldout_final`;
60 rows; 156.8 min; **CITABLE**; 2 answers cut at the limit, in 2 cases, scored as usual). Run 2 —
`eval/results/heldout_v2_60.jsonl` (baseline v2's code `5627e91`; arm `heldout_v2`; 59 rows;
**CITABLE**), paired through `eval/results/heldout_v2_rule.jsonl` (58 rows, rule applied). Analysed in
the pre-registered order, after both runs had finished and the exclusion had been decided.

### Primary — the exit test (applied once, as pre-registered)
**S3 of the final pipeline on the held-out cases: 25 / 55 = 0.455, 95% Wilson [0.330, 0.585];
one-sided exact binomial against 0.173: p = 1.2 × 10⁻⁶** (`summarise.py`; p < 0.05 needed ≥ 15/55).
Clean cases (no detection rule in the input): 25/54. **Phase 2's exit criterion — S3 significantly
above the null baseline — is met, on cases no Phase 2 change was designed on.**

### Secondary — did Phase 2 improve unseen cases? (baseline v2's code → final pipeline, paired)
| Metric (`compare_runs.py`, rule applied) | n | Baseline v2 code | Final pipeline | Test |
|---|---|---|---|---|
| **S3 exact** | 50 | **10** | **21** | **14 gained, 3 lost; exact McNemar p = 0.013** |
| S1 valid first rule | 58 | 54 | 53 | p = 1.0 |
| S4 ATT&CK F1 | 38 | 0.208 | 0.207 | −0.001, 95% CI [−0.044, +0.039] |
| S5 detection F1 | 50 | 0.332 | 0.339 | +0.007, 95% CI [−0.057, +0.078] |
| Tokens / seconds / rules per case | 58 | — | — | no difference (CIs span zero) |
**Sensitivity (the excluded `af688c76` included):** S3 11 → 22 of 51, 14 gained, 3 lost, p = 0.013 —
the conclusion does not depend on the exclusion. Both excluded cases (`54e57ce3`, `af688c76`) were
**S3-correct in the final pipeline** (`54e57ce3` after one answer cut at the limit and retried —
Change 24 at work), so excluding them makes the paired comparison conservative.
Unpaired: baseline v2's code 12/55 = 0.218 (95% Wilson [0.129, 0.344], p = 0.234 against chance —
not distinguishable from chance, as on the tuning cases).

### Next to the tuning set (descriptive; no test of the difference)
| | Baseline v2 code | Final pipeline | Paired change |
|---|---|---|---|
| Tuning cases (60, seed 0) | 7/57 = 0.123 | 22/52 = 0.423 | 6 → 22 of 50 (+18 / −2) |
| **Held-out cases (60, never run)** | **12/55 = 0.218** | **25/55 = 0.455** | **10 → 21 of 50 (+14 / −3)** |
The gain holds on unseen cases: smaller in net cases (+11 against +16) because baseline v2 scores
higher on these cases, while the final pipeline's level is the same or higher (0.455 against 0.423).

### The mechanism, on the held-out cases (`diagnose_logsource.py`, `compare_suggestions.py`)
First rule = the analysis stage's top suggestion **48 / 55**; S3 = the suggestion's own ceiling
(25/55 each); first rules adding a product or service the suggestion lacks: 1 of 50. The
suggestion matches the gold log source in 23 of 58 rows — web gold **12 of 15**, other categories
11 of 37, service-based 0 of 6. (Baseline v2's suggestions score 0 by construction: they carried
`service: sysmon`, which Change 25 removed.) Product field right 45/55.

### Reading
- **The claim stands on unseen cases:** the final pipeline writes the human rule's log source in 45%
  of first rules, far above chance and about twice baseline v2's rate on the same cases (paired
  p = 0.013). Measured exactly as planned: list drawn by committed code before any run, analysis
  plan and exclusion rule fixed in advance, no output read before both runs finished.
- **S4 and S5 did not change** (held-out: −0.001 and +0.007). Phase 2 fixed where the rule looks,
  not what it looks for — the next phase's question.
- What limits S3 now is the analysis stage's suggestion — right for web attacks (12/15) far more
  often than for host categories (11/37), and never for service-based sources (0/6).

---

## 2026-09-27 — Interface: a visual polish before the live demo (user); no pipeline behaviour changed

User: the interface "looks way too basic with the emojis … too much that it was made by AI"; chose a
visual-only pass before the demo (2026-09-28), in one commit that can be reverted at once.
- **Look** (`frontend/style.css`, rewritten; every selector the script uses kept): own sober palette
  instead of GitHub's dark theme verbatim, one teal accent for the main action and focus, flat
  surfaces (no radial gradients), IBM Plex Sans/Mono instead of Inter/JetBrains Mono, smaller radii,
  quiet secondary buttons (the green Save/Download on every rule), a segmented Workspace/Library
  switch, spinner/tick progress steps, thin scrollbars; the context hint hides once a run fills it.
- **Emojis removed** — 13 in the interface (title, tabs, Generate, Save/Download/Delete, Translate,
  paperclip, side-section headers, session delete) → text labels, a Σ mark, two line icons.
- **Wording** — welcome and new-analysis greeting (`backend/main.py`, web layer), input placeholder,
  button labels ("Generate rules", "+ New analysis").
- **Backend display string** — `orchestrator.py`: the "Coverage gaps detected" heading loses its ⚠️.
  Response text only; the rules and every scored field are untouched. **The evaluated pipeline
  remains `a6e9157`.**
- Asset links versioned (`style.css?v=…`) so browsers load the new files.
Script changes are text only (the delete icon, section headers). Tests 432 passed. Verified in the
browser: no console errors; chat, library, and a **live run** through the new interface. That live
run of the sudo case (CVE-2019-14287) suggested `process_creation / windows` and PowerShell and ended
with a rule on `\sudo.exe`, where an API run of the same URL earlier the same day gave correct Linux
rules — run-to-run variation of the model (generation samples at 0.3), noted in the demo runbook.

---

## 2026-09-27 — Interface: a read-only Analysis panel — what the model understood, evidence first (user)

User: the context box "is way too small … difficult for the analyst to understand how the LLM thought".
Chosen: a read-only panel today (before the demo), confirm/correct controls later (Phase 3).
**What was wrong:** a small box under the chat list; long lists first (38 indicator chips in the
SharePoint run) and raw retrieved documents; **the attack vector — the core of the model's
understanding — was not shown at all**, although the page already received it; and no basis for any
claim, although the pipeline records one (`derived_from` for each pattern, `context` for each
indicator, `reasoning`/`relevance` for log sources and techniques).
**What changed** (frontend; one function rewritten, `renderContext`, same name and callers):
- The Workspace is two columns: the conversation and a 400 px **Analysis** panel on the right (330 px
  under 1,180 px wide, hidden under 900 px); the old sidebar box is gone.
- Sections in the pipeline's order: **attack vector** (how it starts, entry point, attacker input,
  type, where it would be seen, kill chain, each pattern with where it appears and the model's basis,
  the model's note); **excluded from rules** (researcher-only strings and why); **log source** (the
  recommended one highlighted, with reasoning and fields); **ATT&CK** (tactic, relevance, IDs removed
  by Change 31); **indicators** by type with their basis; **exploit code**; **checks** (coverage gaps,
  pySigma — opened when there is a gap); **changes made in review**; **retrieved references**. Long
  sections start collapsed.
- **The basis lines are labelled as the model's words, not quotes**: many are paraphrases (e.g. the
  basis for `/_layouts/15/ToolPane.aspx` is "SharePoint URL path accessed during exploitation
  attempt"), and model self-explanations are not a faithful record (CH6 §6.4.4: 0 of 12 departures
  explained). The panel header asks the analyst to check each item against the report.
- Built from text nodes only (no model output is interpreted as HTML). A rule-row overflow bug
  (Save/Download pushed out on narrow widths) fixed.
Verified in the browser at 800 px and 1,440×900: a saved chat (SharePoint) fills every section, a new
analysis clears the panel, a **live run** (sudo CVE-2019-14287) fills it on completion; no console errors;
tests 432 passed. That live run again recommended `process_creation / windows` for the Linux sudo bug
(2 of 3 live runs today) — now visible at a glance in the panel; the demo runbook uses it as the
verification example.

---

## 2026-09-27 — Change 34: the analyst confirms or corrects what the model understood, before any rule is written (user)

User: "lets work on the confirm/correct buttons". First slice chosen by the user: **the log source +
rejecting items** (confirm or change the log source; confirm/reject techniques, indicators and attack
patterns; restore an excluded string; a note). Built on branch `analyst-review` so `main` stays what
the demo runbook describes. Starts plan Phase 3/4 before the professor's sign-off (Phase 0) — the
user's decision, logged in the plan.
**Why it could not simply be wired up** (design §2): the old `feedback_data` was applied at the start
of a *new* run, which re-analyses — the analyst would correct facts the rules are then not written
from. The run now **stops after the analysis and keeps its state**.
**What was built** (tests first, each seen to fail):
- `backend/pipeline/analyst_review.py` — `apply_review(saved analysis, review, SigmaHQ table)`, pure:
  rejected techniques/indicators/patterns are removed before generation; a restored excluded string
  becomes a pattern; a chosen log source is validated against SigmaHQ's table (`on_table`, Change 28),
  put first and marked `user_confirmed` with `confirmed_logsource`; the note goes to the existing
  "User Instructions" slot; the review is recorded (`analyst_review`). Invalid reviews (unknown
  position, status or field; a log source not in SigmaHQ's rules) raise before anything changes.
  Confirming a technique, indicator or pattern is **recorded only** — it changes nothing the rule
  writer receives (said so in the panel). `logsource_choices(table)`: the 125 log sources.
- `sigma_logsource.first_rule_logsource_block`: an analyst-chosen log source is given as YAML +
  "Confirmed by the analyst: use it for the first rule" (the old string form kept).
- `orchestrator.py`: `run_stream` split into `_analysis_events` + `_generation_events` (code moved,
  not changed; two tests pin its exact event sequence, written against the old code and passing
  before and after); `analyse_for_review` (analysis, then a `checkpoint` event with the JSON state to
  save, the panel's data and references); `generate_after_review` (applies the review, raises before
  any stage runs if it is invalid, then generation from the saved state — **no second analysis**);
  `analysis_state` (JSON, without the conversation); `_pipeline_metadata` / `_references` factored
  out of `_format_output` (same keys; `analyst_review` added only when present). **`run_sync`, which
  the harness calls, is not touched** (design P5): no measured number can move.
- `backend/review_sessions.py` — the analysis waits in the session record (design decision 2):
  `awaiting_review → generating → generated` (back to awaiting on failure or restart); generated from
  once; the browser never receives the saved state.
- `main.py`: `/analyze_stream` with `review: true` stops at the checkpoint; `POST /generate_stream`
  (400 invalid review, 404 unknown, 409 already generated); `GET /logsource_choices`; the page is
  served `no-cache` (the browser pane showed a stale pre-redesign page twice). Greeting and the input
  button ("Analyse") say the run stops for the analyst.
- Frontend: Confirm/Reject on each pattern, technique and indicator (by its position in the saved
  list — the panel groups indicators by type); Restore on excluded strings; "Use this" on each
  suggested log source (disabled, with the reason, if it is not in SigmaHQ's rules) and a list of all
  125; a note; a bar with the running summary and **Generate rules**. After generation a **"Your
  review"** section heads the panel. A pending review survives a page reload. The SSE reader now
  handles events split across network chunks. The informational preview is removed.
Tests: 482 passed (+50).
**Live test (sudo CVE-2019-14287, two runs, anecdotal — not a measurement):** both analyses again
recommended Windows (`process_creation / windows` 95%, `file_event / windows` 85%) — 4 of 5 live runs
today. Run 1: the analyst chose `process_creation / linux` (not among the model's suggestions),
rejected T1548.004 (a macOS technique), T1059.001 (PowerShell), T1562.001 and the bare pattern
`sudo`; the rule came out `process_creation / linux`, tagged only the confirmed T1068 and T1059.004.
Run 2 (after a mid-review reload, which restored the analysis): Linux chosen, the pattern `root`
rejected → 3 rules, all `process_creation / linux`, no coverage warnings. 400/404/409 checked; the
saved demo chats still open read-only.
**A design mistake found live and fixed:** a rejected pattern first joined the excluded strings. The
coverage check then flagged every sudo rule as using a "researcher artifact" (`sudo` is a substring of
every real pattern). Rejecting means "not given to the rule writer", as for techniques and indicators;
the test was changed first.
**Found, not fixed (Inbox):**
- **Defect 20 — the web app's coverage retry never runs.** `_should_regenerate_for_coverage` marks
  `coverage_retried` as a side effect; the stream calls it once to word the progress line, so the real
  check always sees "already retried" — while the line says "regenerating with feedback…". Present in
  `run_stream` since the retry was added; `run_sync` (the harness) calls it once, so **no evaluation
  number is affected**. The demo runbook's "one retry if not" is wrong for the web app.
- The review stage returned 1 rule for 3 generated in run 1 ("Merged duplicate rules into a single
  comprehensive rule") — the known "review rewrites the rules" behaviour, now seen dropping rules.
- The old `feedback_data` path (`_apply_user_feedback`) is unused by any client; the panel is hidden
  under 900 px wide, so no review there; P4's check (a rule that violates the analyst's log source →
  one rewrite) is not built yet.

---

## 2026-09-27 — Defect 20 fixed: the web app's coverage retry runs again (user)

User: "fix defect 20". Branch `analyst-review`.
**Cause** (entry above): `_should_regenerate_for_coverage` sets `coverage_retried` when it answers yes;
the stream asked it once to word the progress line, so the real check always answered no.
**Fix** (`orchestrator._generation_events`): the decision is taken once — `not generation_retried and
_should_regenerate_for_coverage(...)`, exactly `run_sync`'s expression — and both the progress line and
the retry use it. So the line also stops saying "regenerating" after a validation retry has already used
the request's one regeneration (it said so before, too).
**Tests first** (5 failed before the fix, as defect 20 predicts): the stream regenerates once when the
first rules miss the attack vector; `generate_after_review` does too; the line says "regenerating" only
when it does; and **the stream makes exactly the stage calls `run_sync` makes** in five scenarios
(valid/invalid first review × rules covering from the first, second or no generation). The fake review
stage now passes generation's rules through (before, it always returned a covering rule, so no test could
see a gap). Tests: 490 passed. `run_sync` untouched: **the evaluated pipeline always retried; the web app
now matches it.**
**Live (SharePoint ToolShell, through the analyst review):** analysis 113 s; review — `webserver` confirmed
(the model's first suggestion), the pattern `ysoserial.exe` rejected, T1566.002 and T1204.002 rejected,
T1190 confirmed. First generation: 5 rules, **4/7 patterns missed** → the progress line said
"regenerating", and the server log shows a **second generation** → **1/7 missed**. 134 s from Generate to
the rules. Four rules `webserver`, one `process_creation / windows` (the ASPX file creation); tags carry
T1190 and none of the rejected techniques.
**Seen, for the Inbox:** `ysoserial.exe` still appears in one rule — in its `description` only ("use of
ysoserial.exe to generate ViewState payloads"), which is correct context; the detection matches
`__VIEWSTATEGENERATOR` on the server. The same value was also an indicator and a PoC behaviour, which the
analyst did not reject: rejecting a pattern does not reject the same string elsewhere. A check of the
analyst's rejections (design P4) should look at detection values, not the whole rule text.

---

## 2026-09-27 — Change 35: one decision per string, and the rules checked against the analyst's review (design P4) (user)

User: "go ahead with option 1 and then the P4 check". Branch `analyst-review`.
**Option 1 — one decision per string.** The model often lists the same string as an attack pattern
and as an indicator; both reach the rule writer. Live on SharePoint, `ysoserial.exe` was rejected as a
pattern and still reached it as an indicator. Now rejecting a pattern or an indicator also rejects its
copies in both lists (`apply_review`): matched **exactly**, case and spacing aside — never "contains",
so rejecting the bare pattern `sudo` leaves the indicator `sudo -u#-1 id`. Copies are recorded as
`linked`; confirming a copy of a rejected string is refused (a contradiction). The panel crosses the
copy out ("rejected with its copy in the other list") and disables its buttons; the bar counts copies.
Tests first (5 failed).
**P4 — the rules checked against the review.** `review_departures(rules, context)` (pure; YAML parsed,
a rule that does not parse is left to validation): the **first** rule's log source against the
analyst's choice (the prompt asks for it on the first rule; later rules may observe other stages —
SharePoint's ASPX file); every rule's **ATT&CK tags** against the rejected techniques (a parent of a
rejected sub-technique is not a departure); every rule's **detection values** against the rejected
strings and their copies (exact, without `*` wildcards or a leading path separator — `\ysoserial.exe`
detects on ysoserial.exe; a description naming the string is not a departure). In
`_generation_events`, after the coverage step: departures → **one rewrite** with the reason in a new
prompt slot ("What departs from the analyst's review … final"), apart from the one regeneration for
errors/gaps; what remains is recorded (`analyst_check`), shown in "Your review", listed under the
rules, and never edited by code. A review that asks nothing of the rules adds no step. `run_sync`
untouched (it never has a review). Tests first.
**First live test (sudo, analyst chose `linux / auditd`, rejected the bare `sudo` and T1548.004,
T1059.001, T1562.001) showed two problems, both fixed with tests first:**
1. **The rewrite's answer could not be read** (`Invalid \escape` — defect 5) and gave **0 rules**; the
   check then said the rules "follow your review after one rewrite" (true of no rules) and the three
   earlier rules were lost. Now a rewrite that gives no rules **puts back the rules before it** and says
   so ("The rewrite gave no rules; the earlier rules are kept"), with the departures still listed.
2. **Rules 2 and 3 were flagged for detecting on `sudo`** — almost certainly `Image|endswith: '/sudo'`
   AND the `-u#-1` argument, which is right. Rejecting the bare pattern meant "not on its own"; for
   `ysoserial.exe` rejecting means "never". Code cannot tell which, so **only the unambiguous
   decisions get the rewrite** (`ENFORCED_DEPARTURES`: the log source and rejected techniques); a
   rejected string used in a detection is **shown, not rewritten** ("Rejected strings used in
   detection … check whether each rule depends on it"). A departure from what was described to the
   user before building ("detection values … one rewrite"), for the reason above.
The first departure of that run was real: the first rule was `process_creation / linux / auditd`
where the analyst chose `linux / auditd` (Sigma's service form has no category).
Tests: 521 passed (+31). **Live retest of the fixed code: pending** — the VPN dropped (Spark
unreachable) after the fixes.

---

## 2026-09-27 — Change 35 live retest, after the VPN came back (user: "run the retest")

Both cases through the web app on `5294a99` (anecdotes, not measurements).
**Sudo (CVE-2019-14287)** — the analysis was identical to the failing run (Windows again, 7 of 8 live
runs today); the same review: `linux / auditd` chosen, the bare pattern `sudo` rejected (its indicator
copy crossed out with it — "1 copy rejected with them"), T1548.004, T1059.001, T1562.001 rejected.
Generation 3 rules → coverage regeneration (3 gaps → 1) → the check found **1 enforced departure**
(first rule `process_creation / linux / auditd` against the analyst's `linux / auditd`) → **one
rewrite, which produced 3 rules this time** → the model **kept the extra `category: process_creation`**
on all three. Shown plainly: "Still departing after one rewrite. The rules were not edited — check
them before use", and listed under the rules. The rules detect on the `-u#-1` / `-u#4294967295`
arguments; no rule detected on the bare `sudo`, so nothing was flagged; no rejected technique in any
tag. 146 s. The first fix (no rules → keep the earlier rules) was not exercised: the rewrite parsed.
**SharePoint (ToolShell)** — analysis 111 s; `ysoserial.exe` was pattern 3 and indicator 35: rejecting
the pattern crossed out the indicator (buttons disabled). Weak techniques this run (T1036.012
"Browser Fingerprint", T1216, T1185, T1189 drive-by, T1566.002) rejected; `webserver` confirmed; **T1190
was not proposed at all** (the review can reject but not add). Generation 5 rules → coverage
regeneration (2 gaps → 1/7) → check: **"the log source and techniques follow your review"** — no
rewrite. First rule `webserver`; no rejected technique tagged; **`ysoserial` appears nowhere in the
rules**, description included. 164 s.
**Observed:** a model that keeps a non-standard log-source form after one explicit rewrite (sudo) — the
check's value is that the analyst sees it; code does not force it. Adding a technique the model missed
(T1190) is outside this slice ("editing values", not built).

---

## 2026-09-27 — The simulated-analyst run built (plan 5.3), and a Change 34 regression it found (user)

User, leaving for a few hours: no A/A run on its own; "keep working on the other changes on the order"
— the order: 5.3 first, then defect 5 (plan Decisions log). Measurement plan for 5.3 written into
`ACTION_PLAN.md` before any run, as a proposal for the user to approve.
**Cases changed before any run:** first written as the 60 held-out cases, then the **60 tuning cases**
(seed 0) — reading oracle-run failures on held-out cases would spoil them for the next confirmation.
On the tuning cases arm U against `p2g_shared60` (same code `a6e9157`) is the A/A noise floor.
**Built** (tests first, each seen to fail):
- `eval/run_eval.py --oracle-logsource`: `run_oracle_case` — the analysis once
  (`analyse_for_review`), then generation twice from its state: arm **U** with no review, arm **O**
  with the gold log source as the analyst's choice (`oracle_review`: in Sigma's form, only when
  SigmaHQ's table has it — the check a real analyst's choice passes; nothing else from the gold rule).
  Each arm scored against the gold rule and costed as the analysis plus its own generation; rows
  labelled `<arm>_unreviewed` / `<arm>_oracle`; the oracle row keeps `oracle_review`,
  `analyst_review`, `analyst_check`. `run_oracle_cases` writes both rows or neither (the stop rule).
  `load_done` shared by both modes. `run_case` split into `_base_row` / `_record_result` /
  `_record_error` without change (its tests pass unchanged).
- `backend/telemetry.summarise_calls(calls)`: the summary of any list of calls; `summary()` uses it.
- Dry run (committed code): **58 of the 60 tuning cases** have a gold log source in SigmaHQ's table
  (57 of 60 held-out).
**Smoke run, 1 tuning case (a4a899e8, webserver; scratch output, not cited):** wiring right — one
analysis, two arms, per-arm cost, the check recorded. **It found a regression from Change 34:** the
analyst's `webserver` was given to the rule writer as YAML **without Change 29's note** ("no
`product` and no `service`: leave them out"), which the model's own suggestion carries; the rule
writer wrote `product: webserver`, the check rewrote once, the model kept it — S3 wrong *with* the
right answer. Fixed: the analyst's choice gets the same note (test first). Rerun of the same case:
first rule `category: webserver` only, no departure, S3 right in both arms, 3.3 min. Also: the
unreviewed arm's S5 on that case was 0.0 in the first smoke and 0.667 in the second — sampling at
generation's 0.3, the reason for the paired design and the noise floor. A closing-message crash for
output outside the repo fixed. Tests: 535 passed. **The 60-case run has not started** — the plan
awaits the user.

---

## 2026-09-27 — Change 36 (defect 5): the rule writer answers in YAML blocks, not JSON strings — built, not measured (user)

The next change in the user's order. Branch **`defect5-yaml-rules`** (off `analyst-review` at
`c3f3e76`), so the simulated-analyst run (5.3) stays on the frozen pipeline. Measurement plan in
`ACTION_PLAN.md` ("Next pipeline change"), written before building, awaiting the user's approval.
**Why:** each rule travelled inside a JSON string, so every backslash was escaped twice, and one bad
escape (`Invalid \escape`, a Windows path) lost every rule of the answer. **Generation only** — one
change at a time; a failed review already falls back to the rules as they were.
**What changed** (tests first, each seen to fail):
- `prompts.RULE_GENERATION`: an "Output Format" section — each rule under "### Rule N: <what it
  detects and why>" as a ```yaml block written as in a Sigma file (a backslash once), optional
  "### Notes", no JSON; the worked example in that format with **the same content** (hyphenated
  tags and the `<new UUID>` placeholder kept — Changes 30/33, their tests unchanged but for reading
  the new format); the unused `target_ttp` dropped. The source writes `\\` so the prompt text has
  one backslash (compiles with warnings as errors).
- `stage_generate.parse_rule_blocks(text)`: rules = the ```yaml/```yml blocks, each explained by the
  last "### Rule N" heading before it; notes after "### Notes"; `parse_error` when no block has a
  rule. The stage calls the model with `json_mode=False`, and records every call's `parse_error` in
  `generation_log` (so failures a retry hides become countable); an unreadable answer still gives
  "Generation error: …" in the notes, as before.
- `eval/count_generation_failures.py` (the plan's primary measure): cases with no rule whose kept
  response carries "Generation error" — computable for old and new runs — and, from Change 36 on,
  unreadable generation calls. On the reference `p2g_shared60`: **3 cases** (`c5a178bf`,
  `b014ea07`, `ec3a3c2f` — the three the 2026-09-26 entry named by hand), 99 generation calls
  (unreadable calls not recorded then). `p2f_product60`: 0 cases, 94 calls.
Tests: 550 passed. **Smoke, the preflight's 2 cases (scratch output, not cited):** the model used the
new format in all 4 generation calls (0 unreadable); both first rules valid. Those rules had no
backslashes, so the smoke shows format compliance, not the escape fix — that is the 60-case run's.
**Seen:** the PoC stage's own JSON failed once in the smoke (`Expecting ',' delimiter`) — the same
family, another stage (Inbox).

---

## 2026-09-27 — The simulated-analyst run (5.3) and the Change 36 run, started (user: "run them")

The user approved both measurement plans ("push it and run them"). **Never two runs from one
checkout:** each runs from its own detached worktree at its commit — `../SigmaAssistant-run-oracle`
at `c3f3e76` (5.3) and `../SigmaAssistant-run-c36` at `c605223` (Change 36, branch
`defect5-yaml-rules`) — with `.env`, `data/chroma_db`, `data/sigma`, `eval/snapshots` linked from this
repository (read-only use); results written into this repository's `eval/results/`. (A first
attempt at the two worktrees named them wrongly — a zsh loop did not split its arguments — and put
both at `c3f3e76`; both were removed, symlinks unlinked first, before any run; the linked data was
checked intact: 379 snapshots.) Both harnesses' dry runs select **the same 60 cases as
`p2g_shared60`** (checked by id; 5 flagged as contaminated, reported apart); 58 are choosable for
the oracle arm.
One chained background command, kept awake with `caffeinate`: preflight in the oracle worktree
(**passed 16:26**: tunnel, model, context 262,144, smoke CITABLE) → run 1
`run_resilient.py -- --sample 60 --seed 0 --no-web-enrich --oracle-logsource --arm oracle_ls --out
eval/results/oracle_ls60.jsonl` → preflight in the Change 36 worktree → run 2 `… --arm c36_yaml --out
eval/results/c36_yaml60.jsonl`. A watcher reports run 1's end or 40 min without a new row.

---

## 2026-09-27 — The simulated-analyst run (plan 5.3): results

Run 1 of the chain: **60 / 60, 58 oracle rows, 0 failed, 265.4 min** (16:26–20:52); wrapper exit 0.
`eval/results/oracle_ls60_unreviewed.jsonl` and `…_oracle.jsonl`, both **CITABLE** (`summarise.py`:
every gate passed). Read as pre-registered, with committed code only (`compare_runs.py` U → O).
**Primary — S5 detection-field F1, paired within case: 0.388 → 0.531, +0.144, 95% CI [0.056,
0.241], n = 53** (13 higher, 6 lower, 34 the same). With the right log source as the analyst's
choice, the rules use more of the right detection fields.
**Reported, not tested:** S3 in O = adherence: 25 → 44 of 53 (19 gained, 0 lost; by construction
mostly). S1 55 vs 54 of 58 (p = 1.000). S4 −0.007 (CI [−0.068, 0.052]). Tokens +4,330 (CI [−484,
9,317]); seconds +2.8 (CI [−13.1, 16.5]); rules per case −0.07.
**Adherence** (new committed counter `eval/count_review_checks.py`, the plan's "rewrites and
remaining departures"; tests first): 58 checked; **followed first time 46**; 12 departed (all on the
log source) → one rewrite each → **followed after it 3**; **still departing 9** (shown; rules not
edited), of which **4 use the analyst's log source in a later rule** (post-hoc count added to the
counter, test first) and **1 rewrite gave no rules** (`881834a4`; the earlier rules were kept — the
Change 35 fix, exercised). Overall 49 / 58 follow the analyst. Read post-hoc: the 9 are form mixing
(3 — a service-form choice, `windows/security` or `firewall`, given a category, as in the live sudo
`linux/auditd` case) and stage order (6 — the gold is a later stage; the model keeps the
initial-access rule first, generation instruction 2).
**Where the S5 gain comes from** (post-hoc, `eval/s5_by_logsource.py`, `compare_runs.metric_value`
pairing): **all from the 19 cases whose log source became right**, S5 0.132 → 0.521 (+0.389); right
in both (25) 0.722 → 0.711; wrong in both (9) 0.000 → 0.056; became wrong 0. The log source gates
the fields. (This script and its test were written together; the test was run with the script
moved away first and seen to fail — weaker than test first, noted.)
**Noise floor — the by-product** (`compare_runs.py p2g_shared60 → U`: code `a6e9157` both, same 60
cases): S3 22 vs 24 of 51 (**6 discordant**, 2/4, p = 0.688); S1 52 vs 57 (1/6, p = 0.125 — the
reference lost 3 cases to defect 5); **S5 +0.086, CI [−0.007, 0.187]** (11/5/34); S4 +0.046 (CI
[−0.039, 0.141]); tokens +1,358 (CI crosses 0); **seconds +23.8 (CI [0.0, 60.2])** — the Spark is
shared. So: ~1 case in 8 flips S3 between identical runs, and S5 swings of ~0.09 are within noise.
Chapter notes: CH6 §6.0b; CH7 49 (upper bound), 50 (noise); CH5 5.8.
**Inbox:** the one rewrite fixes 3 of 12 departures; service-form choices get a category added
(the first-rule block already carries "no `category`"); stage order — the first rule is the
initial-access rule even when the analyst's log source is a later stage.
Run 2 (Change 36) started 20:57 after its preflight passed.

---

## 2026-09-28 — Change 36 (defect 5) measured: no answer lost to the format; no harm detected

Run 2 of the chain, worktree `../SigmaAssistant-run-c36` at `c605223`: **60 / 60, 0 failed, 171.1
min** (20:57–23:48), wrapper exit 0; `eval/results/c36_yaml60.jsonl`, **CITABLE**. Read as
pre-registered against `p2g_shared60` (code `a6e9157`, the same 60 cases).
**Primary** (`eval/count_generation_failures.py`, committed before the run):
- **Cases with no rule because generation's answer could not be read: 3 → 0.** Context — the old
  JSON format loses 0 to 3 such cases per run on these cases: `p2f_product60` 0, tonight's unreviewed
  arm (same frozen code) 1 (`71c432c4`), `p2g_shared60` 3. So 3 → 0 is not by itself a significant
  difference; the reference run was an unlucky one.
- **Unreadable generation answers: 0 of 91 calls** (recorded from this change on). `[READ]` The run
  logs (local) have 8 "Generation failed" lines in tonight's old-format run (both arms) and **0** in
  this one.
- **S1 52 → 57 of 60** (1 only A, 6 only B; exact McNemar p = 0.125) — the same pattern as the noise
  floor measured tonight (U against the same reference: 52 vs 57, 1/6), so **not attributable**.
**Watched for harm, paired:** S3 22 → 24 of 51 (2/4, p = 0.688); S4 +0.013 (95% CI [−0.040, 0.071]);
S5 +0.059 (CI [−0.039, 0.155]); tokens −201 (CI [−3,636, 3,336]); seconds +17.0 (CI [−6.9, 54.3]) —
**none detectable**. **Rules per case +0.517, CI [0.117, 0.967]** — the model writes more rules in the
new format; part of it is the 3 recovered cases (`c5a178bf` 0 → 8 rules, `ec3a3c2f` 0 → 3, `b014ea07`
0 → 2 — its first rule does not parse), the rest not examined.
**Reading:** the change removes the failure mode it targeted (no unreadable answer in 91 calls, against
several per run before) without a detectable cost on any score. It cannot be shown to raise S1 on 60
cases, because the old format's losses are rare and irregular (0–3 per run). Review still returns JSON
(a failed review falls back to the rules as they were); the PoC stage's JSON failed once in the smoke
(Inbox).
**Branches:** `analyst-review` merged into `defect5-yaml-rules` first (`13bc77e`; the log's two
appended ends were the only conflict, kept both in date order; 556 tests passed after the merge).

---

## 2026-09-28 — Change 36 kept; the run worktrees removed (user)

User: "keep change 36, remove the worktrees and push it". Change 36 stays in the pipeline (branch
`defect5-yaml-rules`, which carries all of `analyst-review` too); it goes into `main` with the
review work after the demo. The worktrees `../SigmaAssistant-run-oracle` and `../SigmaAssistant-run-c36`
were removed — their data links unlinked first, then `git worktree remove`; they held only those links
and each preflight's 2-case smoke output. `.env`, `data/chroma_db`, `data/sigma` and the 379 snapshots
were checked intact afterwards; `../SigmaAssistant-baseline-v2` is kept (user, 2026-09-27).

---

## 2026-09-28 — The professor's feedback; why the same report gets a good rule one time and a wrong one the next (measured)

After the demo (user): the professor (1) wants the thesis to **understand** why "some of the Sigma
rules generated in May were good, then more were generated and they were wrong", and asked for
examples; (2) said the assistant now relies on the human, and "the point of all of this is to
automate the process and rely more on the AI" — human input matters, but automation is the goal.
**Three sources, with evidence:**
1. **The system changed between May and now** — model (Gemini hybrid → all-local qwen3-coder), and
   defects since measured and fixed. The rule library (`data/saved_rules.json`, April) shows them:
   "Access to CVE-2026-1731 Rapid7 Analysis on AttackerKB" (15 Apr) detects *visits to the report
   page* (`cs-host|contains: 'attackerkb.com'`) — defect 8, the pasted URL routed to chat and the
   page never read (57% of URLs, fixed by Change 8 on 2026-09-13); "Citrix NetScaler … NSC_TASS" (16
   Apr) puts an invented `product: citrix` / `service: netscaler` on `category: webserver` and
   looks for response cookies a web-server log does not record (Changes 25/28/29); "Follina MSDT"
   (7 Apr) is close to SigmaHQ's but has a sequential fake id (defect 10) and the underscore tag
   style (Change 33). No May result file exists (the harness came in September), so May cannot be
   rescored.
2. **Different inputs differ in difficulty** — held-out: the analysis stage's suggestion right for
   web 12/15, host categories 11/37, service-based 0/6 (log 2026-09-27).
3. **The same input, the same code, different outcomes — measured now.** New committed script
   `eval/list_disagreements.py` (tests first, each seen to fail) on `p2g_shared60` against
   `oracle_ls60_unreviewed` (the same pipeline, `a6e9157` path, the same 60 cases, frozen pages):
   **16 of 60 cases disagree** (S1 or S3 flips, or S5 apart by ≥ 0.5). Over all 60, the two runs
   concluded differently at the **attack-vector stage in 12**, the **analysis's first log-source
   suggestion in 15**, and **the first rule's log source in 19** — the difference grows down the
   chain. Of the 16, the first divergence was the attack-vector stage in 6, the analysis in 2, the
   rule writer in 8; of the 6 log-source flips, 4 began at the attack-vector stage. Example
   `ad7085ac` (Sourgum, CVE-2021-31979/33771): run A — attack vector `file_event` → suggestion
   `file_event/windows` → first rule right, **S5 1.00**; run B — `registry_event` →
   `registry_event/windows` → wrong, **S5 0.00**.
   **Temperature 0 is not deterministic here:** the PoC, attack-vector and analysis stages call the
   model at temperature 0 (checked in the code), none of their code or prompts changed between the two
   commits (`git diff a6e9157 c3f3e76` empty for them and `prompts.py`), and the pages are snapshots —
   yet the first stage concluded differently in 12 of 60. `[UNMEASURED]` Likely cause: inference
   on a shared GPU (request batching, floating-point order) breaking near-ties, amplified over
   answers thousands of tokens long; not tested yet.
**The mechanism** ties to 5.3: an early difference decides the log source, and the log source
gates the detection fields (S5 0.13 vs 0.52 when it becomes right).

---

## 2026-09-28 — The analyst review and Change 36 merged into `main` (user)

User: "go ahead with the merge", as decided before the demo. `analyst-review` (roadmap, professor's
feedback) was merged into `defect5-yaml-rules` first (`b61cad3`; the log's appended ends were the only
conflict, kept in date order; 562 tests passed), then **one live run through the review flow with
Change 36** (sudo; the analysis again recommended `process_creation / windows`; the analyst chose
`process_creation / linux`, rejected the bare `sudo` — its indicator copy went with it — and T1548.004,
T1059.001, T1562.001): 3 rules, all `process_creation / linux`, **every generation answer read (0
"Generation failed")**, explanations taken from the "### Rule N:" headings shown in the chat, the
coverage retry ran, the check reported "the log source and techniques follow your review", and rule 3's
use of the rejected `sudo` was shown, not rewritten; 76 s. Then `defect5-yaml-rules` into `main`: the one
conflict was `DEMO_RUNBOOK.md`, where `main`'s pre-demo stopgap ("the web app does not retry",
"prefer the lowest chat") met the branch's text for the code now merged — the branch's version kept,
its header note updated. 562 tests passed on `main`. The user's own comments on four prompt section
headers (uncommitted, 10:17) were set aside with `git stash` during the merge and put back afterwards.

---

## 2026-09-28 — May vs now: the prompts, the inputs and the outputs, reconstructed (professor's question)

User: "go ahead with the prompt diff and the April chats". Notes: `thesis/MAY_VS_NOW_NOTES.md`. Two new
committed scripts, tests first and each seen to fail (16 tests): `eval/prompt_history.py` (the prompts of
two git versions side by side, parsed from `git show`, never run) and `eval/old_sessions.py` (the saved
chats as runs; `--find` for strings, `--results` counts a result file the same way and lists the models
called). `data/sessions.json` is local user data, so the chat counts can be re-run on this laptop only.
**What survives:** the May code (`2ec05f6`; prompts identical to `f457855`), `7b80426` (12 April), and 20
saved answers with rules dated 20 March – 23 April. **None is dated in May** (the next is 13 September):
the rules shown in May were written by 23 April or never saved. Which model wrote each April rule, and
the prompt text between 15 April and 14 May, were not recorded.
**Findings:**
- **Prompts:** of the 8 prompts the pipeline uses now, 5 are unchanged since May; attack vector (10,776
  → 11,855 chars), analysis (4,358 → 4,280) and rule writing (6,145 → 7,100; one input added) changed.
  The large prompt change came before May (rule writing 2,449 → 6,145 chars, 8 → 17 inputs, three new
  stage prompts). The main differences are elsewhere: the rule writer (May: Gemini 2.5 Flash per the
  code's routing and the 2026-08-06 banner; now qwen3-coder:30b — every September run checked called
  only qwen3-coder:30b, e.g. baseline v1 321 of 321 calls), web search (April chats: 0–16 extra web
  sources; now off), and what fills the slots.
- **The May attack-vector prompt's worked examples were the demo reports:** Example A = Citrix
  NetScaler (`/saml/login`, `NSC_TASS`), Example B = BeyondTrust CVE-2026-1731 (`remoteVersion`,
  `BT26-02-RS.nss`, the patch password). Their strings are in 7 of the 20 April answers, all about these
  two vulnerabilities; the 15 April BeyondTrust chat holds the password before the attack-vector stage
  existed; on 22 April the model's output repeats Example B's sentence word for word (2 answers). The
  prompt was tuned on its test reports, so their rules improved without evidence for new reports. On
  September's 60 other reports these examples' text was in 10 of 60 attack-vector records (log
  2026-09-26).
- **April rules:** 56 rules, 54 complete, **7 with a log source SigmaHQ's rules use** (0 of 28 in the
  attack-vector pipeline, 16–23 April); `linux-windows`, the May analysis table's product cell, is in
  13 of the 20 answers. Same measure in September: held-out baseline v2 code 105/208 → final pipeline
  188/204 (same 60 reports); `c36_yaml60` 236/250.
- **Repeats:** BeyondTrust 5 runs → 5 different first-rule log sources (visits to the report page;
  auditd rules on the researchers' patch-diffing; then three WebSocket rules on three invented web log
  sources); SolarWinds 3 → 3; nginx-ui 4 → 3; Citrix 2 → 2; Follina 2 → 1, but the 12 April rules were
  both incomplete (condition outside `detection`) and tagged T1548.003. Not a clean variance measure:
  code and prompts changed between runs and the web search differed.
**Correction to the entry above ("The professor's feedback…"):** it called the 15 April AttackerKB rule
defect 8 (a URL routed to chat). That chat went through the pipeline and saved its stage results, so it
was not misrouted: the page's text never reached the stages, cause not recorded. CH6 §6.0c corrected.

---

## 2026-09-28 — May vs now rerun: the May code through today's harness, and the measurement plan (fixed before any run)

User: "rerun the may code on the same saved pages, several times each. Gather results". Pushed
`c0b689d` first (user).
**How the May code runs** (new, committed with this entry): `run_eval.py --code <checkout>` runs an
older version of the pipeline through today's harness. `eval/old_code_worker.py` imports the old code
in its own process (its `backend` package cannot sit next to today's); `eval/old_code.py` sends it one
case at a time with the case's saved pages and records its LLM calls here, so the row, the scorer,
resuming and stopping at a failed call are the harness's own. Every row now records which code ran
(`config.code`, `config.code_path`). Tests: `tests/test_old_code.py` (11). **Lapse:** the adapter's
first 9 tests were written before the code but not run until after it (the rule is: seen to fail
first). Checked instead by four planted bugs (calls not recorded; pages not restored; URL fragment
not stripped; a dead worker not counted as a failed call): each made a test fail; restored, all pass.
The two `run_config` tests were seen to fail first. Smoke: 2 cases (seed 7, a sample no run uses),
`2ec05f6` through the adapter, CITABLE; every stage's calls recorded, pages served from snapshots.
**What is today's in the May arm, and why (the rest is the May code unchanged — its prompts, stages,
review-and-retry loop, page extraction, no Change 9 id fix):**
- the LLM client and call recording: same model and server, with Change 24's output limit (without it
  an unbounded answer hangs the run — held-out run 2 stopped this way six times);
- the saved pages and web search off, as every run since September;
- routing: bare-URL input goes straight to rule generation, as today (Change 8); the May classifier
  sent about half of such inputs to chat (defect 8) — that failure is already measured and is left out
  so the arms compare rules;
- the retrieval index is today's (rebuilt in September, `d9d9e3f`: valid YAML examples, all
  platforms); the May index no longer exists.
**Not answered by this run:** Gemini vs qwen (the key was deleted), April's web-search results, the
May index, defect 8's routing.
**Found while preparing:** the review prompt, unchanged since May and in use today, still carries one
example taken from the Citrix report (`/metadata/samlidp/asdf`). Not changed now (no pipeline change
before or during a run); added to the plan's Inbox.

### Measurement plan (fixed before any run)
- **Cases:** the 60 held-out cases (`eval/manifest_heldout.jsonl`, no `--sample`), frozen pages,
  `--no-web-enrich`. Held-out because no version's prompts were written from them (the tuning 60 were
  used to develop `main`'s changes).
- **Arms, k = 3 runs each:** May = `2ec05f6` via `--code ../SigmaAssistant-may`, arms
  `may_heldout_r1..3`; main = the commit of this entry, arms `main_heldout_r1..3`. Files
  `eval/results/{may,main}_heldout_r{1,2,3}.jsonl`. Both arms from one frozen checkout of this commit
  (data linked in). Rounds: May r and main r run at the same time (same server load), r = 1, 2, 3, each
  under `run_resilient.py`. More rounds, if ever added, are a separate labelled addition.
- **Nobody reads rows or scores until all six runs finish** (progress lines only).
- **Primary** (`eval/compare_arms.py`, committed with this entry, 7 tests seen to fail first): per
  case, the mean over its 3 runs; main − May, paired over the cases every run of both arms has,
  bootstrap 95% CI (10,000 resamples, seed 0) of: **S3u** and **S5u**, the log source and detection-field
  F1 **as the user gets them** — a first rule that does not parse counts as wrong (0). Chosen over the
  usual convention because the May code lacks Change 9, so some of its rules will not parse (defect 10)
  and leaving them out would flatter it.
- **Consistency (primary for the professor's question):** cases whose 3 runs chose the same first-rule
  log source, per arm; exact McNemar between the arms.
- **Secondary:** S1, S3, S4, S5 (the harness's convention), rules, seconds, tokens per case; S3 right in
  every run / wrong in every run / mixed; per pair of runs of one arm, cases concluded differently at the
  attack-vector stage, the analysis, the first rule's log source; rules with a log source SigmaHQ's rules
  use (`old_sessions.py --results`, per run). The 2 contamination-flagged held-out cases are listed with
  their values (descriptive).
- **Failures:** an infrastructure failure stops and resumes. A case that stops one run three times is
  removed from that run by a documented manual step and so drops out of every comparison (the tool
  compares only cases every run has). An answer cut at the output limit is a scored failure, in both
  arms (same client).
- **Reading, fixed now:** a CI above 0 on S3u or S5u = the code and prompt changes since May make better
  rules on unseen reports with the same model; a CI containing 0 = no detectable difference from code
  and prompts, and the May-vs-now difference rests on what this run cannot test (model, web search, the
  prompts' tuning on the demo reports) and on run-to-run variance.

### The rerun started; a presentation begun; one correction
The six runs started 2026-09-29 00:04 as three rounds (May r and main r side by side, from the frozen
checkout `../SigmaAssistant-rerun` at `8f6a91c`; preflight passed: tunnel, model, 262,144-token server
context, tests, smoke CITABLE). A slide deck for the professor (user: "lets make a presentation on
this") holds the reconstruction and the rerun's design; the results slides wait for the six runs.
**Correction to `thesis/MAY_VS_NOW_NOTES.md` §1:** the May review stage checked rules with hand-written
YAML checks, not pySigma; pySigma validation arrived on 2026-08-06 (`a1c4f37`). Found while checking
the slides against the code.

---

## 2026-09-29 — May vs now rerun: results (as pre-registered)

**Runs:** six, all 60 of 60 rows, all **CITABLE**, no stop or relaunch in any (rounds 00:04–04:41,
04:41–09:50, 09:50–14:01; each run 240–309 min). Every call went to qwen3-coder:30b (`old_sessions.py
--results`). Files: `eval/results/{may,main}_heldout_r{1,2,3}.jsonl`. No row or score was read before all
six finished. Analysis: `eval/compare_arms.py --a may_heldout_r{1,2,3} --b main_heldout_r{1,2,3}`
(committed; this entry adds its listing of the flagged cases and a two-significant-figure p, 2 tests seen
to fail first — output formatting only, no measure changed). 60 cases in every run of both arms.
**Primary** (case = mean of its 3 runs; main − May, paired, bootstrap 95% CI):
| Measure | May code | main | main − May |
|---|---|---|---|
| **S3u** log source right, as the user gets it (n = 60) | 0.072 | 0.439 | **+0.367 [+0.250, +0.489]** |
| **S5u** detection-field F1, as the user gets it (n = 60) | 0.171 | 0.330 | **+0.158 [+0.096, +0.222]** |
| **Same first-rule log source in all 3 runs** (n = 60) | **18** | **43** | only May 4, only main 29; exact McNemar **p = 1.1e-05** |
**Secondary:** S1 0.711 → 0.950 (+0.239 [+0.167, +0.317]); S3 (convention) 0.104 → 0.452, n = 56; S4
0.217 → 0.224 (+0.007 [−0.065, +0.080], n = 42 — no difference); S5 (convention) 0.249 → 0.347 (+0.098
[+0.034, +0.163], n = 56); rules per case 3.13 → 3.62; seconds 275 → 279 (no difference); tokens 36,565 →
56,516 per case. S3 right in every run / wrong in every run / mixed: May 2 / 52 / 6, main 23 / 30 / 7.
Per pair of runs of one arm, cases concluded differently at the attack-vector stage / the analysis / the
first rule's log source: **May 2.0 / 9.0 / 32.3, main 3.3 / 6.0 / 13.3** (of 60). Rules with a log source
SigmaHQ's rules use: May 81/178, 80/192, 92/193; main 207/217, 202/217, 202/217. The 2 contamination-flagged
cases: S3u 0 in both arms; S5u May 0.00/0.00, main 0.00/0.11 — they do not carry the result.
**Reading, as fixed before the runs:** both primary CIs lie above 0 — **with the same model and the same
pages, today's code and prompts write better rules on unseen reports than the May code**, and far more
consistently. With qwen writing its rules, the May code is below the chance baseline on the log source
(0.072 vs the null 0.173) and 29% of its first rules do not parse (S1 0.711).
**What this does not say:** the May system's rules were written by Gemini 2.5 Flash, with web search; this
rerun gives the May code qwen for every stage, today's retrieval index and today's routing. So it measures
the code and prompts, not the May system as it ran. `[UNMEASURED]` Gemini's contribution.
**Interpretation (not a test):** in the May code the runs agree up to the analysis and part at the rule
writer (32.3 of 60 per pair); in `main` the rule writer diverges in 13.3 — consistent with Change 26 tying the
first rule to the analysis's recommendation, and with SigmaHQ's table (Changes 28–29) narrowing its choices.
**Post-hoc observation:** in `main` the attack-vector stage concluded differently in 3.3 of 60 per pair of
runs; the September A/A comparison found 12 of 60 (runs a day apart, sequential; these ran concurrently). Not
a test; P-B (the source of temperature-0 variation) would have to settle it.

---

## 2026-09-29 — P-B: is temperature 0 repeatable? The probe and its plan (fixed before any call)

User (choosing the next step): the variance probe (plan P-B). Everything else from this session is kept
(user: "I want to keep all of what we did") — both checkouts, all result files, both decks.
**Why:** two runs of identical code on identical pages concluded differently at the attack-vector stage
(temperature 0) in 12 of 60 cases (log 2026-09-28); in the May rerun, today's code did so in 3.3 of 60
per pair of runs (concurrent runs). Is the model's answer at temperature 0 repeatable, and what breaks it?
**Tool:** `eval/probe_determinism.py` (tests first, 5, seen to fail): for each case it captures the exact
attack-vector prompt (saved pages; the PoC stage run once; the stage stopped at its model call), then
sends that same prompt again and again. Every request is exactly the pipeline's (a test holds it to
`OllamaLLMClient.generate`'s), plus a seed where a condition says so. Identical prompts are sent once.
**Plan:**
- *Cases:* the 6 whose two September runs first diverged at the attack-vector stage
  (`list_disagreements.py`: 20c6ed1c, 36222790, 92389a99, ad0960eb, ad7085ac, 32b5db62; tuning cases, no
  scoring).
- *Conditions per prompt:* one at a time ×5 (as the pipeline sends it); one at a time with seed 42 ×5; 4 at
  once (no seed); 4 at once with seed 42. Output: `eval/results/determinism_probe.jsonl`.
- *Measures:* per case and condition, the number of different answers (exact text) and of different
  `primary_telemetry` labels (what the log source follows).
- *Reading, fixed now:* (a) one-at-a-time answers identical but at-once answers differ → the variation
  comes from concurrent requests (server batching); (b) one-at-a-time answers differ and the seed makes
  them identical → a seed in the client is a candidate change (one line, then measured); (c) neither →
  not fixable from the client, and the pipeline has to live with it by design (P-C, self-consistency).
- *Limits:* other users' load on the shared server is not observed (each call's time is recorded); ≤ 6
  prompts × 18 calls is descriptive, not a test.

### P-B results — the first request of a prompt answers differently; every repeat is identical
The probe ran 19:12–19:25 (no errors; `eval/results/determinism_probe.jsonl`, 96 rows). `ad0960eb` sends the
same prompt as `92389a99`, so 5 distinct prompts, 18 requests each.
**By the plan's table** every prompt gave 2 different answers in "one at a time" and 1 in every other
condition, and 1 telemetry label everywhere — which reads as case (b), "the seed makes them identical".
**That reading is wrong, and the design is why:** the conditions always ran in the same order, so the
seed conditions always came after the first request. In time order (`probe_determinism.py --report`,
added after the probe — `order_effects`, `served_in_turn`, 2 tests seen to fail first):
- **5 of 5 prompts: the first request's answer was never given again; all 17 later answers were identical**
  — with or without the seed, one at a time or sent at once. The first requests were also slower (e.g.
  14.4 s vs 6.4 s) and longer (481 vs 457 tokens).
- **10 of 10 batches sent at once were answered one after another** (times ≈ 1×, 2×, 3×, 4× a single
  request): the server queues requests; nothing was processed together, so batching was not tested and is
  not a factor on this server as configured.
- The stage's `primary_telemetry` label was the same in all 18 answers of every prompt: the first answer
  differed in wording, not in the label the log source follows (these 5 prompts).
**Design flaw, disclosed:** the order of conditions was fixed, so the seed was confounded with "not the
first request". The seed's effect is therefore unmeasured; the repeats show it is not needed for
repeatability once a prompt has been seen.
**Reading:** at temperature 0 the model is repeatable **for a prompt the server has just processed**; the
first time a prompt arrives it can answer differently. `[UNMEASURED]` Likely mechanism: the server reuses
the already-processed prompt on a repeat (prompt caching), and computing it fresh vs reusing it gives
slightly different numbers, enough to change a near-tie between words. In a pipeline run every prompt is
new, so its answer may depend on what the server processed just before — the previous case's prompt
(they share the long instruction part) or another user's request — which would explain why two runs of
identical code differ. Not tested yet.
**Next, proposed (P-B follow-up):** alternate between prompts so that every request is a first one — are
first answers repeatable among themselves, and does what came before change them? If the answer depends
only on the prompt when it is sent fresh or only when warm, a fix is possible (e.g. a warm-up request
before the real one); if it depends on what came before, the pipeline has to live with it (P-C).

### P-B follow-up: is a first-time answer repeatable, and does what came before change it? (plan fixed before any call)
User: "run the follow-up test … we are doing research so is very important for us to understand all of
this". Pushed `e137d30` first (user). `probe_determinism.py --follow-up` (tests first: 4 new, seen to fail):
the same 6 cases' attack-vector prompts, recaptured (a prompt can differ from the first probe's if the PoC
stage answers differently at capture; each prompt's hash is recorded and compared). One request at a time,
in a fixed, recorded order (`follow_up_schedule`, 95 requests): the questions in a **rotation** ×4 (each
always after the same other question); the **reversed** rotation ×2 (after a different one); each **after
an unrelated question** ×2 ("Reply with the single word OK.", no shared text); and each **asked twice in a
row** after its rotation neighbour, its reversed neighbour and the unrelated question. Each answer records
the question sent just before it. The report text starts at character 892 of this prompt: two different
questions share only the instruction before it (and the JSON system message).
**Measures, per question** (`follow_up_analysis`): first-time asks — different answers overall, and the
most different answers after one and the same preceding question; asked again right away — different
answers across the three contexts; telemetry labels; whether the asked-again answer equals the first
probe's repeats of a byte-identical prompt (`same_as_first_probe`).
**Reading, fixed now:** (i) one first-time answer per question whatever came before → first-time answers
are repeatable; the first probe's difference was first-time vs repeat only. (ii) one answer after the same
preceding question but different answers after different ones → **the answer depends on what the server
processed just before** — which would explain why two runs of identical code differ. (iii) different
first-time answers even after the same question → something else varies (other users' requests are not
observed). Separately, (iv) asked-again answers identical across all three contexts (and equal to the first
probe's) → **a warm-up request (ask twice, keep the second) would make answers repeatable** — a candidate
pipeline change, to be measured on its own; otherwise the pipeline lives with it (P-C). 5 questions:
descriptive, not a test.

### P-B follow-up results — stable for hours, not across days; asking twice gives false agreement
Ran after the plan above; 95 requests, 0 errors (`eval/results/determinism_followup.jsonl`). Prompt hashes:
3 of 5 questions byte-identical to the first probe's; **2 changed** (`ad7085ac`, `32b5db62`) because the
PoC stage — also temperature 0 — answered differently at capture. `probe_determinism.py --report
--follow-up` and `--labels` (the latter added after the run, `todays_labels`, 1 test seen to fail first):
| Question | first-time asks | different | most different after one and the same question | asked again | different | same as first probe |
|---|---|---|---|---|---|---|
| 20c6ed1c | 12 | 2 | 1 | 4 | 1 | no |
| 36222790 | 12 | 2 | 2 | 4 | 1 | no |
| 92389a99 | 12 | 2 | 2 | 4 | 1 | no |
| ad7085ac | 12 | 3 | 3 | 4 | 1 | (prompt changed) |
| 32b5db62 | 11 | 2 | 2 | 5 | 1 | (prompt changed) |
- **Asked again right away: one answer per question, whatever came before** (5 of 5).
- **First-time answers differ in wording even after one and the same preceding question** (4 of 5): what
  came just before does not explain it — reading (iii); other users' requests, queued with ours, are not
  observed.
- **The asked-again answer is not the one from a few hours earlier** (3 of 3 comparable): a warm-up request
  would not make answers repeatable over time — by the plan's reading, the pipeline has to live with it (P-C).
- **The label the log source follows: one per question over all 34 answers today** (5 of 5, both probes). But
  the two September runs, a day apart, gave **different labels for byte-identical prompts** (the no-PoC
  reports — the prompt depends only on the saved page): `20c6ed1c` other / webserver_access_log,
  `36222790` file_event / process_creation, `92389a99` process_creation / file_event; today's label is one
  of the two in each. So the wording varies from ask to ask, the label holds for hours, and **between
  sessions a day apart the label itself changed**. `[UNMEASURED]` why: the server's state over time (model
  reloads, other users' work on the same GPU), not tested.
- **Upstream too:** the PoC stage changed its answer between the two probes for 2 of 5 reports, which
  changes the attack-vector prompt itself.
**What it means.** (1) Temperature 0 does not make this server repeatable: not by a seed (no effect seen),
not by a warm-up (fails across hours); run-to-run variation is a property of the deployment the pipeline
must be designed for. (2) **For self-consistency (P-C): asking the same question again in a row returns the
same answer — agreement that means nothing.** Votes must come from independent samples (a temperature above
0, reworded prompts, or asks far apart in time), and the design must say which. (3) Every result stays a
rate over runs; a single example is one sample.

---

## 2026-09-29 — Better log-source picks (user): the diagnosis, and Change 37 (unreadable answers)

User: "lets work on better log-source picks" (roadmap R7). **Diagnosis on the 60 tuning cases only** — the
held-out cases are not looked at case by case, so they stay usable for confirmation (the May lesson).
Three recent runs of today's analysis code on them (`p2g_shared60`, `oracle_ls60_unreviewed`,
`c36_yaml60`). `compare_suggestions.py`: the analysis stage's top pick = the gold log source in 23 / 26 of 60;
by the gold's form: service-defined 0 of 5, web 6–9 of 12, other categories 17 of 43; **no pick at all in 2–4
of 60**; a pick without a category (the product + service form) **0 of 60 in every run**.
**Wrong, or just different?** New `eval/alternative_logsources.py` (tests first, 4, seen to fail; post-hoc,
descriptive): a pick that is not the gold's may match another human-written SigmaHQ rule for the same report
(a rule citing one of the case's input URLs; a URL cited by more than 5 rules links nothing). Emerging-threats
rules: 27 of 60 cases have another rule for the same report. Per run — gold 23 / 26 / 26; **another human rule
9 / 5 / 5; neither 26 / 25 / 25**; no pick 2 / 4 / 4. So about 25 of 60 picks match no human rule for the
report: the real room. Patterns among them: host reports whose gold targets a specific trace (a dropped file,
a registry key, a DNS query, a PowerShell script block, a remote thread) picked as `process_creation`; exploit
reports whose gold detects the host after the break-in picked as `webserver`; network C2 gold (proxy, DNS,
firewall) picked as host; service-defined logs (Windows Security, FortiOS, Zeek) never picked. The stage gives
confidence 0.95 on nearly every pick, right or wrong: its self-reported confidence carries no signal.
**The no-pick cases** are unreadable answers: the run logs show `[analysis] Combined analysis failed: Invalid
\escape` 6 times and the 16,384-token output limit on 3 attempts 2 times — the analysis-stage twin of defect 5
(Change 36 fixed it for generation only).
**Change 37 — repair stray backslashes, then read** (`base_stage.parse_json`, all JSON stages; tests first, 8,
seen to fail). Only after `json.loads` has failed on an escape: every backslash is doubled except `\"`, `\\`,
`\/` and a real `\uXXXX`. A first version kept `\b \f \n \r \t` as escapes; its own test showed `C:\Users\bob`
turning `\b` into a control character, so in an answer that already failed on a stray backslash those are
read as a path's backslash too. An answer that parses is untouched (by construction; a test holds it).
**Measure, fixed before any call** (`eval/probe_json_repair.py`, 3 tests seen to fail): the 60 tuning cases
(seed 0) through the pipeline's own analysis path (`analyse_for_review`: preprocessing, PoC, attack vector,
analysis; saved pages; no web search); every PoC, attack-vector and analysis answer is captured and **read twice
— with the reader before Change 37 and with today's** — so the comparison is on identical answers. Primary: per
stage, answers unreadable before vs now. Also: cases with no log-source suggestion (earlier runs: 2–4 of 60,
descriptive), and the repaired values listed for a check that they read as written. The output limit is not
this change's (2 of the 8 failures). A full run's S3 effect is expected small (≤ 4 cases per run gain a pick)
and will show in the next measured run.

### Change 37 measured — no answer needed the repair in this run
`eval/probe_json_repair.py` on the 60 tuning cases (`eval/results/json_repair_probe.jsonl`, 60 rows, no
crash). Answers read with the old reader / today's: PoC 33 answers, unreadable 0 / 0; attack vector 60, 1 / 1;
analysis 59, 0 / 0; **repaired: 0 of 152**. Cases with no log-source suggestion: 1. **The stray-backslash
failure did not occur in this run**; in the three earlier runs the run logs show it 6 times in the analysis
stage (a `grep` of the gitignored logs, not a committed tool). It comes and goes between runs, like the
answers themselves (P-B). The fix stays (it is correct by its tests and cannot change a readable answer), but
**its benefit is unmeasured here: 0 cases to repair**.
The two failures left are other kinds: `9a2d8b3e`'s analysis answer ran into the 16,384-token output limit
on all 3 attempts — the same in 2 of the 3 earlier runs (plan Inbox item 7, "shorter analysis answer");
`47a1658b`'s attack-vector answer was broken JSON of another kind (`Expecting ',' delimiter`), which the repair
rightly leaves alone.

---

## 2026-09-29 — Change 38 (v1): the analysis ranks log sources by their evidence; a second confirmation set

User: "Do it" (the plan: build and test the change, show the wording, then runs on fresh reports).
**Confirmation set 2:** `eval/manifest_confirm2.jsonl`, drawn once by `draw_heldout.py --out … --exclude
<scratch smoke files>` (new `draw()`, `--out`, `--exclude`; 1 test seen to fail first): 60 of the 182 corpus
cases in no result file (and not in the scratch-folder smoke runs), stratified, seed 0 — process_creation 25,
webserver 10, file_event 8, no category (service-defined) 7, registry_set 3, proxy 3, image_load 2, ps_script
1, registry_event 1. No overlap with the tuning or the first held-out set. Not looked at beyond the categories.
**Measure added:** `compare_arms.py --manifest` scores the analysis stage's top pick — **P** (= the gold) and
**Pany** (= the gold or another human rule for the same report, `alternative_logsources`), no pick = wrong; and
counts answers with no pick (2 tests seen to fail first). On two tuning runs it reproduces the earlier counts
(P 0.383 / 0.433 = 23 / 26 of 60).
**Change 38 v1** (`COMBINED_ANALYSIS`, part 3 only; tests first, 7, 4 seen to fail — the other 3 hold what must
stay true): the instruction "Determine the best Sigma log sources for detecting this attack" becomes: recommend
the log sources that would record the attack's **most specific evidence**; first look at what the text gives
to detect on (commands and processes, files, registry keys and values, network destinations, script contents,
events a specific log records — often by an event ID, or a product's or appliance's own log); name that
evidence for each suggestion; put first the log source whose evidence a rule could match with the **fewest
false positives**, whichever form it takes; a log source that records none of the text's evidence is not a
suggestion. New field `evidence` (at most 5 strings from the text); the example's evidence is placeholders only.
The instruction names no log source (a test holds it: no steer towards or away from a category). The user's
uncommitted comments in `prompts.py` were set aside with `git stash` for this commit and put back after.
**Smoke** (2 tuning cases, not the confirmation set): the new field was written in every suggestion; answers
readable and short (2,511 and 1,205 tokens) — **but both top picks stayed `process_creation`**: Operation
Triangulation listed its C2 domains as evidence yet ranked them third (and gave an iOS campaign `windows`);
Kapeka's scheduled task stayed a process start. Two cases say nothing about a rate, but they warn.
**Development check before the confirmation (tuning set only):** one full run of the 60 tuning cases (seed 0)
with Change 38, compared with the three earlier runs of today's analysis on the same cases (`compare_arms.py
--manifest`: P, Pany; descriptive — run-to-run variation alone moves P by up to 5 of 60). If the picks barely
move, the wording is revised on the tuning set and checked again; the confirmation set is run only once the
wording is final, with its plan fixed in this log first.

### Change 38 v1, development check (tuning set): the picks do not move
`c38v1_tuning60.jsonl` (frozen checkout of `adc6c6a`; 60 of 60, CITABLE, 200.9 min, no stop). Against the three
earlier runs of today's analysis on the same cases (`compare_arms.py --manifest`): **P 25 of 60 (0.417) vs 23 /
26 / 26; Pany 0.567 vs 0.533 / 0.517 / 0.517; no pick 2 vs 2 / 4 / 4** — inside run-to-run variation. Top picks:
`process_creation` 36 (c36: 32), `webserver` 17 (18), `registry_set` 3, `file_event` 1, `network_connection` 1;
no product+service pick. Every suggestion carried `evidence` (237 of 237).
**Why (descriptive, tuning set):** the evidence is found but the ranking ignores it. In 12 cases the gold's
category is in the list below the top (rank 2–5), often with far more specific evidence than the top pick — e.g.
`e94486ea`: top `process_creation` with `powershell.exe -nop -w hidden`, `spoolsv.exe`; rank 2 `file_event`
with the full path of the dropped `user.exe`; `71c432c4`: top `process_creation` with `sqlservr.exe`, `gup.exe`;
rank 5 `ps_script` with the script names. The model writes its suggestions in its habitual order: it commits
to the first before it has laid out all the evidence.
**Next, v2 (tuning set):** the evidence first — an inventory of the text's evidence, each item with the log
source that records it and whether it is specific to the attack or also common in normal activity — written
before the suggestions in the answer, which are then ranked from it. Iteration count on the tuning set so far:
1 (disclosed as a researcher degree of freedom; the confirmation set is untouched).

### Change 38 v2 (tuning set, iteration 2): the evidence first — found and judged well, but not used to rank
v2 (tests first, 6 new, seen to fail; one v2 test's phrase then updated to the refined definition): the answer
lists `evidence_inventory` **before** the suggestions — each item with the log source from the tables that
records it and `specific`; the suggestions are "ranked from the inventory"; the inventory is saved in every row
(`stage_analysis`, `_pipeline_metadata`, `DIAGNOSIS_FIELDS`). Refined after a 2-case smoke (the inventory had
followed the prompt's own list order, processes first, and marked every item specific, standard Apple
processes included): the inventory is written **in the order it appears in the text**, and `specific` is true
**only when a defender could search for the exact value and expect no hits from normal activity — false for a
standard program even if the attacker used it**; rank by the log source recording the most items marked
specific. Tests 641 pass.
**Smoke (Operation Triangulation, tuning):** the labels are now calibrated — the Apple system processes false,
all 15 attacker domains true (21 of 27 items true) — **but the top pick is still `process_creation` (1 specific
item) over `network_connection` (15)**; the inventory also ignored its 15-item limit (27). Kapeka (first v2
smoke): the inventory found event 4698 in the Security log (the gold's log source) but no suggestion used it.
**Finding:** the model finds the evidence and, with a strict definition, judges its specificity well, but does
not rank by its own judgements within one long answer. More wording in the same answer is unlikely to change
that; no development run of v2 was started. Decision for the user: a separate short ranking step by the model
(it compares the log sources' evidence on its own), code sorting by the model's own labels, or stopping here.
Iterations on the tuning set so far: 2. The confirmation set is untouched.

### Change 38 v3 (tuning set, iteration 3): a separate ranking step
User (2026-09-30, choosing between a separate model step, code sorting by the model's labels, or stopping):
**"Separate AI step"**. New `LogSourceRankingStage` (`stage_logsource_ranking.py`, stage name
`logsource_ranking`), called by the analysis stage after its answer: a short prompt (`LOGSOURCE_RANKING`)
shows only the candidate log sources with their evidence and the evidence inventory with its `specific` marks,
and asks for one thing — an order, first the log source a rule could use with the fewest false positives
(specific evidence outweighs any amount of evidence normal activity also produces); it may add a log source the
evidence names but no candidate uses. **The model decides; code only checks:** an added log source must be one
SigmaHQ's rules use (Sigma's service convention, then `on_table`), every earlier suggestion is kept (one left out
goes to the end), a failed call leaves the analysis's order. Recorded in every row (`logsource_ranking`: before,
after, changed_top, added, dropped, reason, error). Tests first (9, seen to fail; two phrase checks then
collapsed whitespace); 650 pass.
**Smoke (2 tuning cases):** Operation Triangulation — the ranker moved `network_connection` (the 15 attacker
domains) above `process_creation` (364 tokens); Kapeka — kept `process_creation`, citing the malware's own path.
But Triangulation's **first rule was still written on `process_creation`**: the rule writer departed from the
new recommendation (defect 11's pattern). The development run measures both the pick (P) and the rule (S3u).
**Development run (tuning set):** one full run of the 60 tuning cases with v3, from a frozen checkout of this
commit, compared with v1's run and the three earlier runs (`compare_arms.py --manifest`; descriptive).

### Change 38 v3, development run (tuning set): the picks get worse
`c38v3_tuning60.jsonl` (frozen checkout of `efbef51`; 60 of 60, 0 errors, verdict CITABLE). Started 2026-09-30,
stopped by the user before any row (going offline), restarted 2026-10-02 after preflight passed (Ollama 0.34.1,
unchanged; 650 tests; smoke CITABLE). **Stopped again at 19 rows by the desktop app's new 2-hour limit on
background jobs** (first seen this day; a 201-min run on 09-30 had not been stopped); resumed from row 20 in the
user's own terminal (row 20 checked: a new case, no repeats). Slower than v1 (below); the cause is not measured
(the extra ranking call is one part; the Spark is shared, 9 users logged in at the time).
**Against the three earlier runs** (`compare_arms.py --manifest`; one v3 run vs three; tuning set, descriptive):
**P 22 of 60 (0.367)** vs 23 / 26 / 26 (v1: 25); Pany 0.483 vs mean 0.522 (v1: 0.567); no pick 3 of 60 (vs 10 of
180). **S3u 19 of 60 (0.317)** vs 22 / 26 / 26 (v1: 24); paired against the three, S3u −0.094 95% CI [−0.183,
−0.017], S5u −0.074 [−0.150, −0.006]; S1 0.933 vs 0.922. v3 is the lowest of the five runs on P and on S3u.
(Consistency is not comparable: one v3 run is trivially "the same in every run".)
**The ranking step itself, on the same answers** (new `eval/ranking_effect.py`, tests first, 5, seen to fail —
the analysis's own order is in each row's record, so this is free of run-to-run variation): the step ran in 57
of 60 (3 had no suggestion), failed in 0, added a log source in 2, had an addition refused by code in 13. **It
changed the top pick in 17 of 57: 3 to the gold, 6 away from it (5 to neither, 1 to another human rule's), 1 from
another human rule's to neither, 7 between two wrong ones. P before the step 25 of 60, after 22; Pany 32 → 29.**
8 of the 17 new top picks are `file_event` (exact paths and hashes are "specific"); none of those 8 reports' gold
rules uses `file_event` (3 use `process_creation`; `ranking_effect.py --list`). Where the top changed, the first
rule followed the new top in 7, the old top in 7, other in 3 (defect 11's pattern). Time per case (mean
`elapsed_s`, `compare_arms.py`): v3 463.5 s, v1 200.9 s.
**Reading:** "fewest false positives" is a defensible criterion, but it is not how SigmaHQ's authors chose the log
source for these reports; ranking by it moved the picks away from the human rules more often than towards them.
Together with v1 (no movement) and v2 (evidence judged well, not used), Change 38 does not improve the picks
after three iterations on the tuning set. Per the plan, the confirmation set is **not run** (it was reserved for
a version that moved the picks); it stays unused. Decision for the user: remove Change 38, try again, or keep it.

---

## 2026-10-03 — Change 38 removed; Change 37 kept

User (after the v3 result above): **"remove Change 38, keep Change 37"**. The pipeline goes back to its
pre-Change-38 state (`ffeff82`): the analysis prompt's earlier log-source instruction ("Determine the best Sigma
log sources for detecting this attack"), no evidence inventory, no ranking step (`stage_logsource_ranking.py`
and the `LOGSOURCE_RANKING` prompt deleted), one model call in the analysis stage, and the two diagnosis fields
taken out of `run_eval.DIAGNOSIS_FIELDS`. Checked: all 13 prompt strings equal `ffeff82`'s; `backend/` and
`run_eval.py` differ from `ffeff82` only by the author's four section-header comments (`ad32dc8`). Change 37
(`repair_json_escapes`) stays. Tests first (`test_change38_removed.py`, 4: 3 seen to fail, the Change 37 one
holds what must stay true); the 22 tests of the removed code are deleted with it (in history at `efbef51`);
638 pass (`pytest tests`).
**Kept, because they measure rather than change the pipeline:** P / Pany in `compare_arms.py --manifest`,
`alternative_logsources.py`, `draw_heldout.py --out/--exclude`, `ranking_effect.py` (reads saved rows), and
**confirmation set 2** (`eval/manifest_confirm2.jsonl`), still unused — available to a later change.
**For the thesis (negative result):** three iterations of one idea on the tuning set — ask the model to rank log
sources by how specific their evidence is — none moved the top pick towards the human rules (v1 P 25 vs 23–26;
v2 judged the evidence well but did not rank by it; v3's separate ranking step: P 25 → 22 on the same answers,
S3u 19 of 60, the lowest of five runs). The model's notion of the most specific evidence (an exact file path or
hash) is not how SigmaHQ's authors chose these reports' log sources. Tuning-set iterations are disclosed as a
researcher degree of freedom; the confirmation set was never run on any version of Change 38.

---

## 2026-10-03 — P-C self-consistency: tool built, piloted on 2 tuning cases, shelved (user)

User: "lets do option 1" (P-C: the analysis answers the same input k times at a sampling temperature; the log
source most answers put first is the vote, how many agree is the confidence; disagreeing reports would go to the
analyst). New `eval/probe_self_consistency.py` (tests first, 11, seen to fail): the stages before the analysis
run once; the analysis then answers that identical input once at temperature 0 and k = 5 times at 0.7 (the
server's own default for the model: `ollama show` gives temperature 0.7, top_p 0.8, top_k 20, repeat_penalty
1.05; the client sets only the temperature). Measures built in: the vote vs the single answer (exact McNemar),
P by level of agreement, accept-only-m-of-k (coverage vs accuracy), unanimous vs the others (one-sided Fisher).
The same 60 tuning cases as every tuning run (checked); confirmation set 2 loads (60, no overlap).
**Pilot (2 tuning cases, `eval/results/pc_pilot2.jsonl`; design, not a result):** all 12 answers readable; the
sampled answers differ (indicators 23–33, techniques, the lower-ranked log sources) but **both cases' top pick
was `process_creation` in all 6 answers, and both are wrong** (gold `image_load`, `windows/security`; Pany 1 of
2). The habitual first pick survives sampling: two cases say nothing about a rate, but they warn that agreement
may not separate right picks from wrong ones. Time: 84–145 s per analysis answer (September runs: mean 67 s),
10.5–13.8 min per case → 10–14 h for the 60 tuning cases.
**Shelved** (user, 2026-10-03: "I don't think we gotta focus on right log source right now, what do we do about
the detection fields?"). No measurement plan was fixed and no full run made; the tool stays for later.

---

## 2026-10-03 — Detection: a value-level score (S5v) and a detection diagnosis (user: "do 1 and 2")

User: "I don't think we gotta focus on right log source right now, what do we do about the detection fields?"
→ (1) diagnose the detection where the log source is right, (2) score the values, not only the field names.
**Why both:** S5 is mostly the log source again. Within each held-out run of today's code (`s5_by_logsource.py`
run against itself), first-rule S5 is **0.668 / 0.632 / 0.688 when the log source is right (27 / 27 / 25
cases) and 0.043 / 0.070 / 0.119 when it is wrong (31 / 31 / 30)**: each log source has its own field names.
And S5 ignores values: tuning case `20c6ed1c` (Sitecore) scores S5 0.67 with `cs-uri-query|contains: cmd=` and
`request_body|contains: $(nslookup, <parameter>=a[$(` against a human rule matching the vulnerable page
`/sitecore/shell/ClientBin/Reporting/Report.ashx`. Two of those strings are the attack-vector prompt's own
inline examples of a `pattern` (`prompts.py`, the `payload_signatures` description: `"-enc JAB"`,
`"<parameter>=a[$("`, `"$(nslookup"`, `"'; DROP TABLE"`, `"../../etc/passwd"`, `"rO0AB"`) — defect 15 reaching the
detection; `count_example_copies.py` checks the worked examples' markers but not these inline examples.
**S5v — definition, fixed before any run is scored** (`scorers.score_detection_values`; tests first, 9, seen to
fail): the (field, value) pairs a detection looks for — every string or number, lower-cased, `*` at the ends
removed, a doubled backslash read as one; field = the name before the first `|` (as S5), "" for a bare keyword
list; selections named `filter…` (SigmaHQ's exclusions), `condition` and `timeframe` skipped. A human value g is
**found** by one of ours p when p contains g (ours at least as specific), or g contains p and p is at least half
as long; under 3 characters only when equal. Reported: recall in any field and in the same field, precision and
F1 in any field; undefined on a side with no values. Not yet a harness metric: computed post-hoc from saved rules.
**Diagnosis tool** `eval/diagnose_detection.py` (6 tests; **written before they were run — a lapse; checked
instead by 3 planted bugs, each caught**): per case, first rule vs the human rule — S3 as scored, S5 with fields
missed/added, S5v with values found/missed, the best of the case's rules on S5 and S5v, and with `--grounding`
which of our values and of the human's occur in the report's own text (pages preprocessed offline from the
snapshots + the GitHub files the PoC stage reads, as `count_example_copies.py`; a leading path separator not
required; under 3 characters not judged). Descriptive, **tuning set only**: runs `c36_yaml60` (today's
generation, Change 36), `p2g_shared60`, `oracle_ls60_unreviewed`, and `oracle_ls60_oracle` (the analyst's
log source given, plan 5.3).

### Detection diagnosis: results (tuning set, four runs; descriptive)
`diagnose_detection.py --grounding` (+1 test, seen to fail: "of the human's values in the report, ours found").
First rule, cases whose log source is right — `c36_yaml60` (26) / `p2g_shared60` (22) / `oracle_ls60_unreviewed` (26)
/ `oracle_ls60_oracle` (45, the analyst's log source given):
- **Fields mostly right, values mostly wrong.** S5 F1 0.708 / 0.647 / 0.720 / 0.637; **S5v F1 0.191 / 0.160 / 0.217
  / 0.140** (recall 0.174 / 0.128 / 0.206 / 0.133; same field 0.140 / 0.085 / 0.174 / 0.078). Cases with S5 ≥ 0.5
  but none of the human's values: **10 of 26 / 10 of 22 / 12 of 26 / 24 of 45**. Giving the right log source
  (oracle) does not fix the values.
- **Many human values are not in the report.** Of the human rules' values, 56 of 142 / 63 of 123 / 58 of 144 /
  79 of 218 occur in the report's own text (36–51%); in 9 / 6 / 9 / 21 cases none does. A literal check: a value
  the report writes differently counts as absent, so these are lower bounds on what the report gives.
- **Of the human's values that are in the report, the first rule uses about a quarter to a third: 18 of 56 / 15
  of 63 / 17 of 58 / 19 of 79.** That is the part a model reading the report could have got.
- **Our values not in the report:** 34 of 83 / 12 of 58 / 34 of 89 / 38 of 129. Most common: Office and script
  host binaries (`\winword.exe`, `\excel.exe`, `\wscript.exe`…: the model's knowledge of usual parents), and the
  attack-vector prompt's inline examples (`$(nslookup` 2, `<parameter>=a[$(` 1 in `c36_yaml60`; `ro0ab`,
  `username=` in `p2g_shared60`) — defect 15 in the detection; not yet counted by a committed criterion.
- **The first rule is not always the case's best:** a later rule has a better S5v in 7 / 5 / 7 / 11 of these
  cases (best-of-rules S5v 0.252 / 0.222 / 0.273 / 0.211).
Where the log source is wrong (32 / 31 / 31 / 9), S5 0.04–0.09 and S5v 0.03: as expected, both fail together.
**Reading:** the detection's weakness is the values, not the field names: right place, wrong strings. Two parts:
the report's own specific strings mostly do not reach the rule (fixable from the text), and much of what the
human rule matches is not in the report at all (knowledge the human brought: a bound on any report-only method).

### Detection, step 1: where the report's own values are lost (tuning set, four runs; descriptive)
User: "push it and do step 1". The rule writer does not see the report (`RULE_GENERATION`'s inputs: the attack
vector summary, payload signatures, incidental list, attack summary, indicators, techniques, retrieved documents,
the URLs). So a human value that is in the report but not in our first rule was either **given** to the rule
writer (in a saved stage output it receives: the attack vector without its incidental list, the attack summary,
the analysis's indicators and techniques) and not used; given only on the **incidental list** (which tells the
rule writer to avoid it); or **never given**. `diagnose_detection.py` (+5 tests, seen to fail; +1 for
`--min-value-chars`, seen to fail). Retrieved documents are not saved, nor the PoC stage's output, so a value
reaching the rule writer only through them counts as never given.
Cases whose log source is right, `c36_yaml60` / `p2g_shared60` / `oracle_ls60_unreviewed` / `oracle_ls60_oracle`:
- **all values (≥ 3 characters):** missed by the first rule 38 / 48 / 41 / 60 — given, not used **24 / 33 / 28 /
  40**; never given 13 / 14 / 13 / 20; incidental list 1 / 1 / 0 / 0; a later rule of the case uses 6 / 8 / 7 / 9.
- **sensitivity, values ≥ 6 characters** (short values such as `add`, `esta` occur in a report by chance;
  `--min-value-chars 6`, post-hoc): the human's values in the report 30 of 102 / 37 of 86 / 35 of 107 / 52 of 173;
  the first rule uses **7 of 30 / 5 of 37 / 7 of 35 / 9 of 52**; of the misses, given, not used **12 / 22 / 19 /
  28**, never given 10 / 9 / 9 / 15, incidental list 1 / 1 / 0 / 0.
**Reading:** the loss happens at both points. The larger part (52–69% of the misses with ≥ 6 characters) is at
the rule writer: the string was in what it was given and the first rule does not use it — e.g. `reg.exe save
hklm\sam %temp%\~reg_sam.save`, `\comsvcs.dll minidump`, `\report.wer`. The rest (30–43%) never left the report:
`wmic /node:`, `invoke-wmimethod win32_process -name create -argumentlist`, `netstat -aon | find` — command lines
no earlier stage carried forward, which the rule writer cannot see. The incidental list almost never removed a
human value (≤ 1 per run). "Given" is a literal match anywhere in the inputs, including inside an indicator's
context sentence, so it is an upper bound on how clearly the value was offered.

---

## 2026-10-03 — Change 39: the attack-vector prompt's inline example patterns removed

User: "remove the copied prompt examples". Found by the detection diagnosis (above): the description of a payload
signature's `pattern` in `ATTACK_VECTOR_EXTRACTION` gave six literal attack strings as examples — `"-enc JAB"`,
`"<parameter>=a[$("`, `"$(nslookup"`, `"'; DROP TABLE"`, `"../../etc/passwd"`, `"rO0AB"`. Searched every prompt:
this is the only live one (`ENTITY_EXTRACTION`, `RULE_OPTIMIZATION` also give examples but are used nowhere);
other suspicious values in rules (`cmd=`, `eval=`, `/login`) are in no prompt — the model's own knowledge.
**Measured before the change** (`count_example_copies.py`, new count, tests first, 3, seen to fail): these are
generic class patterns, which the copy criterion deliberately does not count (`probe_attack_vector`,
`test_generic_patterns_are_not_markers`), so they are counted **apart**: an example string in the output that
the input (pages + fetched GitHub code) does not contain. Reports with one in their rules — `c36_yaml60` 4,
`p2g_shared60` 2, `oracle_ls60_unreviewed` 4, `oracle_ls60_oracle` 4 (same attack vectors), `c38v1_tuning60` 2,
`c38v3_tuning60` 2, `main_heldout_r1/r2/r3` 2 / 1 / 2 (of 60 each); mostly `ro0ab` and `$(nslookup`; in the vector
2–4. Not every one is wrong (`rO0AB` is a right generic pattern for a Java deserialization flaw), but e.g.
`$(nslookup` in Sitecore's (.NET deserialization) rule, and the template text `<parameter>=a[$(`, came from the
prompt.
**Change** (tests first, 3: 1 seen to fail, 2 hold what must stay true): the list is **deleted** — "`pattern`:
The literal string or simple regex." — not replaced by placeholders (placeholders are copied too, Change 30);
the worked examples still show patterns. 677 tests pass.
**Measure, fixed now (before any run):** primary — tuning reports with an inline example string in their rules
(and in the vector), absent from the input: expected 2–4 → 0; the strings no longer occur in any prompt, so any
left would come from the model's knowledge. Secondary, descriptive — S5v (first rule; right-log-source cases and
all), S3u, S5u paired against `c36_yaml60`: no change expected beyond run-to-run noise (2–4 cases). The run is
the user's decision (it may share a run with the next change; the primary count is attributable to this change
alone, the secondary measures would not be).

### Detection, step 2: how the unused values were offered (tuning set, four runs; descriptive)
User: "look at how the unused values were offered". `diagnose_detection.py` now rebuilds what the rule writer is
given with the pipeline's own formatting (`AttackVectorStage.format_vector_summary`, the first 10 payload
signatures, the indicators, the attack summary, the techniques; the incidental list's first 20) instead of every
saved field (step 1 also searched e.g. the vector's `reasoning`, which the rule writer never sees). Tests
updated, +3 (6 failed before the change). **Step 1's totals are unchanged** under the exact input (e.g.
`c36_yaml60`, ≥ 6 characters: given 12, never given 10, incidental 1). Each missed value is put under the
clearest way it was offered: as a payload pattern, as an indicator's value, only inside a description (a
signature's quote, an indicator's context, the vector summary, the attack summary, a technique), on the
incidental list, or never given.
Cases whose log source is right, values ≥ 6 characters, `c36_yaml60` / `p2g_shared60` / `oracle_ls60_unreviewed` /
`oracle_ls60_oracle` (misses 23 / 32 / 28 / 43): **as an indicator 8 / 18 / 13 / 18**; never given 10 / 9 / 9 /
15; only in a description 4 / 3 / 5 / 6; **as a payload pattern 0 / 1 / 1 / 4**; incidental list 1 / 1 / 0 / 0.
(≥ 3 characters, `c36_yaml60`, 38 misses: indicator 12, never 13, description 8, pattern 4, incidental 1.)
**Reading:** the rule writer uses the payload signatures — the attack vector's "what rules should match" — but
mostly not the analysis's indicators: the largest group of report values it had and did not use were offered as
indicators (e.g. `reg.exe save hklm\sam %temp%\~reg_sam.save`, `\comsvcs.dll minidump`, `\winupd.log full`,
`\policydefinitions\postgresql.exe`). The never-given group is mostly post-exploitation host activity
(`wmic /node:`, `invoke-wmimethod win32_process -name create -argumentlist`, `netstat -aon | find`): the
attack-vector stage is asked about initial access and exploitation ("DURING EXPLOITATION"), and the analysis did
not list them either. Many human rules in this corpus detect that later host activity.

---

## 2026-10-03 — Change 40: the strings the report gives, for the rule writer; and the two-arm run's plan

User: "push it and design the run" → chose **"Prompt + record"** (no new retry) and **"Two arms, same night"**.
**Measures built first** (`a22a0a4`; tests first, seen to fail): `compare_arms.py` gains **S5vu** (primary: the
first rule's S5v as the user gets it — a rule that does not parse, or has no values, scores 0; undefined when
the human rule has no values) and **S5v** (secondary: rules that parse). `backend/pipeline/indicator_use.py`:
an indicator is *used* when a rule's detection value contains it, or is contained in it and is at least half as
long (S5v's matching); under 3 characters not judged; `filter…` selections skipped. `diagnose_detection.py`
reports it for any saved run (the same function), so the earlier code is measured the same way. Baseline,
`c36_yaml60`, log source right: **609 indicators, 155 used by some rule (25%), 35 by the first rule (6%)**; S5vu
over all 60 cases 0.102.
**Change 40** (tests first, 6, seen to fail; 698 pass): in `RULE_GENERATION` the indicators move from a JSON
dump under the attack summary to right after the payload signatures, as **"Strings the Report Gives (found by
the analysis — build the detection from the ones specific to this attack)"**, one line each (`format_indicators`:
`` `value` (type) — context``). Instruction 12 ("Include specific detection criteria based on the extracted
indicators") becomes "Build the detection from the strings the report gives: the payload signatures, and the
strings above that are specific to this attack (commands, file paths, registry keys, process names, network
destinations)". The model decides which strings fit (no type is filtered by code; kinds of evidence named, no
value). The pipeline records `indicator_use` {given, used, unused} on the final rules (with the coverage
check), in the metadata and `DIAGNOSIS_FIELDS`. Not enforced: no retry.

### Run plan — fixed before the run
**Arms** (60 tuning cases, seed 0, `--no-web-enrich`, `run_resilient`, one run each, **started together** in
the user's terminal so both see the same server conditions — P-B: answers differ between sessions, not within
one):
- **A, before** — frozen checkout of `5d8eae2` (the pipeline before Changes 39 and 40) → `c40A_tuning60.jsonl`
- **B, after** — frozen checkout of the Change 40 commit (Changes 39 + 40) → `c40B_tuning60.jsonl`
**Primary:** S5vu, B − A, paired over the cases both have (`compare_arms.py`, bootstrap 95% CI, 10,000, seed 0).
Descriptive (tuning set; one run per arm).
**Mechanism:** the share of indicators used by the first rule (`diagnose_detection.py`, all parsed cases and log
source right), A vs B; the report's values offered as indicators that the first rule does not use (log source
right, ≥ 6 characters, `--grounding --min-value-chars 6`), A vs B.
**Guards:** S5v precision (first rule, log source right); S3u, S5u, S1, rules per case (`compare_arms.py`).
**Change 39:** reports with an inline example string in their rules, absent from the input
(`count_example_copies.py`): A expected 2–4, B 0.
**Gate to the confirmation set:** S5vu B − A > 0, the first rule's indicator share higher in B, and neither S3u
nor S1 lower in B with a 95% CI entirely below 0. If it passes, confirmation set 2 (`eval/manifest_confirm2.jsonl`,
60 fresh cases, never run) with k = 3 runs per arm of the same two commits; that plan is fixed in this log first.

### Two-arm run (Changes 39 + 40 vs before, tuning set): Change 40 fails its gate; Change 39 works
`c40A_tuning60.jsonl` (A, `5d8eae2`) and `c40B_tuning60.jsonl` (B, `6a3fcf4`): both 60 of 60, 0 errors, verdict
CITABLE; started together 2026-10-03 ~02:45 in the user's terminal, finished ~13:55. Both stopped once at the
same case (`e710a880`, 37/60: one request timed out — A in review, B in analysis — about the same time, so
likely the server); `run_resilient` relaunched each (1/5) and the case was redone (saved once in each arm).
**Primary (as planned, `compare_arms.py`): S5vu A 0.105, B 0.075, B − A −0.030, 95% CI [−0.065, +0.003].**
Guards: S3u 0.433 → 0.383 (−0.050 [−0.117, +0.017]); S5u 0.339 → 0.286 (−0.053 [−0.116, +0.002]); S1 0.933 →
0.933; rules per case 4.217 → 3.983 (−0.233 [−0.567, +0.067]); S5v 0.099 → 0.087. P 27 → 26 of 60. No difference
excludes 0, but every content measure is lower in B. Time per case 633 s in both.
**Mechanism (`diagnose_detection.py`):** indicators used by the first rule, all parsed cases, **A 116 of 1,698
(6.8%), B 127 of 1,544 (8.2%)**; by some rule A 466 (27.4%), B 417 (27.0%). Log source right (A 26, B 23 cases):
first rule 46 of 846 vs 42 of 653; S5v precision 0.282 → 0.226 (guard, lower); of the human's values in the
report (≥ 6 characters) the first rule uses 11 of 44 vs 7 of 30, misses offered as an indicator 17 vs 8 (not
comparable: different cases have the right log source in each arm).
**Change 39 (primary, as planned):** reports with an inline example string, absent from the input — **in the
rules A 2 (`ro0ab`) → B 0; in the vector A 3 → B 0.** Its secondary measures cannot be separated from Change 40's.
**Gate** (S5vu B − A > 0, indicator share up, no S3u/S1 drop with a CI below 0): **not passed** — S5vu is lower.
The confirmation set is not run. **Reading:** presenting the indicators as "the strings the report gives", next
to the payload signatures, barely changed how many the first rule uses (6.8% → 8.2%) and did not raise S5v; the
rule writer still uses mostly the payload signatures (a short list, checked by code with a retry) and not the
long, mixed indicator list (median 20 per case). Framing and position were not the obstacle. Decision for the
user: keep or remove Change 40; keep Change 39 (it removed what it targeted).

---

## 2026-10-03 — Change 40's prompt change removed; Change 39 kept; the record of indicator use kept

User: "remove change 40, keep 39". `prompts.py` and `stage_generate.py` restored from `a22a0a4` (before Change 40;
Change 39 and the author's comments included): the indicators are again a JSON dump under the attack summary,
instruction 12 is the earlier one, `format_indicators` is gone. **Kept:** `indicator_use` recorded on the final
rules (orchestrator, metadata, `DIAGNOSIS_FIELDS`) — measurement only. `backend/` and `run_eval.py` differ from
`a22a0a4` only by that record. Tests first (`test_change40_removed.py`, 5: 3 seen to fail, 2 hold what must stay
— Change 39 and the record); `test_report_strings.py` (Change 40's tests) deleted; 697 pass.
**Process note:** the push of `4feca00` ran in the same command as its secret scan, which reported 2 pattern hits;
checked after the push — both are strings inside generated detection rules (`…&apikey=` in a public exploit's
URL, a router's `httoken=` parameter), not credentials. From now on a push runs only after a clean scan or after
every hit has been read.

---

## 2026-10-03 — Change 41: a separate evidence step (the analysis split, first piece); and the run's plan

User: "design the split" → chose **"Like payload patterns"** (the checked strings join the payload signatures:
same framing, same coverage check, same single retry) and **"Leave it as is"** (the analysis keeps its indicators;
one change at a time). Why (log above): the rule writer uses the payload signatures (a short list, checked by
code with one retry: 76% used) but not the analysis's long, mixed indicator list (median 20 per case; Change 40's
reframing gave nothing), and about a third of the report's values the human rules use are never passed on.
**Change 41** (tests first: 14 new, seen to fail; the review-checkpoint stand-in pipeline and its expected event
sequence gain the step; 711 → 713 pass with the measure): new `EvidenceStage` (`stage_evidence.py`, stage name
`evidence`), after the attack vector and before the analysis, in both pipeline paths (`run_sync`,
`_analysis_events` + the app's step list). One job (`EVIDENCE_EXTRACTION`, placeholders only, no value, no log
source named): copy up to 8 strings a detection rule could match on — command lines, file paths, registry keys and
values, process/service/task names, URLs, domains, user agents, pipes, mutexes — **exactly as the report writes
them**, with the sentence each is in, its kind and the activity; leave out hashes, CVE identifiers and product,
vendor and actor names; it gets the report text (the analysis's window), the attack-vector summary and the
incidental list. **Code checks, never repairs:** a string is kept only if the report text the step was given
contains it (case, runs of whitespace and a doubled backslash ignored), it has ≥ 3 characters, it is not on the
incidental list, and it is no existing payload signature or repeat; at most 8. Kept strings are appended to
`attack_vector.payload_signatures` (`source: evidence`, `where` = kind, `derived_from` = the sentence); the
generation prompt now shows up to 16 payload signatures (was 10). Everything is recorded (`evidence`: proposed,
kept, dropped with reasons, error) in the metadata and `DIAGNOSIS_FIELDS`; a failed call adds nothing.
Side effects, disclosed: the coverage check's retry (≥ 50% of the signatures unused) now also counts the
evidence strings, so it may fire more often; one more model call per case.
**Measure built** (`diagnose_detection.py`, tests first, 2): the evidence step's record and the kept strings'
use by some rule / the first rule.

### Run plan — fixed before the run
**Arms** (60 tuning cases, seed 0, `--no-web-enrich`, `run_resilient`, one run each, started together in the
user's terminal): **A** — frozen checkout of `cde43ed` (main: Change 39, no Change 40 prompt) →
`c41A_tuning60.jsonl`; **B** — frozen checkout of the Change 41 commit → `c41B_tuning60.jsonl`.
**Primary:** S5vu, B − A, paired (`compare_arms.py`, bootstrap 95% CI, 10,000, seed 0). Descriptive (tuning set).
**Mechanism:** (1) of the human rules' values that occur in the report (≥ 6 characters, `diagnose_detection.py
--grounding --min-value-chars 6`), the share the first rule uses, summed over all parsed cases, A vs B; (2) the
evidence step in B: strings proposed, kept, dropped by reason ("not in the report" = how often the model's
"verbatim" strings are not verbatim), kept strings used by some rule and by the first rule.
**Guards:** S5v precision (first rule, log source right); S3u, S5u, S1, rules per case; time per case; cases
whose generation ran twice.
**Gate to the confirmation set:** S5vu B − A > 0, mechanism (1) higher in B, and neither S3u nor S1 lower in B
with a 95% CI entirely below 0. If it passes: confirmation set 2 (60 fresh cases, never run), k = 3 runs per arm
of the same two commits, its plan fixed here first.

### Change 41, two-arm run (tuning set): the gate passes
`c41A_tuning60.jsonl` (A, `cde43ed`) and `c41B_tuning60.jsonl` (B, `4def19d`): both 60 of 60, 0 errors, no stop,
verdict CITABLE; started together 2026-10-03 16:11, finished ~21:20 / ~21:53 (the server was faster: 5.2 and 5.7
min per case).
**Primary (`compare_arms.py`): S5vu A 0.080, B 0.105, B − A +0.026, 95% CI [−0.013, +0.069].** (Run-to-run
variation of this size is possible: arm A of the Change 40 run, earlier code, scored 0.105.)
Guards: S3u 0.400 → 0.383 (−0.017 [−0.083, +0.033]); S1 0.950 → 0.967 (+0.017 [−0.050, +0.083]); S5u 0.316 →
0.299 (−0.017 [−0.068, +0.032]); rules per case 3.850 → 4.067; time 310 → 342 s (+32 [−16, +88]); tokens +11,597
[+8,260, +14,901]; P 26 → 25 of 60; generation ran twice in 34 → 42 of 60 (the coverage retry fires more, as
disclosed). S5v precision, log source right: 0.232 → 0.291.
**Mechanism (`diagnose_detection.py --grounding --min-value-chars 6`):** (1) of the human rules' values in the
report, the first rule uses — log source right 7 of 30 → 10 of 34, wrong 4 of 58 → 5 of 50; **all parsed cases
11 of 88 (12.5%) → 15 of 84 (17.9%)**. (2) The evidence step (B, parsed cases): proposed 423, **kept 285**,
dropped 86 duplicate, 35 incidental, **15 not in the report (3.5% of proposed)**, 2 too short; failed 0; kept
strings used by some rule 165 (58%), by the first rule 53 (19%). Misses are now more often "given as a payload
pattern" (8 / 22 vs 3 / 5): the strings reach the rule writer's checked list, and the first rule still skips some.
**Gate** (S5vu B − A > 0; mechanism (1) higher in B; neither S3u nor S1 lower with a 95% CI below 0): **passed**.
Observation, quick count (not a committed tool): 30 of the 299 kept strings are defanged (`[.]`), e.g.
`trustsecpro[.]com` — verbatim, but not as they would appear in a log. Left as is: the confirmation tests this
commit unchanged; refanging would be its own change.

### Confirmation plan (confirmation set 2) — fixed before any confirmation run
**Cases:** `eval/manifest_confirm2.jsonl`, 60 cases never run by any arm (drawn 2026-09-29; no overlap with the
tuning or the first held-out set; only their categories were looked at). Flags as every run: `--manifest
eval/manifest_confirm2.jsonl`, no `--sample`, `--no-web-enrich`, `run_resilient`.
**Arms, k = 3 runs each:** A = frozen `cde43ed` → `c41A_confirm_r1/r2/r3.jsonl`; B = frozen `4def19d` →
`c41B_confirm_r1/r2/r3.jsonl`. The two arms run at the same time (one terminal tab each, its 3 runs one after
another), so both see the same server conditions. **Nobody reads any confirmation row or score until all six runs
are finished.**
**Primary:** S5vu, B − A, each case's value the mean of its 3 runs, paired over the cases every run has
(`compare_arms.py --a r1 r2 r3 --b r1 r2 r3`, bootstrap 95% CI, 10,000, seed 0). **Confirmed if the CI's lower
bound is above 0**; otherwise not confirmed (reported as is).
**Secondary, descriptive:** mechanism (1) pooled over the 3 runs per arm; the evidence step's record (B); guards
S3u, S5u, S1, rules per case, time, tokens, second generations; P/Pany; consistency across the 3 runs.

### Change 41, confirmation (confirmation set 2, k = 3 per arm): not confirmed
`c41A_confirm_r1/r2/r3.jsonl` (A, `cde43ed`) and `c41B_confirm_r1/r2/r3.jsonl` (B, `4def19d`): all six 60 of 60,
0 errors, verdict CITABLE; started 2026-10-03 ~23:10, finished 2026-10-04 ~22:20; every run used exactly the
manifest's 60 cases (no overlap with the tuning or the first held-out set — checked by full rule id: tuning
`e710a880-…3023` and confirmation `e710a880-…33da` are two rules). No row or score was read before all six ended.
**Disclosed, run conditions:** run 1 of each arm — one connection error each, relaunched by `run_resilient`, the
case redone. 2026-10-04 ~13:20 the connection was lost for > 10 minutes and both arms gave up at 13:33 (A run 3 at
18/60, B run 2 at 54/60; B's run 3 gave up at 13:44 with no row); **the Spark itself had been restarted** (uptime
3 h 35 min at 18:24 → booted ~14:50; Ollama still 0.34.1, same model and context). Resumed ~15:20 (same commands;
resume per file). ~18:50 a VPN drop shorter than the 10-minute window; both rebuilt the tunnel and resumed. The arms
straddle the restart unequally (after it: A ~42 cases of run 3; B 6 of run 2 and all of run 3) — answers depend on
the server's state (P-B), so this is a slight imbalance, not a reason to discard.
**Primary (as planned): S5vu A 0.149, B 0.144, B − A −0.005, 95% CI [−0.039, +0.025] — the lower bound is below
0: not confirmed.** The tuning set's +0.026 [−0.013, +0.069] did not replicate.
Secondary (`compare_arms.py`, case = mean of 3 runs): S3u 0.428 → 0.444 (+0.017 [−0.011, +0.050]); S5u 0.313 →
0.331 (+0.018 [−0.017, +0.055]); S1 0.956 → 0.961; S4 0.182 → 0.147 (−0.036 [−0.077, +0.002]); S5v 0.159 → 0.145;
rules 3.950 → 4.044; time 368 → 399 s (+31 [−12, +73]); tokens +11,142 [+8,528, +13,971]; P 0.483 → 0.494; Pany
0.644 → 0.644; same first-rule log source in all 3 runs 47 → 49 of 60 (McNemar p = 0.73); generation ran twice in
109 → 131 of 180.
**Mechanism (pooled over the 3 runs, `diagnose_detection.py --grounding --min-value-chars 6`):** of the human rules'
values in the report, the first rule uses **A 99 of 591 (16.8%), B 118 of 591 (20.0%)**. The evidence step (B):
proposed 1,295, kept 862, dropped 208 duplicate, 171 incidental, **53 not in the report (4.1%)**, 1 too short; 1
failed call of 180. So the mechanism moved as designed, but not enough to change S5v: the report's own values are a
minority of what the human rules match (with ≥ 6 characters, 591 of the human values over 3 runs; most are not in
the report at all), and the added strings come with others the human rule does not use.
**Reading:** giving the rule writer the report's own strings, checked and verbatim, makes it use more of them, but
the value score against the human rule does not rise. Detection values that agree with the human rule mostly come
from knowledge the report does not hold. Decision for the user: keep Change 41 (an analyst-facing, verified
evidence list, R2; no measured benefit on S5v; costs time and retries) or remove it.

---

## 2026-10-04 — Change 41 removed

User: "remove change 41" (after the confirmation: not confirmed). `orchestrator.py`, `prompts.py`,
`stage_attack_vector.py`, `run_eval.py`, `frontend/script.js` and the review-checkpoint test restored from `cde43ed`;
`stage_evidence.py` and its tests deleted (in history at `4def19d`). `backend/`, `frontend/` and `run_eval.py` are
now identical to `cde43ed`: Change 39 and the record of indicator use stay; the payload signatures are shown up to
10 again. The diagnosis tool keeps reading the evidence record of saved runs. Tests first
(`test_change41_removed.py`, 4: 3 seen to fail, 1 holds Change 39); 703 pass. The idea (a checked evidence list)
stays on the roadmap as an analyst-facing feature (R2), not as a rule-quality change.

---

## 2026-10-04 — A rule evaluator for replay tests (R9): definition, fixed before any code

User: "what is the replay test?" → "which one do you think is better, to write our own evaluator or the one from
pySigma?" → "design the evaluator". Chosen (my recommendation, the user asked to design it): **pySigma (installed,
0.11.23; used by the review stage) parses the rule; a small matcher of ours evaluates pySigma's parsed condition
against events.** No new dependency. Why not pySigma's SQLite backend: a new dependency with a version risk
(Python 3.9, pySigma 0.11), and more steps between rule and verdict (rule → SQL, event → table, SQLite's ASCII-only
case folding, regex as an add-on). Why not fully our own: Sigma's modifiers, wildcards and condition grammar are
where the errors would be; pySigma resolves them (checked: `endswith` → `*\\x`, `contains|all` → AND, `all of
sel_*` / `1 of filter_*` expanded; `SigmaString.to_regex()`).
**What exists to validate it:** SigmaHQ's `regression_data/` — 138 recordings, each for one rule (by id): an
`info.yml` with the expected `match_count` (1 in 114 tests; absent in 24 → read as "at least 1"), the `.evtx`, and
a `.json` copy of the events (136 of 138; 128 hold one event, 8 several written back to back). SigmaHQ's own runner
uses an external binary (`evtx-sigma-checker`), which we do not have; the JSON copies hold the same events.
**Only 2 of the corpus's 303 gold rules have a recording** (React2Shell CVE-2025-55182, Grixba), so the recordings
validate the evaluator; they cannot score our rules.
**Definition (`eval/rule_matcher.py`):**
- A rule is parsed by `SigmaRule.from_yaml`; its condition by pySigma (`parsed_condition[0].parse()`). A parse error,
  more than one condition, or an aggregation/correlation → "cannot evaluate", never a guess.
- The tree is evaluated per event: AND / OR / NOT as written; a field-equals-value node looks the field up by its
  exact name, else case-insensitively; a missing field does not match (except a null value, below).
- Values: a string (`SigmaString`, modifiers already applied by pySigma) matches when its `to_regex()` pattern
  matches the whole field value, **case-insensitively** (Sigma's default; case-sensitive for `|cased`); a number
  equals the field's number (a numeric string counts); a null matches a missing, null or empty field; `|re` is
  searched with its own flags (case-sensitive by default, as in Sigma); `|exists`, `|cidr`, `|lt/lte/gt/gte`,
  booleans and `|fieldref` as named. Any other value type → "cannot evaluate".
- A keyword (field-less value) matches when its pattern is found anywhere in any field value of the event.
- An event from a Windows event JSON is flattened: `EventData` (or `UserData`'s inner map) fields, plus `EventID`,
  `Channel`, `Provider_Name`, `Computer` from `System`. An already-flat map (e.g. a synthetic event) is used as is.
- Log-source applicability is **not** part of the matcher; the replay step decides which events a rule sees.
**Validation, fixed now:** each recording's rule (found by id under `data/sigma/rules*`) is run over its JSON
events; **agree** = the number of matching events equals `match_count` (≥ 1 when absent); otherwise disagree; no
JSON, rule not found or "cannot evaluate" → listed apart with the reason. **The first pass's agreement rate is
reported as is.** Any later fix to the matcher gets its own test first, and the final rate is reported next to the
first; the matcher scores our rules only once every evaluable recording agrees or each disagreement is explained.
Also, descriptive: every rule against the other recordings' events (off-target matches; each one listed, since some
may be genuine).

### The evaluator's validation on SigmaHQ's recordings: first pass 132 of 136
Committed before the first pass (`e8fa0fb`; tests first — `test_rule_matcher.py` 16, `test_validate_matcher.py` 6;
4 planted bugs: 3 caught at once, the 4th — a missing field read as empty — caught after one test was added, `Field:
'*'` needs the field). `eval/validate_matcher.py` → `eval/results/matcher_validation.jsonl`:
**138 recordings: agree 132, disagree 4, no JSON 2 → 132 of 136 evaluable (97.1%), first pass, no fix.** No rule
missing, none "cannot evaluate".
**The 4 disagreements, examined — all the evaluator matching more events than `match_count` (1), and each extra event
satisfies the rule as written:** `0b9ad457` AnyDesk Temporary Artefact — 3 events whose `TargetFilename` contains
`\AppData\Roaming\AnyDesk\user.conf` (`user.conf.new` ×2, `user.conf~RF…TMP`); `8fbf3271` Cred Dump Tools Dropped
Files — `procdump64.exe`, `procdump64a.exe`, `procdump.exe`, each a listed `endswith` (the `:Zone.Identifier` copies
correctly not matched); `45e112d0` IE Change Domain Zone — three `ZoneMap\Domains\bad-domain.com\…` values, all
`DWORD (0x00000002)`, which the filter does not exclude; `c7dcacd0` Disable Administrative Share Creation —
`AutoShareServer` and `AutoShareWks` both `DWORD (0x00000000)`, both listed. So the recordings' `match_count`
undercounts these four (SigmaHQ's external checker may count differently); no matcher change.
**Off-target (descriptive):** 28 rules match events of other recordings, 45 pairs — related rules overlapping by
design (e.g. the generic "File Download Via Bitsadmin" fires on the four specific Bitsadmin rules' recordings).
**Verdict under the plan:** every evaluable recording agrees or its disagreement is explained → the evaluator may
score rules. Its known limits: the 2 recordings without JSON (EVTX only; reading EVTX would need a new dependency),
and the value types it raises "cannot evaluate" for (none occurred here).

---

## 2026-10-05 — R9.2 synthetic replay: design and validation plan (PROPOSED; fixed once the user settles the open points)

User: "I want to understand more about the synthetic replay, like how do you know it should work and we are not
making this to have good results" → "yes, write that first". **Nothing is built and nothing is scored until the
open points below are decided; after that, the builder and the measures are frozen before they touch our rules.**

**What it measures — and what it does not.** "If the behaviour the human rule targets happened, would our rule
fire?" The events are built from the human rule, so it is still agreement with the human's view — at the level of
detection logic (fields, modifiers, conditions, log source), not strings. It does **not** show that a rule catches
the real attack; only real logs do (lab detonation, 5.6). This is stated with every result.

**How it could flatter us, and how it could punish us.** (1) Building an event means filling text around the
human's fragments; any context we invent (e.g. a realistic command line around `-enc`) could make our rule fire for
our words, not its logic. (2) A very broad rule of ours would fire on almost any built event. (3) Minimal events
hold only the fields the human rule uses, so a rule of ours that also requires another field (e.g. the parent
process) cannot fire — this punishes specificity. Each is either removed by the construction rule or measured.

**The event builder (frozen before use).** For each rule (pySigma-parsed, as the evaluator): the condition tree is
put in disjunctive normal form with NOT pushed down to the atoms; **each conjunction is one way the rule can fire →
one event** (at most 20 per rule, in a fixed order; the cap is reported). Values are **minimal, nothing invented**:
a wildcard string becomes its literal parts (`*` → nothing, `?` → `x`); several string atoms on one field are joined
by one space, starts-with parts first and ends-with parts last; a number is itself; `|gt N` → N+1, `|lt N` → N−1;
`|cidr` → the network's first host; `|exists: true` → the field with `x`, `false`/null → field absent; booleans as
written; `|fieldref` → both fields `x`; an expansion → its first alternative; a keyword → the field `Message`.
Negated atoms are satisfied by leaving their field out (a missing field matches no pattern); when the same field is
set by a positive atom, the evaluator checks the negation holds. A regex atom, a contradiction (e.g. one field equal
to two values), or an event the evaluator says the source rule does not fire on → **"cannot build"**, listed with
the reason, never patched. Events carry only the fields their conjunction needs, plus the source rule's log source.

**Log-source applicability (OPEN POINT 2).** Proposed: our rule sees an event when every log-source field our rule
names (category, product, service) equals the event's, or the event's leaves it unnamed. Also reported: firing with
log source ignored (logic only), so log-source misses (already S3) and logic misses are told apart.

**Measures for our rules (OPEN POINT 1 on the unit).** Per case: **hit** — the case's rules fire on at least one of
the human rule's events (proposed primary: **any rule of the case**, as deployed; first rule secondary); **coverage**
— the share of the human rule's events caught; **breadth** — the share of the *other* cases' event sets our rules
fire on (an early warning of false alarms: a broad rule cannot look good on hit without showing here); **miss
reasons** — rule does not parse / log source / a field our rule requires is absent from the event / value mismatch.

**Validation — on cases whose answer is known, before scoring any of our rules (thresholds: OPEN POINT 3).**
- **V1 Builder self-check:** each rule fires on its own built events (SigmaHQ's 136 recordings' rules and the
  corpus's 303 gold rules). Proposed pass: **≥ 95% of buildable rules**; every failure listed.
- **V2 Real vs synthetic, SigmaHQ's recordings (the strongest test):** for every pair (rule X, recording of rule Y)
  among the 136, *real* = X fires on Y's recorded events (the validated evaluator: 136 self-pairs + the 45 related
  pairs found 2026-10-04), *synthetic* = X fires on events built from Y's rule. Proposed pass: **synthetic false
  fires on real non-pairs ≤ 1%**; the synthetic hit rate on the 45 related pairs is **reported, not thresholded** —
  it measures how much minimal events under-detect compared with real logs (the size of bias 3).
- **V3 Unrelated rules stay quiet:** each corpus gold rule against the other gold rules' events. Proposed pass:
  **≤ 2% of pairs fire**, each listed (related campaigns may overlap genuinely).
- **V4 A known ordering:** the May code is worse than today's (held-out, k = 3: log source 0.072 vs 0.439). Proposed
  pass: replay hit, today − May, **95% CI above 0** (paired by case, mean of 3 runs).
- **V5 Null baseline:** each case scored with *another* case's generated rules (a fixed derangement, seed 0) on
  today's held-out runs. Proposed pass: **null hit ≤ 5%** and far below the real hit.
**If any of V1, V2, V3, V4, V5 fails, the replay is not used for our rules, and that is reported.** A builder bug found
during validation gets a test first; the first-pass and final validation numbers are both reported.

**Then, and only then, our rules:** today's held-out runs (`main_heldout_r1–r3`, never tuned on) and the fresh-report
runs of today's pipeline (`c41A_confirm_r1–r3`) as primary, k = 3 each; the tuning runs descriptive; the May runs for
context. No builder or measure change after our scores are seen.
**Open points settled by the user (2026-10-05), before anything is built — the design above is now FIXED:**
(1) unit: **any rule of the case** is primary (first rule secondary); (2) log-source applicability: **lenient on
fields the human rule's log source leaves unnamed** (log-source-ignored firing also reported); (3) validation
thresholds **as proposed**: V1 ≥ 95%, V2 synthetic false fires on real non-pairs ≤ 1% (related-pair hit reported),
V3 ≤ 2%, V4 today − May 95% CI above 0, V5 null hit ≤ 5% and far below the real hit.

### R9.2 amendment (user, 2026-10-05, before anything is built): our rule may catch the attack another way
User: "a lot of the attack vectors written by the human were not even present on the PoC, so do you think is really
that bad that we don't have exactly what the human have? maybe it will trigger even without what the human wrote"
→ "yes, add them to the design". The point holds: two valid rules can catch one attack through different evidence,
and in real logs both would be present. Events built from a human rule hold only that rule's evidence, so **a replay
hit means "catches what the human targeted"; a miss is ambiguous** — the replay is a **lower bound**, conservative
against our rules (as S3, S5 and S5v are). The size of this bias on known data is V2's related-pair hit rate (of the
45 real "different rule, same recorded attack" pairs, the share synthetic events also catch) — reported as such.
Added to the fixed design:
1. **Events from every human rule for the report.** Besides the gold rule, the other human-written SigmaHQ rules for
   the same report, by the definition already used for Pany (`alternative_logsources.py`: an emerging-threats rule
   citing one of the case's input URLs, a URL cited by more than 5 rules linking nothing). **Primary hit: our rules
   fire on the events of any human rule for the report**; hit on the gold rule's events alone is reported as well
   (the measure first fixed). Coverage and breadth use the same union; V3 stays on gold rules; V4 and V5 are applied
   to the primary hit.
2. **Misses sorted.** A missed case is a **"report-grounded miss — plausible different detection, unverified"** when
   one of the case's rules parses and every one of its detection values that can be judged (≥ 3 characters) occurs in
   the report's text (`diagnose_detection.grounded`, the pages + fetched PoC code), at least one value judged; other
   misses are "ungrounded". Reported apart; never counted as a hit.
3. **Real logs for the question itself.** Whether a rule fires without the human's evidence is settled only by real
   attack logs. Lab detonation (5.6) chooses 2–3 reports that are **report-grounded misses**, reproducible in the
   user's lab, preferably held-out or fresh reports; the user runs the lab (never operated by Claude); the recorded
   logs are scored with the validated evaluator for both our rules and the human rules.
**Not done, on purpose:** no events are built from the report text — our rules are written from that same report,
so they would fire almost by construction.

### R9.2 build: two precisions fixed before the validation runs (2026-10-05)
Written while building `eval/validate_replay.py`, before it has run: (a) V5's "far below the real hit" means **the
null hit is at most half the real hit** (as well as ≤ 5%); (b) V1 is checked on both rule sets — SigmaHQ's recording
rules and the corpus's gold rules — and **must reach 95% in each** (the stricter reading). V2 compares logic only
(the recordings carry no log-source label to apply), as the evaluator's validation did. V4 and V5 necessarily compute
today's held-out replay hit; it is reported as the primary result only after all five tests pass.

### R9.2 validation: the replay does not pass (V4 fails) — it is not used to score our rules
Code committed before running (`39c20c8`). **First pass crashed** (a corpus gold rule has a number among its
keywords: the builder crashed, the matcher would have said "cannot evaluate"); fixed with tests first (`1a9dba3`;
the matcher's own validation re-run: unchanged, 132 of 136). Second pass (`eval/validate_replay.py` →
`eval/results/replay_validation.json`), no other change:
- **V1 pass** — recordings' rules 134 of 134 buildable (2 unbuildable: regex), gold 419 of 420 (17 of 437 unbuildable;
  cannot-build: regex 33 / 41 conjunctions). The 1 failure, `10ac0730` (nsswitch.conf, CVE-2025-32463): `endswith:
  /etc/nsswitch.conf` and not exactly `/etc/nsswitch.conf` — the minimal value is the excluded path; "nothing
  invented" cannot add a prefix. Explained, a limit of the construction.
- **V2 pass** — synthetic false fires on real non-pairs **31 of 18,046 (0.17%)**, mostly related rules (e.g. "Renamed
  AdFind Execution" on "PUA - AdFind.EXE Execution": minimal events lack the fields a real event has, so some NOT
  conditions hold). **Related real pairs caught: 15 of 44 (34%)** — the measured size of the under-detection bias:
  minimal events miss about two thirds of the cases where a different rule fires on the same recorded attack.
- **V3 pass** — unrelated gold rules: 9 of 182,378 pairs fire.
- **V4 FAIL** — replay hit on held-out, k = 3: May 0.046, today 0.086, **+0.040, 95% CI [−0.017, +0.098]** (n = 58);
  the CI is not above 0.
- **V5 pass** — shuffled rules 0.006 vs real 0.086.
**Verdict under the plan: not all pass → the synthetic replay is not used to score our rules.** No design change is
made to rescue it (that would be choosing the measure after seeing it). **Reading:** the replay is **specific but
insensitive** — when it fires it means something (V2, V3, V5), but minimal events built only from a human rule's
own values rarely catch a different rule (34% on real pairs), and our rules — May's or today's — rarely fire on them
(4.6%, 8.6%), so it cannot rank two versions of the code known to differ (log source 0.072 vs 0.439; S5 +0.158).
This agrees with S5v: our rules seldom share the human rules' values. **It leaves "does the rule fire?" to real logs**
(5.6 lab detonation; R10 benign logs). The tools stay (validated evaluator; builder; scoring) for real-log replay.

---

## 2026-10-05 — Pipeline quality, part A (no behaviour change): M1 and H8

User: "write the chapter 4 notes first, and then lets work on the pipeline quality" → order agreed: A (M1, H8), then
#1 ATT&CK retrieval query, #2 the technique cap, #3 the review prompt's Citrix example, #4 temperature 0, #5 defect 11,
#6 labels/imperatives, #7 a shorter analysis answer.
**M1** (prompt review §5): every row now records the rules **as the rule writer wrote them, before review**
(`pre_review_rules`: the last generation the final review processed) and the review's list of changes
(`review_changes`), in the metadata and `DIAGNOSIS_FIELDS`. The rules a user gets are unchanged. Why: only reviewed
rules were saved, so review's effect (it once merged three rules into one) could not be measured. Tests first (3, seen
to fail).
**H8** (prompt review §5 item 8): the five prompts nothing calls are deleted — `ENTITY_EXTRACTION`, `TTP_MAPPING`
(the pre-combined analysis), `RULE_VALIDATION`, `RULE_OPTIMIZATION` (the pre-combined review), `WEB_SEARCH_QUERIES`.
Checked: the 8 prompts in use are identical to before; the author's section comments are kept. Tests first (1, seen to
fail). 750 pass.

---

## 2026-10-05 — Change 42 (#1): the analysis searches ATT&CK with the attack-vector summary, then the text

**Diagnosis first** (new `eval/probe_mitre_query.py`, tests first, 5, seen to fail; offline — the local index and the
saved pages, no model call). The analysis stage's ATT&CK search (5 results, given to the model as "MITRE context") used
`combined_text[:500]`. On the tuning cases those 500 characters are mostly the input URLs, a page header and, e.g. on
Securelist, the whole site menu ("Dark mode off / Securelist menu / English Russian Spanish…"). The embedding model
reads at most 256 word pieces (~1,000 characters). Three queries, fixed before looking, on `c41A_tuning60`'s 42 cases
whose gold rule names techniques — a gold technique among the 5 results:
**current 3 of 42** (parent 6; mean recall 0.071) · **attack-vector summary 12 of 42** (14; 0.226) · **summary then the
current text 14 of 42** (14; 0.239).
**Change 42** (tests first, 2: 1 seen to fail, 1 holds the fallback): the query is `format_vector_summary(attack
vector)` followed by `combined_text[:500]`. Chosen over the summary alone because when the attack-vector stage finds
nothing its summary is a fixed sentence, and the text keeps the search informed. 757 pass. Measured in a run with #2
(plan below, fixed before the run).

---

## 2026-10-05 — Change 43 (#2): the technique limit is a limit, not a target; and the three-arm run's plan

**Why:** Change 32's "List at most the 10 most relevant techniques" became a quota. Techniques listed per case (the
analysis's `ttp_mappings`): `p2f_product60` (before Change 32) median 5, exactly 10 in 5 of 60, over 10 in 12;
`p2g_shared60`, `c36_yaml60`, `c41A_tuning60` (after) median 10, **exactly 10 in 42 / 41 / 44 of 60**. Gold rules tag 1
technique in 28 of 40 (Change 25 run). (Counted from the rows' saved `ttp_mappings`.)
**Change 43** (tests first, 2, seen to fail; Change 32's test now checks the ceiling in the new wording): instruction 5
of the analysis's ATT&CK part becomes "List the techniques most relevant first, as many as the text gives evidence for
and never more than 10; 10 is a limit, not a target". No typical number is suggested; the model decides. 759 pass.

### Run plan — fixed before the run (Changes 42 and 43, tuning set)
**Arms**, started together in the user's terminal (60 tuning cases, seed 0, `--no-web-enrich`, `run_resilient`, one run
each, frozen checkouts): **A** `1b90c44` (before 42 and 43; M1 records pre-review rules) → `c42A_tuning60.jsonl`;
**B** `ef6d118` (+ Change 42) → `c42B_tuning60.jsonl`; **C** the Change 43 commit (+ 42 + 43) → `c42C_tuning60.jsonl`.
B − A attributes Change 42, C − B Change 43; all three see the same server conditions.
**Change 42 — primary:** S4 (exact-technique F1, rules that parse; `compare_arms.py`), B − A, paired, bootstrap 95%
CI; parent-technique S4 reported too. **Mechanism:** cases whose analysis lists a gold technique (exact / parent),
A vs B (the offline retrieval check: 3 → 14 of 42). **Gate:** S4 B − A > 0, the mechanism higher in B, and neither S3u
nor S1 lower with a 95% CI entirely below 0.
**Change 43 — primary:** S4, C − B. **Mechanism:** techniques listed per case (median; cases with exactly 10), B vs C;
S4 precision. **Gate:** S4 C − B > 0, fewer cases with exactly 10, and the same guards.
**Guards (both):** S3u, S5u, S5vu, S1, rules per case, time; cut answers.
**If a change passes its gate:** a **confirmation set 3** — 60 of the 121 corpus cases never run (`draw_heldout.py
--exclude` every result file), drawn and committed before any run on it — k = 3 per arm, confirmed if the paired
95% CI's lower bound is above 0 (as Change 41's). Confirmation set 2 is spent (Change 41).
**Run plan amendment (user, 2026-10-05: "I won't be able to do the run of 10-20 hours right now"), before any run:**
the three arms run in **sessions of 20 cases** (`--sample 60 --seed 0 --limit 20`, then `--limit 40`, then `--limit
60`; `--limit` applies after the sample, and resume skips the cases done). In every session all three arms run
together, so each case's three versions see the same server state — the comparison is paired within case, as before;
sessions may be on different days. Everything else in the plan is unchanged.

---

## 2026-10-05 — #5, defect 11 diagnosed on today's pipeline: effectively fixed; no change

User: "do the defect 11 diagnosis first" (offline; the committed `diagnose_logsource.py`, definitions fixed
2026-09-24). Eight runs of today's pipeline — tuning `c41A_tuning60`, `c40A_tuning60`; confirmation set 2
`c41A_confirm_r1–r3`; held-out `main_heldout_r1–r3`:
- **First rule = the analysis's top suggestion, exactly (Change 26's measure): 49/57, 53/56, 54/59, 51/56, 52/57,
  48/58, 47/58, 49/55** (81–93%); a product added to it 0 in all eight, a service 1 (`main_heldout_r2`).
- **Overridden** (top suggestion's category right, rule's wrong — defect 11 as defined in 2.1): **1, 1, 3, 2, 3, 0, 0, 0**
  (baseline v2: 14 of 29 right suggestions were overridden).
- Where the wrong rules come from: **followed_wrong** (a wrong top suggestion, followed) 17, 20, 16, 15, 16, 10, 12, 12;
  **ranked_low** (the gold category offered as suggestion 2 or 3) 10, 6, 11, 14, 14, 13, 12, 13; wrong_elsewhere 0–8.
- The gold category is in **some** rule of the response in 30/57, 34/56, 39/59, 31/56, 34/57, 35/58, 36/58, 34/55 —
  4–10 more than in the first rule.
- Typical confusions (gold → top suggestion → rule, `c41A_confirm_r1`): file_event → process_creation (5),
  process_creation → webserver (4), registry_set → process_creation (3).
**Reading:** defect 11 is fixed by Changes 26 and 29 (status FIXED, measured); the rule writer follows the
recommendation. The remaining log-source error is the analysis's pick — wrong (followed) or right but not first —
which is R7 (Change 38's attempt failed). For the assistant, the analyst's choice among the suggestions (Change 34)
is the measured lever (5.3: S5 +0.144 when the analyst is right). Pipeline-quality item #5 closes without a change.

---

## 2026-10-05 — #3, the review prompt's Citrix example: never copied (0 of 2,540 saved reports)

User: "continue with #3". `COMBINED_REVIEW` item 8 ("PoC placeholder leakage") illustrates replacing a
placeholder-looking path with its stable prefix using a value from the Citrix demo report: `/metadata/samlidp/asdf` →
`|startswith: '/metadata/samlidp/'` (Inbox 2026-09-28). Measured before any change:
- `samlidp` occurs in **no retrieval collection** (all five), **no saved page or PoC file**, and **no gold rule** — so in a
  rule it could only come from this prompt.
- `count_example_copies.py` gains the count (`REVIEW_EXAMPLES`, `review_copies`; test first, seen to fail).
- **Every result file (45 files, 2,540 case rows, all code versions since September): `samlidp` appears 0 times** — in
  no rule and in no other saved field.
**Reading:** unlike the attack-vector prompt's examples (copied 1–6 times per 60 before Changes 27/30/39), this one
has never leaked; a run could not measure a fix (0 → 0). Decision for the user: replace it on principle (placeholders,
not real-case values) together with the next review-prompt change, or leave it. Pipeline-quality #3 is measured.

## 2026-10-05 — Change 44 (#3): the review prompt's illustration uses placeholders

User: "bundle the fix". `COMBINED_REVIEW` item 8: `/metadata/samlidp/asdf` → `|startswith: '/metadata/samlidp/'` becomes
`/<app path>/<random token>` → `|startswith: '/<app path>/'`; the point it illustrates (a placeholder path → its stable
prefix) is kept. Done on principle (never copied: 0 of 2,540). As in Change 30 the placeholders are counted markers
(`REVIEW_EXAMPLES` = `samlidp`, `<app path>`, `<random token>`), so a copied placeholder would show. Tests first (3: 2
seen to fail; the third holds the markers). 763 pass. **Measure:** with the next review-prompt change's run — copies in
rules (expected 0 → 0) and that run's guards. The Change 42/43 arms are frozen checkouts without it (no confound).

---

## 2026-10-05 — #7, the analysis answer's length: measured; the cut answers' ends now recorded

User: "continue with #7". New `eval/analysis_length.py` (tests first, 3, seen to fail; offline, from the rows' call
records). Ten runs of today's pipeline and before (`c36_yaml60`, `c40A_tuning60`, `c41A_tuning60`, `c41A_confirm_r1–r3`,
`main_heldout_r1–r3`, `p2f_product60`):
- **Finished analysis answers: median 2,106–2,409 tokens, p90 3,734–5,021, max 5,781–12,658** — far below the 16,384
  limit; median 44–134 s per answer.
- **Cases whose every analysis attempt was cut (no analysis at all): 0–2 per run of 60**, and **the same cases recur**:
  `5de632bc` (REvil/Kaseya) in 3 of 10 runs (all three confirmation runs), `9a2d8b3e` and `54e57ce3` (Emotet) in 2,
  `6f6afac3`, `965fff6c` in 1. Cases with any cut attempt: 0–4 per run.
- **What fills the saved analysis (JSON characters): indicators 56%**, techniques 26%, log-source suggestions 13%, attack
  summary 5% (median indicators 3,272 characters). The techniques are capped at 10; **the indicators have no limit**.
- The recurring cases are long (40,000–62,000 characters; median of the other tuning cases 19,963), several
  indicator-heavy (a quick count, not a committed tool: REvil/Kaseya ~723 domain-like strings, Emotet ~219 hashes and
  ~217 domains, CSharp Streamer ~62 hashes) — but `9a2d8b3e` (29 hashes) and `965fff6c` (none) are not lists.
**Hypothesis, not yet measured:** the model copies out long indicator lists until it runs out. Answers are not saved,
so: **the call record now keeps the last 2,000 characters of an answer cut at the limit** (`cut_tail`, telemetry +
`OllamaLLMClient`; None for finished answers; no answer, retry or rule changes). Tests first (3, seen to fail). 769 pass.
The Change 42/43 arms are frozen checkouts from before this, so their sessions will not record tails; the first run from
`main` after them will. A change (e.g. a limit on indicators, worded as a limit, not a target — Change 43's lesson — or
the indicator list as its own call) waits for what the tails show.

---

## 2026-10-05 — Change 42/43 run: session 1 done; sessions 2 and 3 run together overnight

Session 1 (cases 1–20, started ~17:28 EDT after all three preflights passed) finished ~19:50: **20 of 20 rows in each
arm, the same 20 cases in all three, 0 errors**, no stop, relaunch or give-up lines; mean ~6.6–7.0 min per case. The
three worktrees are unchanged (A `1b90c44`, B `ef6d118`, C `7dd5964`, no edits). **No scores read** (the plan reads them
only when all 60 are done in all arms).
User: "can you start the other 40, so I can leave it all night running." **Sessions 2 and 3 are run as one session of
40 (`--limit 60`) at ~20:00 EDT**, all three arms together, as the plan requires (same night, same cases, same order;
the run resumes after the 20 saved rows). The only difference from the logged plan is one long session instead of two
short ones; the cases and the comparison are unchanged. The tunnel answered (HTTP 200) right before; the full preflight
was not repeated (same frozen code that passed it ~3 hours earlier and has just run 20 cases cleanly).

---

## 2026-10-06 — Changes 42/43, tuning run: 42 passes its gate narrowly, 43 fails

The overnight session ended 01:12–01:18 EDT (last rows of A, B, C): **60 of 60 rows in each arm, the same 60 cases, 0 errors**, no stop, relaunch or
give-up lines; `summarise.py` verdict **CITABLE** for A, B and C. Before reading any score, the measures the run plan
names that no committed tool computed (S4 by parent, S4 precision, the analysis lists a gold technique exact/parent,
techniques listed, exactly 10) were added to `compare_arms.py` (`ATTACK`; tests first, 4, seen to fail; `3af5c32`). Check
against an earlier logged count: `c41A_tuning60` lists exactly 10 in 44 of 60 (logged 44) and 42 cases' gold rules name
techniques (logged 42). 773 pass. All numbers below from `compare_arms.py`, one run per arm, paired, bootstrap 95% CI.

**Change 42 (B − A), primary S4:** 0.193 → 0.212, **+0.019 [−0.047, +0.088]** (n = 37); by parent +0.039 [−0.060,
+0.134]; precision +0.032 [−0.009, +0.079]. **Mechanism:** the analysis lists a gold technique in **17 → 18 of 42**
cases exactly, **26 → 26** by parent. Guards: S3u +0.033 [−0.033, +0.100], S5u +0.076 [−0.011, +0.169], S5vu +0.024
[−0.011, +0.067], S1 +0.033 [−0.033, +0.100], rules +0.05, seconds +8 [−20, +36], tokens +3,367 [−89, +7,131]; cut
answers A 1 call in 1 case, B 0. **Gate (S4 > 0, mechanism higher, no guard CI entirely below 0): passed — narrowly:**
the mechanism rose by one case exactly and not at all by parent, so the S4 gain is not shown to come through it. The
offline retrieval check (a gold technique among the 5 results: 3 → 14 of 42) did not carry into the list the model
writes: in A it already listed a gold technique in 17 of 42 without that retrieval.
Post-hoc (not a gate measure): Change 42 also lowered the quota — exactly 10 listed in **49 → 40 of 60** (−0.150
[−0.250, −0.067]); mean listed 8.93 → 8.18. Why is not measured.

**Change 43 (C − B), primary S4:** 0.206 → 0.171, **−0.035 [−0.102, +0.030]** (n = 40); by parent −0.070 [−0.155,
+0.012]; precision −0.019 [−0.078, +0.041]. **Mechanism:** exactly 10 listed **40 → 35 of 60** (−0.083 [−0.200,
+0.033]); mean listed 8.18 → 7.63; median 10 in all three arms. A gold technique listed **18 → 15 of 42** exactly, **26
→ 21** by parent (−0.119 [−0.238, 0.000]): the shorter lists dropped right techniques as well as padding. Guards: S3u
−0.017 [−0.083, +0.033], S5u −0.036 [−0.125, +0.044], S5vu +0.003, S1 −0.033 [−0.100, +0.033], rules +0.17, seconds
+4. **Gate (S4 > 0, fewer exactly 10, guards): failed** (S4 lower).
Run-to-run scale for reading these: arm A (same pipeline as `c41A_tuning60` a day earlier) lists exactly 10 in 49 of
60, that run in 44.

**Per the plan:** Change 43 is removed (it failed its gate); Change 42 goes to confirmation set 3 (60 never-run cases,
drawn and committed before any run, k = 3 per arm, confirmed if S4's paired 95% CI lower bound is above 0) — both
pending the user's word. Expectation, stated before any confirmation run: with a +0.019 tuning effect and its mechanism
flat, a lower bound above 0 is unlikely.

---

## 2026-10-06 — Change 43 removed; the ceiling of 10 stays

User: "remove change 43" (it failed its gate: S4 C − B −0.035 [−0.102, +0.030]). The analysis prompt's ATT&CK item 5
returns to Change 32's "List at most the 10 most relevant techniques, most relevant first". Tests first
(`test_change43_removed.py`, 2, and Change 32's `test_the_list_has_an_end` restored; 3 seen to fail); Change 43's own
tests (`test_technique_cap.py`) deleted with it (in history at `7dd5964`). 773 pass. Checked: `prompts.py` now differs
from arm A's (`1b90c44`) only by Change 44.
**The user's concern:** without a limit the list "got stuck kinda on a loop". That is defect 19 (2026-09-24: 13 real
techniques, then 336 invented `T1562.001 … T1562.339`, 116,776 characters, until the client timeout), before Change 32
existed. Change 43 never removed the ceiling ("never more than 10"); both wordings keep it. In this run
(`count_techniques.py`): **no arm listed more than 10 in any case (max 10 in A, B and C)**; answers cut at the output
limit: A 1 case, B 0, C 0; invented IDs A 0, B 0, C 2 cases (dropped by Change 31's check). The backstops behind the
prompt's ceiling: the output limit (Change 24, 16,384 tokens, two retries) and the ID check (Change 31). There is no code
cap at 10 — the model's list is used as written.
