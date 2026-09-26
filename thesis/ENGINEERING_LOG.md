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
