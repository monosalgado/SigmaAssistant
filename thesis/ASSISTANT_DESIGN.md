# Assistant redesign — backend design notes

Status: **Reviewed with the user 2026-09-26** (decisions in §9); nothing of Phases A–C built yet.
Started 2026-09-23.
Working notes, not thesis prose. Every claim about current code was verified by
reading it on 2026-09-23; file:line references are to commit `9eb816d`.

---

## 1. Goal

Turn SigmaAssistant from a tool that returns rules into an assistant that:

1. **Explains** — reports what it found in the source and why each rule is built
   the way it is: the attack vector, the log source, the indicators, the ATT&CK
   techniques, and where in the source each of these came from.
2. **Asks the analyst to confirm** — every one of those facts can be accepted,
   edited or rejected before any rule is written.
3. **Generates from the confirmed facts** — the rules must actually obey them.
4. **Lets the analyst edit the rule** — with immediate validation of the edit.

---

## 2. What already exists (verified)

A first attempt at step 2 is in the code but was never connected.

| Piece | Where | State |
|---|---|---|
| `feedback_request` SSE event carrying indicators, TTPs, logsource suggestions and the attack summary | `orchestrator.py:321-328` | emitted, then the pipeline **continues without waiting** |
| `_apply_user_feedback()` — confirmed logsource, removed/added indicators, free-text notes | `orchestrator.py:475-520` | works, but only on `feedback_data` supplied **at the start** of a request |
| `feedback_data` field on the request | `main.py:114` | **no client ever sends it** (`grep feedback_data frontend/` = nothing) |
| UI preview panel | `script.js:593-643` | display only: "This preview is informational. The pipeline will continue automatically." |
| "User confirmed primary log source … USE THIS" prompt text | `stage_generate.py:248-249` | unreachable in practice, since nothing sets `user_confirmed` |
| Saved-rule editing | `main.py:355` `PUT /rules/{id}` | saves **without validating** — an edited rule can be stored broken |
| `UserFeedback` schema | `schemas.py` (removed 2026-09-23) | was defined but never used; the whole file had drifted from the real pipeline output |

### Why it cannot simply be wired up as it is
Corrections are applied at the start of a **new** run. That run re-executes every
analysis stage, and LLM output is not deterministic, so the analyst would be
correcting facts from run 1 that are then applied on top of **different** facts
from run 2 — facts they never saw. It also pays for the whole analysis twice.
A real confirmation step needs the pipeline to **stop and keep its state**.

### A correction to earlier notes on defect 11
The logsource suggestions **do** reach the generation prompt. They are appended
to the end of the Sysmon reference block (`stage_generate.py:273`,
`sysmon_context + logsource_text`), not given their own slot. The observed
behaviour stands (generation follows `attack_vector` instead), but the likely
cause is that the recommendation is buried inside reference material rather
than absent. That changes the fix: it must become an explicit constraint, and
be checked after generation.

**Done since (Phase 2, 2026-09-24/25):** Change 22 (the attack-vector label reaches later
stages in Sigma's terms), Change 25 (a suggested log source with a category carries no
service; an unknown service without a category is marked `service_to_confirm` for the
analyst, the removed value kept in `service_dropped`), Change 26 (the analysis stage's log
source has its own slot at the top of the generation prompt as a *recommendation*; when
`user_confirmed` is set, that slot says "confirmed by the analyst"). Measured: the first
rule follows the recommendation in 44 of 57 cases (was 24 of 58).

---

## 3. Design principles (the defensible part)

**P1 — The report shows what the pipeline actually computed. It is not a new
"explain yourself" LLM call.** A separate explanation call produces a
justification written after the fact, which may not match what drove the rule.
Rendering the stage outputs that were really passed to generation makes the
report faithful by construction. This is the first question a committee will
ask about any explanation feature.

**P2 — Every fact carries evidence that code can check.** Each fact gets a
quote from the source. Paraphrase is acceptable if it is faithful to the page (user,
2026-09-25); code checks whether the quote appears in the fetched text (after
whitespace/case normalisation) and marks it **"verified"** when it does — an unmatched
quote is shown as the model's wording, not hidden or rejected. Today ~26% of quotes
are verbatim. That catches invented facts without a
second model, and it is measurable (§7).
Note: today's indicator `context` field is a paraphrase by design — the few-shot
examples in `prompts.py:97-115` model it that way — so it cannot serve as
evidence. This needs a new field and a prompt change.

**P3 — Rule-to-fact traceability is computed, not narrated.** Which confirmed
indicator values appear in a rule's `detection:`, whether the rule's `logsource:`
equals the confirmed one, which ATT&CK tags match — all string comparisons.
The model's own `explanation` stays, labelled as the model's words.

**P4 — What the analyst confirms is final; what the model suggests is a
recommendation.** (Decision 1, user 2026-09-26.) The model's own suggestions are
recommendations the rule writer may depart from (Change 26; user: "I want them to
think" — no hardcoding for results). A fact the **analyst** confirmed is different: a
human decided. If the analyst confirmed `process_creation/windows` and the rule says
`webserver`, code detects the violation, the model rewrites the rule **once** with the
reason, and if it still violates, the report shows the violation plainly. Code never
edits the rule itself.

**P5 — The automated path stays measurable.** The harness keeps calling one
function that runs analyse → auto-accept everything → generate. With
auto-accept, behaviour must match today's, so the **final Phase 2 run** stays the valid
comparison point. Every behaviour-changing step is measured against it.

---

## 4. Shape: three phases with a checkpoint

```
            ┌──────────── Phase A: ANALYSE ────────────┐
URL/text ──►│ preprocess → web enrich → PoC → attack   │──► Analysis Report
            │ vector → analysis (+ evidence check)     │    + saved state (analysis_id)
            └──────────────────────────────────────────┘
                                 │
                   analyst reviews: accept / edit / reject each fact
                                 ▼
            ┌──────────── Phase B: GENERATE ───────────┐
confirmed ─►│ generate (confirmed facts as constraints)│──► Rules + traceability
facts       │ → review → coverage → constraint check   │    + validation results
            └──────────────────────────────────────────┘
                                 │
                   analyst edits the YAML
                                 ▼
            ┌──────────── Phase C: REFINE ─────────────┐
edited ────►│ deterministic validation (pySigma), no   │──► issues shown immediately
YAML        │ LLM; optional "ask assistant to revise"  │
            └──────────────────────────────────────────┘
```

- Phase B reads Phase A's **saved** state — no re-analysis, no second cost.
- `run_sync` (harness) = A → auto-accept → B, unchanged behaviour (P5).
- Phase C's validation reuses `stage_review._validate_rule`, so the analyst
  gets the same pySigma checks the pipeline uses — and it needs no VPN.

---

## 5. The Analysis Report (data contract — first draft)

Every fact shares one shape:

```
Fact
  id            stable within one analysis, e.g. "ind-3"
  kind          attack_vector | indicator | technique | logsource | ...
  value         the claim itself
  confidence    as reported by the stage (never invented by the report)
  reasoning     the stage's own reasoning text, where it has one
  evidence      [{quote, source_url, verified: bool}]
  status        proposed | accepted | edited | rejected
  origin        model | analyst
```

Report sections, in reading order:

| Section | Filled from | Notes |
|---|---|---|
| Sources read | `preprocessed.url_content` | URL + characters extracted. **Surfaces defect 9**: a page that yielded ~0 chars is shown, not hidden |
| Attack summary | `extraction.attack_summary` | prose, not a fact to confirm |
| Attack vector | `attack_vector` (initial access, vuln class, protocol, confidence, reasoning) | one editable fact |
| Payload signatures | `attack_vector.payload_signatures` | editable list |
| Excluded artifacts | `attack_vector.incidental_artifacts` | shown with *why* they were excluded — the analyst can restore one |
| Indicators | `extraction.indicators` | editable list; analyst can add |
| ATT&CK techniques | `ttp_mapping.mappings` | editable list |
| Platform | the chosen log source's `product`/`category` | stated in plain words — "Windows — process creation", "web server" (user's idea, Phase 0 option D) |
| Log source | `logsource_suggestion` (ranked suggestions + primary) | **the analyst picks one** — becomes a constraint (P4). Shows `service_dropped` ("removed: Sigma rules with a category carry no service") and asks about any `service_to_confirm` |
| Web enrichment | `enrichment.sources` | empty on the all-local setup; say so explicitly rather than show nothing |
| Stage failures | telemetry `output_limited` (Change 24) | if an answer was cut at the output limit and the stage fell back, say so ("the analysis could not finish; these facts are missing") rather than show an empty section |

After Phase B, each rule gets a **traceability block** (P3): logsource matches
confirmed (yes/no), confirmed indicators used / not used, techniques tagged vs
confirmed, coverage warnings, validation issues.

---

## 6. API (first draft)

| Endpoint | Phase | Notes |
|---|---|---|
| `POST /assist/analyze` (SSE) | A | stage progress events, then the report + `analysis_id` |
| `POST /assist/generate` (SSE) | B | `{analysis_id, decisions}` → rules + traceability |
| `POST /assist/validate` | C | `{yaml}` → pySigma issues. No LLM, instant |
| `POST /assist/revise` | C | `{analysis_id, yaml, instruction}` → the model rewrites the rule from a plain-words instruction, then pySigma validates it. **In scope, built after manual editing** (decision 3) |
| `POST /assist/convert` | C, pending | `{yaml, backend}` → a SIEM/EDR query (e.g. Splunk, Sentinel, Elastic). **Pending Phase 0 (option D) and the user's approval of new pySigma backend packages** (decision 4) |

The existing `/analyze_stream` stays working until the new UI replaces it.
`PUT /rules/{id}` should also validate (it currently does not).

**State.** Phase A's context must survive until Phase B. **Decided (2): stored in the
session record already persisted to `data/sessions.json`** — reviewing can take a while,
and a page reload must not lose the analysis.

---

## 7. What this adds to the evaluation

| Measure | Automated? | What it shows |
|---|---|---|
| Regression: auto-accept rerun of the 60 cases vs `baseline60` | yes | the refactor did not change behaviour (P5) |
| **Evidence verification rate** — share of report facts whose quote is found in the source | yes | how often the analysis states things the source does not say |
| **Report accuracy vs gold** — the report's logsource and techniques scored against the gold rule, separately from the rule's | yes | separates "analysis wrong" from "analysis right, generation ignored it" — diagnoses defect 11 directly |
| **Constraint adherence** — share of rules that obey the confirmed logsource | yes | whether P4 works |
| **Simulated analyst ("oracle confirmation")** — confirm the gold logsource / techniques instead of the model's, regenerate, rescore S3–S5 | yes | the upper bound on what the confirmation step is worth, without a user study |
| ~~Small user study~~ | — | **Dropped by the user (2026-09-23).** The simulated analyst above is the substitute; the limitation (it shows what confirmation is worth *when the analyst is right*) goes in Chapter 7 |

---

## 8. Build order (small, separately verified changes)

Each step is one change, tested offline, logged, committed. ★ = changes model
behaviour and needs a 60-case rerun (~3 h 20 min since Change 12, VPN) to measure.

1. ~~**Fix defect 13**~~ — DONE `663f005` (Change 11). The raise was in the
   validator suite, not the condition loop as first recorded.
2. **Report builder** — a pure function from the existing pipeline context to
   the report of §5. No behaviour change; fully offline tests.
3. **Split the orchestrator into Phase A / Phase B** with `run_sync` unchanged.
   Offline tests with a fake client asserting the same call sequence.
4. ★ **Evidence quotes + verifier** — new `evidence` field in the attack-vector
   and analysis prompts, and the deterministic check.
5. ★ **Confirmed logsource as a constraint** — the prompt slot is done (Change 26); what
   remains is P4's check for *analyst-confirmed* facts (one rewrite, then show). Then the
   oracle-confirmation experiment.
6. **API endpoints** + saved state.
7. **Phase C** — `/assist/validate`; make `PUT /rules/{id}` validate; flag logsource
   categories that do not exist in Sigma (former plan step 2.5); then `/assist/revise`.
   `/assist/convert` only if Phase 0 agrees.
8. **GUI** — built against the settled contract.

Steps 4 and 5 both change prompts. Measuring them separately costs two runs but
keeps each effect attributable; measuring them together is cheaper but
confounded. Recommendation: separately.

---

## 9. Decisions (user, 2026-09-26)

1. **Analyst-confirmed facts are final** (P4): violation detected by code → one rewrite by
   the model with the reason → still violating → shown plainly. Model suggestions stay
   recommendations (Change 26).
2. **Phase A state lives in the persisted session** (`data/sessions.json`).
3. **"Ask the assistant to revise this rule" is in scope**, built after manual editing +
   validation. pySigma validation itself is automatic on every edit — no button.
4. **SIEM/EDR query conversion** is in the design as `/assist/convert`, pending Phase 0
   (option D) and approval of new pySigma backend packages.
5. GUI technology: decided in Phase 4 (plan 4.0).
6. Still open: the professor's sign-off on the reframing (Phase 0). No user study (decided
   2026-09-23).

---

## 10. Risks

- Evidence quotes lengthen the analysis output → more tokens and latency. It
  will show up in C1/C2; measure it, don't assume it.
- Verbatim-quote matching can false-negative on text that extraction altered
  (whitespace, HTML entities, line breaks). The normalisation needs its own tests
  on real snapshots before the rate is cited.
- A constraint the model keeps violating could trigger a regeneration loop.
  Keep the existing global cap of one regeneration per request.
- The model does not reliably explain itself when asked: in the Change 26 run it
  explained none of its 12 departures from the recommended log source. Supports P1 —
  explanations come from computed traceability, not from the model's narration.
- Answers can loop until the output limit (13 cut calls over two runs, all in the
  analysis stage). The report must show a stage that could not finish (§5).
