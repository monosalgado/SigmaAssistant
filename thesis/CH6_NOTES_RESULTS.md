# Chapter 6 — Results and Discussion: working notes

**Purpose.** Raw material for writing Chapter 6. Not prose. Organised by the sections of
`OUTLINE.md` §6. The dated, detailed record of each finding is in `ENGINEERING_LOG.md`;
every item below names its log entry or commit so any number can be traced and re-run.
The methodology behind the numbers is in `CH5_NOTES_EVALUATION.md`; limitations are in
`CH7_NOTES_LIMITATIONS.md`.

**Reading rule** (same tags as Chapter 5):
- `[MEASURED]` — produced by running something; date given.
- `[DESIGN]` — a decision, with its justification.
- `[UNMEASURED]` — not yet known. Do not write as fact.
- `[DISCLOSE]` — must appear in the thesis.

Started 2026-09-23.

---

## Throughline (a suggestion for framing, the user decides)

Most findings so far share one shape: **the pipeline produced a plausible rule without
having used its source** — the input never reached the stage that needed it (defects 8,
14, 15), a stage's answer was overridden or invented (defects 10, 11), or a failure was
swallowed and the run looked normal (defects 12, 13, 17). None of these was visible in
the output. All surfaced only by measuring. This is the outline's §6.4 argument —
"static review misses grounding failures" — and it now has numbers.

---

## 6.1 Baseline system performance — baseline v1 `[MEASURED] 2026-09-19`

`eval/results/baseline60.jsonl` · 60 cases, stratified sample (seed 0) of 303 ·
`qwen3-coder:30b` on every stage, all-local · web enrichment off · log: baseline-run entry
(2026-09-19) and Change 19 (gates).

| Metric | Result | n | Null baseline (chance) |
|---|---|---|---|
| S1 valid Sigma | 0.917 (55/60) | 60 | — |
| S2 validator issues per rule | 1.00 | 55 | — |
| **S3 logsource exact** | **0.145** (8/55), Wilson 95% CI 0.076–0.262 | 55 | **0.173** |
| S4 ATT&CK exact F1 | 0.123 | 37 | 0.092 |
| S5 detection-field F1 | 0.205 | 53 | 0.133 |
| Rules per case | 3.27 (196 total) | 60 | — |

- **S3 is indistinguishable from chance** — the interval contains 0.173. The headline
  weakness; it is what Phase 2 of the plan targets.
- S4 and S5 are above their baselines by modest margins; n is too small for fine
  comparisons.
- Scores use the **first** rule of each response (what a user sees); all rules are
  stored, so best-of-N can be computed later without a rerun. `[DESIGN]`
- The 5 S1 failures: 2 responses with no rule at all (86 characters each — see defect 17
  below), 2 malformed YAML, 1 `contains` modifier on a null value.
- **Clean vs contaminated cases** (Change 18): on the 55 clean cases every metric is
  within 0.008 of the full run (S3 0.140, S4 0.120, S5 0.208) → the headline does not
  depend on the 5 cases whose input already contained a rule.
- Cost (C1/C2): 321 LLM calls, 2,227,584 tokens (mean 37,126/case); per case median
  89.1 s, range 38.7–320.7 s; 101.9 min wall time.
- `[DISCLOSE]` Citability: **CITABLE WITH CAVEATS (2)** under `check_gates`: its PoC
  GitHub inputs were fetched live (before Change 17), and a pipeline crash would not have
  been recorded as one (before Change 14). State both with any number from this run.
- `[DISCLOSE]` It predates Change 12 (the stages now read the whole source), so it
  measures the pipeline *before* the largest grounding fix. Baseline v2 (below) is the
  first run of the current pipeline with every guard in place.

### Baseline v2 — the current reference `[MEASURED] 2026-09-24`

`eval/results/baseline60_v2.jsonl` · the **same 60 cases** as v1 (paired by rule) · same
model and settings · PoC GitHub inputs from snapshots · log: "Baseline v2 (plan 1.5)".
Verdict **CITABLE** — all seven gates pass; the first file without caveats.

| Metric | v2 | n | Null baseline | v1 → v2 on the same cases (paired) |
|---|---|---|---|---|
| S1 valid Sigma | 0.950 (57/60) | 60 | — | 55 → 57; p = 0.73 |
| S2 issues per rule | 1.11 | 57 | — | — |
| **S3 logsource exact** | **0.123** | 57 | **0.173** | 8 → 5 of 52; p = 0.45 |
| S4 ATT&CK exact F1 | 0.175 | 40 | 0.092 | +0.014, 95% CI [−0.048, +0.086], n = 35 |
| S5 detection-field F1 | 0.239 | 56 | 0.133 | +0.003, 95% CI [−0.072, +0.075], n = 51 |
| Rules per case | 4.15 | 60 | — | +0.88, CI [+0.42, +1.38] |
| Tokens per case | 53,803 | 60 | — | **+45%**, CI [+11.8k, +21.5k] |
| Seconds per case (mean / median) | 169.3 / 142 | 60 | — | **+65%**, CI [+42, +99] s |

Paired column: `eval/compare_runs.py eval/results/baseline60.jsonl eval/results/baseline60_v2.jsonl`
(Change 23; reproduces the scratch analysis exactly except the intervals' last digits).

- **No change in rule quality detectable at n = 60** between v1 and v2 — and a measured
  cost of +45% tokens and +65% time per case. S3 is still at chance.
- `[DISCLOSE]` **Read differences between runs paired.** Unpaired, S4 appears to rise
  0.123 → 0.175; on the same cases it is +0.014 with an interval spanning zero. The gap is
  which cases get scored: 5 cases score only in v2 (their first rule now parses; mean
  0.467). A good example for the methodology chapter of why paired analysis matters.
- `[DISCLOSE]` v1 → v2 is **not a single-variable comparison**: Changes 11 and 12, PoC
  inputs from snapshots instead of live, and run-to-run variation.
- `[DISCLOSE]` Not claimed: that the changes have *no* effect. 60 cases cannot detect
  small effects; the S4/S5 intervals allow about ±0.08.
- Clean cases only (55): S3 0.113, S4 0.189, S5 0.238. Flagged (5): too few to read.
- Cost detail: sum of per-case time 169 min (v1: 103 min). The run itself took about
  3 h 30 min of wall time, of which ~41 min was a network outage (CH5 notes).

---

## 6.2 Ablation findings — `[UNMEASURED]`

No ablation arm is wired yet (`--arm` is only a label). Likely core, pending the
contributions agreed with the professor: A1 (no RAG), A5 (single prompt vs the pipeline),
and a naive baseline (most common logsource, no LLM).

One arm-like measurement exists, on one stage only — the source window (§6.4.2).

---

## 6.3 Cost–quality Pareto — blocked `[DISCLOSE]`

Contribution 2 compared cloud (Gemini) and local (Ollama) tiers. The Gemini key was
suspended (2026-09-11) and deleted (2026-09-23), and the user decided to run every stage
on `qwen3-coder:30b`. Without a second tier there is no routing trade-off to measure.
What remains measurable: tokens and time per stage (stage labels since Change 13), and
the cost of each fix — e.g. Change 12: +26% time on its two stages alone; end to end,
v1 → v2 +45% tokens and +65% time per case with no detectable quality change (§6.1).

---

## 6.4 Defects found by systematic evaluation

Grouped by what went wrong. Evaluation-harness problems (defects 12, 14, 16, 17 and the
contamination finding) are in Chapter 5 §5.9; this section is about the **pipeline**.

### 6.4.1 The input never reached the stage — intent misrouting (defect 8) `[MEASURED] 2026-09-13`
- A bare URL (28 of 30 real user inputs in `data/sessions.json`) has no instruction verb,
  and the intent classifier's few-shot examples contained no URL. **17 of 30 (57%)** real
  CTI URLs were routed to "question"/"chat", which answers **without fetching the page**
  — yet still emits a plausible Sigma rule, written from the URL string alone
  (Wilson 95% CI ~36–70%).
- Fix: a deterministic short-circuit for bare URLs before any LLM call. After: **30/30**
  routed correctly; 5/5 regression probes (questions, refinements, a question *about* a
  URL) still classified by the model.
- Consequence: **every harness number from before `8184050` is invalid.**
- Log: Change 8 (`8184050`).

### 6.4.2 The stage read navigation, not the article — fixed source windows (defect 15) `[MEASURED] 2026-09-23`
- The analysis stage read only the first **4,000** characters of the extracted text, the
  attack-vector stage the first **8,000**. Across all 303 cases the text fits entirely in
  those windows in **23 (8%)** and **66 (22%)** cases (median length 19,158 characters,
  max 79,800). On many pages the window held only site navigation (inspected by hand:
  GitHub page chrome, vendor menus, marketing blocks).
- Symptom: the attack-vector stage **reproduced its own prompt's worked examples** —
  e.g. "unauthenticated HTTP POST to /saml/login with a crafted SAMLRequest" for a Windows
  "defrag" rule whose source never mentions SAML. Pre-registered criteria, same 60 cases:
  example content absent from the input in **13/60** outputs (21.7%, CI 13.1–33.6%),
  **11/60 in the attack vector itself**; 37% of cases without PoC code vs 9% with.
- Fix (Change 12): both stages read the whole source up to a stated bound of 100,000
  characters. Re-measured on the same cases, paired: copying **into the attack vector
  11 → 4** (8 fixed, 1 new, **exact McNemar p = 0.039**); anywhere in the output 13 → 10
  (p = 0.55; the rest mostly patch filenames in an "incidental" list). Cost: +26% time on
  those stages; median input 8.5k → 22.4k characters.
- `[DISCLOSE]` Only the attack-vector stage was re-measured; the analysis stage's effect
  on S1–S5 needs baseline v2.
- `[MEASURED] 2026-09-24` Baseline v2 (whole-source stages, all 60 cases): **no detectable
  change on S1–S5** (paired; §6.1), at +45% tokens and +65% time per case. Less copying
  did not measurably improve agreement with the human rules. Copying persists: in v2 a
  Windows kernel-rootkit report still got the `/saml/login` entry point of Example A.
- Why the examples were copyable: the worked examples were written from specific past
  cases — `data/saved_rules.json` holds the real "CVE-2026-3055 Citrix NetScaler SAML …
  NSC_TASS" rule the SAML example came from.
- `[MEASURED] 2026-09-26` **Replacing the example moved the copying** (Change 27;
  `eval/count_example_copies.py`, committed and run on the reference before the run): the old
  SAML example's text in the vector itself **4 → 0**; the new email/ISO/LNK example's text
  **0 → 2** — the Qakbot and Emotet-LNK reports received its initial-access sentence word for
  word and its invented `qx7loader.dll` / `QxUpdate`. Total in the vector itself 4 → 2.
- `[MEASURED] 2026-09-26` The copied names **reach the generated rules** (`in_rules`, added to
  the committed counter the same day; first found by a one-off search): the new example's
  names in the rules of those 2 cases; the old example's strings in the rules of 4 cases in
  baseline v2 and in step (c). **Every example copied into the vector also reached the rules**
  (10 of 10 case-runs). Retrieval is ruled out as a source: no marker occurs in any retrieval
  collection. Detection strings for files that do not exist; S3 cannot see them.
- For the thesis: with this model, a concrete worked example is copied into reports that
  resemble it. Which example is copied depends on which reports look like it; changing the
  example does not remove the behaviour. Defect 15 stays open (options in the plan).
- Log: defect-15 measurement entry and Change 12 (`ac725e1`, `f9b64f1`); "Change 27 measured".

### 6.4.3 A bias the window did not fix — web telemetry for host rules `[MEASURED] 2026-09-23`, reduced 2026-09-26 (Change 27)
- After Change 12, the attack-vector stage still names `webserver_access_log` as primary
  telemetry for **21 of 48** cases whose gold rule is not a web or proxy rule (23 before;
  p = 0.69, unchanged).
- `[UNMEASURED]` Hypothesis: two of the three worked examples are web exploits, and the
  field is defined as where "the initial exploit" is visible, while many gold rules
  detect post-exploitation behaviour on the host. Plan task 2.3.
- `[MEASURED] 2026-09-24` In the full pipeline (baseline v2, plan 2.1): web telemetry for
  **16 of 46** non-web gold cases — and the generated rule lands on web telemetry in the
  same 16 of 46. (Different run and denominator from the 21/48 above; not directly
  comparable.) The bias reaches the rule — see §6.4.4.
- `[MEASURED] 2026-09-24` After Change 22 the bias flows through real category names:
  attack-vector web 18 of 44 non-web cases (unchanged stage; first written "of 46" — corrected
  2026-09-26, log "Correction: two … denominators"), **analysis top suggestion web
  4 → 11**, rule web 18. Fixing the vocabulary made the bias visible; it now has to be fixed
  at its source (plan 2.3, step d).
- `[MEASURED] 2026-09-26` **Change 27 (examples rebalanced, `primary_telemetry` redefined as
  where the described activity is seen), measured** against the Change 26 run
  (`p2d_web_bias60.jsonl`, CITABLE, measures fixed before the run):
  - attack-vector web on non-web gold **18/48 → 14/45** (primary); first rule web
    **16/48 → 8/45**; analysis top suggestion web 10/48 → 7/45;
  - **S3 13 → 13 of 54** (2 gained, 2 lost, p = 1.0); S1, S4, S5 no detectable change; no
    web gold case lost its web label (the risk stated before the run).
  - `[DISCLOSE]` These counts are over cases whose first rule parses, so the denominators
    differ between runs. Read case by case, only 4 cases changed web ↔ non-web (3 off web,
    1 on); the rest of the drop is two web-labelled cases whose first rule stopped parsing.
    Not tested paired.
  - The 2 S3 gains are relabelled cases (web → `process_creation`); the 2 losses are the new
    definition read reasonably ("a dropper drops a DLL" → `file_event`) where the gold rule
    is `process_creation` (read by hand).
  - For the thesis: **the web bias was real and is reduced, but it no longer limited S3.**
    Status: reduced; the remaining S3 limit is the analysis suggestion (plan 2.6).

### 6.4.4 A correct suggestion overridden — generation ignores the logsource suggestion (defect 11), open, measured 2026-09-24
- `[MEASURED]` Observed live (Bumblebee report, 2026-09-13): the analysis stage suggested
  `process_creation / windows / sysmon` at 0.95 confidence; the generated rule used
  `webserver_access_log` and described an attack the report does not contain. Seen again
  2026-09-14.
- Mechanism (corrected 2026-09-23): the suggestion *does* reach the generation prompt,
  but appended to the end of the Sysmon reference block (`stage_generate.py:273`) —
  buried in reference material, not an instruction.
- `[MEASURED] 2026-09-24` **How often — and why S3 is at chance** (plan 2.1,
  `eval/diagnose_logsource.py` on baseline v2, category level, n = 57, buckets fixed
  before counting):
  - the analysis stage's top suggestion has the right category in **29 of 57**;
  - generation **keeps it in 15 and overrides it in 14** — about half of the correct
    suggestions are lost at the last step;
  - where the analysis is wrong (27), the gold was offered 2nd/3rd in 7; generation
    rescues a wrong suggestion once.
  - The failing field is the category (16/57 right), not the service (alone wrong in 1).
- `[MEASURED]` post-hoc — **two vocabularies**: the rule's category is the attack-vector
  stage's own telemetry label, verbatim, in **24 of 41** wrong rules (10 of the 14
  overrides); **17 of 41** wrong rules use a category no SigmaHQ rule uses
  (`webserver_access_log` 15). The attack-vector stage picks from 13 labels of its own,
  not Sigma categories, and generation copies them. A rule with such a category can never
  match anything.
- `[MEASURED]` post-hoc — **the suggestion is not usable as-is**: had the rule copied the
  top suggestion verbatim, S3 would be **0 of 57** — its `service` is `sysmon` in 44 cases
  (the analysis prompt's only example uses `service: sysmon`; SigmaHQ's Sysmon-based rules
  carry only category and product). Category and product both right in 18 of 57.
- Mechanism `[DESIGN — inspected]`: generation rule 2 makes an initial-access rule
  "MANDATORY" with a logsource matching "the telemetry where that traffic is observed",
  and the attack-vector summary ("Primary telemetry: …") sits near the top of the prompt;
  the analysis suggestion is buried in the Sysmon block. The prompt ranks the attack
  vector above the analysis.
- For the thesis: this is the §6.4 throughline again — a stage got it right and a later
  stage overrode it, silently. Also a prompt-example copy (`service: sysmon`), the same
  pattern as defect 15.
- `[DISCLOSE]` The post-hoc measures were chosen after seeing the data: descriptive, they
  motivate the Phase 2 changes; they do not test a hypothesis.
- `[MEASURED] 2026-09-24` **Change 22 (one vocabulary), measured** — the attack-vector
  label now reaches later stages as a Sigma category (`p2a_vocabulary60_r2.jsonl`, CITABLE,
  paired against v2, measures fixed before the run):
  - wrong rules with a category no SigmaHQ rule uses **17 → 1** (primary measure);
  - generation overrides a correct suggestion **14 → 3**;
  - **S3 exact 6 → 11 of 52 on the same cases, 0 lost, p = 0.062** — one-directional, not
    significant at 0.05. Unpaired 0.208 (11/53) vs chance 0.173: above chance for the
    first time, not distinguishably so;
  - S4 +0.019, S5 +0.030 (both CIs span zero); cost unchanged.
  - For the thesis: a *wording* change between two stages — no new information — removed
    most overrides. The stages were not disagreeing about the attack; they were using
    different words for the same log source.
  - `[DISCLOSE]` S1 fell 57 → 53 (p = 0.22): 3 malformed YAML, 2 generation-JSON parse
    failures (defect 5); none involves the output limit.
- `[MEASURED] 2026-09-25` **Change 25 (no service next to a category), measured** against the
  Change 22 run (`p2b_service60.jsonl`, CITABLE, measures fixed before the run):
  - the suggestion's service matches the human rule **0/53 → 51/58**; S3 had the rule copied the
    suggestion **0/53 → 15/58** — the prerequisite for step (c);
  - S3 paired 11 → 8 of 53 (3 lost, p = 0.25), stated expectation "little change" held within
    noise; 2 of the 3 losses are the rule writer inventing `category: email` over a correct
    suggestion — the override step (c) targets.
  - Finding: the analysis stage never suggests a log source *without* a category; the 6 gold
    rules defined by a service (e.g. Windows Security) are always missed there.
- `[MEASURED] 2026-09-25` **Change 26 (the prompt recommends the analysis's log source for the
  first rule; nothing enforced), measured** (`p2c_first_rule60.jsonl`, CITABLE):
  - first rule follows the suggestion **24/58 → 44/57**; overrides 6 → 2; non-Sigma categories 3 → 0;
  - **S3 9 → 14 of 56, 0 lost (p = 0.062)**; **S5 +0.075, 95% CI [+0.008, +0.146]** — the first
    quality interval that excludes zero; S4 unchanged;
  - cumulative vs baseline v2: **S3 7 → 14 of 55, 0 lost, p = 0.016** — `[DISCLOSE]` four paired
    comparisons in Phase 2, so not conclusive alone (Bonferroni threshold 0.0125); not yet
    tested against the chance level (14/57 = 0.246 vs 0.173).
  - For the thesis: **the stages were right more often than the rules showed** — once the
    rule writer is told to use the analysis's log source, S3 approaches what the suggestion
    allows (16/57). The bottleneck has moved upstream, to the suggestion itself.
  - The model ignored the instruction to explain a departure (0 of 12) — relevant to the
    assistant's promise of explanations: they have to be asked for differently, or produced
    by a separate step.
- `[MEASURED] 2026-09-26` **Change 28 (the analysis prompt's table generated from SigmaHQ's
  main rule set: every category and service-based source, with their fields), measured**
  (`p2e_table60.jsonl`, CITABLE, measures fixed before the run, all 60 rows counted):
  - **top suggestion = gold log source 13 → 23 of 60 (12 gained, 2 lost, exact McNemar
    p = 0.013)** — the step's pre-registered primary; web gold 0 → 9 of 12; suggestions that
    are real SigmaHQ log sources 39 → 59 of 60;
  - **S3 on the rule 12 → 13 of 53 (p = 1.0)**; first rule follows the suggestion 47 → 35;
    S1, S4, S5 no detectable change.
  - Why (read case by case, post-hoc): in 6 of the 9 web gold cases with a right suggestion the
    rule writer **adds a product** (`fortigate`, `iis`, `sitecore`, `webserver`…) — it reads
    `product` as the attacked application, while SigmaHQ's web rules carry none; 2 more first
    rules do not parse. The service form (Windows Security…) was never suggested (0 of 60).
  - For the thesis: the throughline again — the analysis stage is now right far more often,
    and a later stage rewrites part of its answer. `[DISCLOSE]` one run, on the tuning cases.

### 6.4.5 A field invented instead of generated — rule identifiers (defect 10) `[MEASURED]`
- The model emitted UUID-shaped ids with non-hex characters
  (`5a3b4c5d-6e7f-8g9h-…`); pySigma rejects the whole rule at parse time, so S1 fails and
  S2–S5 become undefined for a rule whose detection logic may be fine — a
  measurement-integrity problem before a product one.
- Fix: ids validated and assigned in code (Change 9, `73d8446`). One demo run replaced
  9 of 9 ids.
- `[MEASURED] 2026-09-24` The rate, from baseline v2: **186 of 417 generated rules (45%)**
  had their id replaced by code, in 44 of 60 cases. The record counts invalid and missing
  ids together, so how many would have failed to parse without Change 9 is not known (an
  invalid id fails; a missing one does not — `id` is optional in pySigma).

### 6.4.6 One malformed rule lost the whole answer (defect 13) `[MEASURED]`
- A malformed condition (`Expected end of text, found '*'`) made pySigma's validator suite
  raise outside any guard; the request died and all 3 generated rules were lost (Microsoft
  "Prestige" report, 2026-09-14).
- The first recorded mechanism was **wrong**; a reproduction showed the raise came from a
  core validator re-parsing the condition, not from the loop first blamed. Worth one
  sentence: reproduce before recording a mechanism.
- Fix: Change 11 (`663f005`). Frequency: 1 live observation; 0 in 60 harness cases.

### 6.4.7 Found by code audit, before the harness existed `[DISCLOSE]`: quality effect unmeasured
- **pySigma installed but unused** (Change 1, `a1c4f37`): validation was hand-rolled.
  Differential testing against pySigma showed the old code **rejected valid rules**
  (it required `level`, which the Sigma spec makes optional) and missed dangling
  condition references.
- **RAG exemplars were Python dict reprs, not YAML** (Change 2, `d9d9e3f`): the model was
  asked for YAML while every retrieved example was `repr` output. Also: 3,103 of 3,104
  rules carry MITRE tags but the field was never embedded, so no exemplar ever showed one.
- **Corpus filtered to Windows only** (Change 2): the filter excluded **722 of 3,104
  parseable rules (23.3%)** — an earlier verbal estimate of "42%" was wrong. Collection
  2,382 → 3,104 rules.
- All three landed before measurement was possible; write them as *defects identified by
  audit*, not as improvements, unless an ablation measures them.

### 6.4.8 A generation that never ends (defect 19) `[MEASURED — diagnostic]` 2026-09-24, open
- Case `9a2d8b3e` (Check Point "Stealth Falcon") under Change 22: the analysis call never
  finished — 3 × 600 s timeouts, on every attempt across two runs. A streamed probe of the
  same request (first token after 5.3 s, so not queued) produced **116,776 characters in
  722 s** until a 30,000-token cap: 13 real ATT&CK techniques, then **336 invented ones in
  sequence, `T1562.001` … `T1562.339`**. In baseline v2 the same call ended at 4,637 tokens.
- Mechanism: no LLM call sets an output limit, and the prompt asks for an unbounded list.
  At temperature 0 a retry repeats the loop, so the run stops at the same case every time
  (CH7 item 28, now observed). In the web app the user waits ~30 min, then gets rules built
  on an empty analysis.
- `[UNMEASURED]` Likely the same loop, not shown: baseline v2's hung case 52, and two
  analysis calls of ~690 s (a timed-out first attempt, then a normal retry).
- For the thesis: another silent failure, this time of the model rather than the code — and
  a small, meaning-preserving prompt change (Change 22) was enough to trigger it on one case.
- `[DISCLOSE]` The probe is a scratch diagnostic; a committed version must reproduce it
  before its numbers are cited.
- Fix: Change 24 — every answer bounded at 16,384 tokens (above the longest finished
  answer in v2, 12,374), a cut answer retried twice, then recorded as the model's failure
  and measured with the case. Bounds the time; does not prevent the loop. Two follow-ups
  change finished answers and get their own runs: drop technique IDs that do not exist in
  ATT&CK (plan 2.2e), and at most 10 techniques per analysis (2.2f).

### 6.4.9 Open, not yet measured
- Defect 9: page extraction yields near-zero text on some pages; navigation boilerplate
  survives extraction (the extractor removes `nav`/`header` tags, but many sites build
  menus from generic elements). Plan 2.4 — dropped 2026-09-24 (2.1 found nothing pointing
  to it).
- Defect 4: the coverage check that triggers regeneration is substring matching.
- Defect 5: `json_mode=True` on the generation stage (Tam et al. predicts a reasoning
  cost).
- Defect 6: the `fast` tier is dead code.

---

## 6.5 A negative result — the security-pretrained model (contribution 3, dropped) `[MEASURED] 2026-09-23`

> **Not used in the thesis** (user, 2026-09-25: "We are not going to use Foundation-Sec at all"). Kept as history only; do not write it up.

- The installed `foundation-sec:8b` is the **base** model (completion only, no chat
  template), not Instruct. On the attack-vector stage (3 real cases, the pipeline's own
  prompt): via the chat endpoint it returned only `<|im_end|>`; via raw completion,
  1 empty token; with JSON forced by grammar, **the identical 294-token copy of the
  prompt's first worked example, 3 of 3**, ignoring the source.
- Both variants document a **4,096-token** sequence length. The pipeline's prompts
  (baseline v1, 321 calls): median 4,539 tokens, p90 10,492, max 46,199 — **61% exceed
  4,096**, 24% exceed 8,192. Per stage (18 four-call cases), median prompt: attack vector
  4,405 · analysis 4,056 · generation 8,339 · review 3,008 tokens.
- Outcome: user decision to keep every stage on `qwen3-coder:30b`; contribution 3 off
  the table unless reopened.
- `[DISCLOSE]` This tested the base model with prompts designed for an instruction
  model; it is not evidence about Foundation-Sec-8B-Instruct, which was not installed.
- `[DISCLOSE]` Traceability is weaker than elsewhere: the probe ran from scratch scripts
  that were **not committed**, and the engineering log mentions it only in passing (the
  defect-15 measurement entry). The numbers above are the record. If this result goes
  into the thesis, rerun it from a committed script first (see the plan's Inbox).
- Prompt sizes come from `eval/results/baseline60.jsonl` (`llm_calls[].prompt_tokens`)
  and can be recomputed from it.

---

## 6.6 Smaller observations worth a sentence each

- `[MEASURED]` Only **26.6%** (54/203) of the "quotes" the attack-vector stage gives as
  evidence appear verbatim in its input (25.6% after Change 12). An upper bound on
  invention — honest paraphrase also misses — but it motivates checking quotes in code
  (plan 3.3).
- `[MEASURED]` Link rot during the project: 10 of 45 GitHub files linked from the corpus
  were already gone (2026-09-23); earlier, 12 of 437 reference pages returned 404.
- `[MEASURED]` Per-stage cost is now attributable (Change 13): the first stopped live
  run named `analysis, attack_vector, generation, poc_analysis` as the failing stages.
