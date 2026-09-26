# Prompt review — 2026-09-26

Requested by the user ("profoundly analyze the prompts we are using; how can they improve?").
Written during the Change 29 run; nothing in `backend/` was changed for it. Every number is
from the committed result files or the code, with its source; `[MEASURED]` = counted,
`[READ]` = read case by case in a run log or file (not a committed measure), `[HYPOTHESIS]` =
not measured. Proposals are candidates, each with the measure that would judge it — none
is applied until the user decides.
**Provenance:** the `[MEASURED]` counts below were made with one-off scripts over the
committed result files (tags, validation issues, copies of the example id) or read from the
local run logs (regenerations). They guide this review; before any is cited in the thesis it
needs a committed measure, like every other number.

---

## 1. What the pipeline actually sends to the model

| Prompt | Stage | Temp. | Prompt tokens, median / max | Answer tokens, median / max | Calls in 60 cases |
|---|---|---|---|---|---|
| `ATTACK_VECTOR_EXTRACTION` | attack vector | 0.0 | 8,530 / 20,992 | 561 / 1,570 | 60 |
| `POC_CODE_ANALYSIS` | PoC (only when code is found) | 0.0 | 1,338 / 4,171 | 637 / 1,547 | 33 |
| `COMBINED_ANALYSIS` | analysis | 0.0 | 10,553 / 22,956 | 2,194 / 16,384 (cut) | 61 |
| `RULE_GENERATION` | generation | **0.3** | 10,935 / 25,855 | 1,380 / 3,628 | **103** |
| `COMBINED_REVIEW` | review — **its rules are the ones scored** | **0.2** | 3,651 / 9,742 | 1,551 / 3,508 | 72 |
Source: `p2e_table60.jsonl` (`llm_calls`); temperatures from the `llm_call` sites.
Not in the evaluated path: `INTENT_CLASSIFICATION` (a bare URL bypasses it, Change 8 — every
eval input), `IMAGE_TRANSCRIPTION` (disabled all-local), `CONVERSATIONAL` (chat only), and an
LLM-based Sigma→LEQL translator in `backend/translation/` used by the web app.
**Dead:** `ENTITY_EXTRACTION`, `TTP_MAPPING`, `RULE_VALIDATION`, `RULE_OPTIMIZATION`,
`WEB_SEARCH_QUERIES` — defined, never used (housekeeping, like H7).

---

## 2. Five patterns across the prompts

### P1. The hand-written example outweighs everything else in the prompt `[MEASURED]`
The clearest measurement: **tactic tags.** The rule writer's one worked example tags
`attack.credential_access` (underscore). Every generation prompt also carries 3 real SigmaHQ
rules from retrieval, and **all 3,021** multi-word tactic tags in SigmaHQ's main set use
hyphens (`attack.credential-access`), as do all 389 in the gold rules. Result: **137 of 143**
multi-word tactic tags in the last run's rules use the underscore (baseline v2: 152 of 166) —
committed measure `eval/count_rule_conventions.py` (a first one-off count, which also matched
text outside `tags`, gave 143 of 150). pySigma flags each one — "Invalid MITRE ATT&CK tagging"
is **the most frequent issue in the run (136)**, fed to the review model as noise. S4 is unaffected (it compares
techniques only), but every rule breaks SigmaHQ's current convention.
The same pattern, earlier: `service: sysmon` from the analysis example (44 of 57 suggestions in
v2); the table cell "linux-windows/apache-iis" (16 suggestions in step d); the attack-vector
examples copied into look-alike reports (defect 15); the example's placeholder rule id
`12345678-1234-…` copied 0–5 times per run — a *valid* UUID, so Change 9 does not replace it
and rules end up sharing an id.
**Lesson:** for this model the worked examples are the strongest lever in every prompt —
stronger than retrieved real rules and stronger than written instructions. They must follow
SigmaHQ's current conventions exactly and contain nothing that belongs to one case.

### P2. Model-made intermediate results are handed on as facts `[MEASURED]` + `[READ]`
- The generation prompt introduces the attack-vector stage's guesses as "**Payload Signatures
  (strings/patterns a real attacker MUST produce — prefer these in detection)**", and
  instruction 3 repeats it. In both step (d) cases where the attack-vector stage copied the
  example, the invented names were in the rules; **in neither did the coverage regeneration
  run** (`[READ]`, run log; `1f32d820` had a single generation) — the label alone carried them
  in. Across three runs every example copied into the vector reached the rules (10 of 10).
- The coverage regeneration (code, ~19–24 cases per run `[READ]` in the run logs) tells the
  writer that each missed signature "**MUST literally**" appear in a rule — an amplifier for
  the same errors whenever it fires.
- The attack-vector prompt makes `payload_signatures` "**REQUIRED**, 1–8 items", so a report
  with no concrete pattern still gets some — invented ones are then labelled "MUST produce".
- The taxonomy retrieval is labelled "**authoritative**", but it includes the Sigma
  specification's general text, "product — examples: windows, **apache**, check point fw1",
  next to the appendix saying web server logs have no product. The rule writer that added
  `fortigate`, `confluence`… as the product of web rules (Change 28 run) was following one
  "authoritative" text over the other.
**Lesson:** say where each input comes from and how sure it is ("candidate patterns proposed
by an earlier step — use those the source text supports"); keep "authoritative" for data that
is (ATT&CK ids, SigmaHQ's own rules).

### P3. Many absolute orders that compete `[READ]` in the prompt text
The generation instructions contain MUST / NEVER / MANDATORY in capitals a dozen times, and
several pull against each other: instruction 1 (first rule on the recommended log source), 2
("initial-access detection is MANDATORY", on the network telemetry), 7 and the kill-chain
block ("AT LEAST one rule PER stage — MANDATORY"), and on a retry the coverage block ("FIX THEM
NOW"). The model resolves conflicts its own way: in step (c) 12 first rules departed from the
recommendation, mostly toward the initial-access rule, and **0 of 12** gave the reason it was
asked for. `logsource.version` is still a pySigma error 11 times in the last run despite "NEVER
copy … into `logsource.version`" — an instruction whose exception clause ("unless the LOG FORMAT
itself differs") leaves the door open.
**Lesson:** fewer imperatives, a stated order for conflicts, reasons instead of capitals.

### P4. The last model to touch a rule does not know what earlier stages decided `[READ]`
The review model **rewrites the rules, and its version is what the user sees and S3 scores**.
It runs at temperature 0.2, sees neither the recommended log source nor the table, and is told
to "keep the most comprehensive" rule when deduplicating — which can change which rule comes
first. Its "IoC enrichment" step adds extracted IPs/domains/hashes to detections. How often it
changes the first rule's log source is **unmeasured**: rows record the rules after review only.
(Change 29 fixes the same gap one step earlier — the rule writer never saw the table.)

### P5. The output format fights the content `[MEASURED]`
Generation and review return Sigma YAML **inside JSON strings**, so every backslash and quote is
escaped twice (the example itself needs `'\\\\lsass.exe'`). JSON failures from bad escapes: 1–2
per run (defect 5; now seen in the analysis stage too). YAML errors ("mapping values are not
allowed", unresolved conditions): 13 review errors in the last run, and review-error
regenerations: 16–24 per run `[READ]`. 103 generation calls for 60 cases.

---

## 3. A configuration finding that changes the thesis notes `[MEASURED]`
**Generation runs at temperature 0.3 and review at 0.2**; attack vector, PoC and analysis at 0.
The notes say "temperature 0" throughout (Chapter 7 item 15, several log entries). The two
stages that write and rewrite the scored rules sample, so part of the 2–3-case S3 swings between
runs is sampling noise — `[HYPOTHESIS]` how much. This needs a correction in the notes either
way (logged separately).

---

## 4. Per prompt

| Prompt | Works well | Problems (evidence) |
|---|---|---|
| Attack vector | Clear four-way split of content (exploit / post-exploit / researcher / background); the incidental list is a real safeguard | Examples copied (defect 15 → Change 30); `payload_signatures` REQUIRED even when the text has none (P2) |
| PoC | Focused; its example values (`evil.com`, `…\Temp\svc`) were copied 0 times in two runs | — |
| Analysis | Since Changes 25/28: generated table, Sigma's two forms explained; suggestions right 23/60 | Three jobs in one answer — the longest answers and every loop so far (defect 19); "Be thorough … BOTH explicit AND implicit" indicators (71 in one case); leftover `"suggested_log_sources": ["sysmon", …]` in the example; techniques uncapped (→ Change 32) |
| Generation | Instructions after the long context; first-rule section near the top (Change 26); reasons given for several rules | P1 (tags, id), P2 (labels), P3 (competing MUSTs), P5 (YAML in JSON); temperature 0.3; the log source appears twice (first-rule section and "Recommended Log Sources" — consistent, 59/59, but redundant); ~11k tokens of retrieval of mixed relevance (Sysmon docs even for web cases) |
| Review | Deterministic pySigma checks first; ATT&CK tactic check fed back, not applied by code | P4 (rewrites the scored rules blind to the log-source decision; IoC enrichment); temperature 0.2; its SAML example (`/metadata/samlidp/asdf`) is from the same real case as the old Example A (copied 0 times in two runs) |

---

## 5. Candidate changes, in the order I would take them

**Measure before changing (no pipeline behaviour change):**
- **M1. Record the first rule before review** (and the review's `changes_made`) in each row — a
  harness/orchestrator field, like Change 31's dropped ids. Then P4 can be measured.
- **M2. An A/A run**: the same code twice, to measure how many S3 cases flip by chance. Every
  paired result in Phase 2 would then have a noise floor. One run (~3 h).

**Prompt changes (each its own run if it can move S3):**
1. **Generation example fixed** (P1): hyphen tactic tags, no fixed id (Change 9 assigns one),
   nothing case-specific. Measures: pySigma tag warnings (136 → ?), duplicate ids.
   **Scheduled 2026-09-26 (user): Change 33, in the shared run.** Low risk;
   does not touch the log source — could join the shared run.
2. **Honest labels** (P2): payload signatures as "candidates proposed by an earlier step; use
   those the source supports"; the coverage retry asks to reconsider missed signatures instead
   of "MUST literally contain"; `payload_signatures` may be empty; "authoritative" kept for the
   ATT&CK and SigmaHQ data. Measures: example copies in rules, payload patterns absent from the
   input (committed counter), S5. Can move S3 → its own run.
3. **Temperature 0 for generation and review** (§3): a configuration change; its own run, or
   combined with M2 as the new baseline — to be decided.
4. **Fewer, ordered imperatives** (P3): one line stating which instruction wins in a conflict;
   capitals removed; `version:` rule without the exception. Measures: departures from the
   recommended log source, version errors, S3.
5. **Review told the log-source decision** (P4), after M1 shows how often it changes it.
6. **Rules as YAML blocks, not JSON strings** (P5): larger change to generation and review
   parsing. Measures: S1, JSON failures, review-error regenerations.
7. **Analysis answer shortened** after Change 32's result: e.g. at most N indicators, or the
   log-source part as its own call (loops, S3).
8. Housekeeping: delete the five dead prompts.

**Not recommended now:** changing the model, fine-tuning, or rewriting all prompts at once —
Phase 2's evidence is that one change at a time with its own measure is what makes each effect
defensible.
