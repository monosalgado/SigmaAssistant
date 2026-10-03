# Action plan

Created 2026-09-23. **This file decides what gets worked on.** Anything not in the
current phase goes to the Inbox or the Parking lot, not into the code.

**Current phase: 2 — Fix the logsource failure.** Phase 1 complete 2026-09-24
(its Inbox triaged with the user 2026-09-25). Phase 0 runs in parallel (it needs the
professor, not the code).
**Update 2026-09-27:** Phase 2 is complete (held-out confirmation). Active: the first slice of
Phases 3/4 — the analyst confirms or corrects the analysis before generation (Change 34, branch
`analyst-review`), started before the professor's sign-off by the user's decision.

---

## Why this plan exists

Work so far has followed findings as they appeared. Each fix was sound and logged,
but the order was set by what turned up next, not by what the thesis needs. The
root cause is that **the thesis's contributions are not settled**:

| Contribution in `OUTLINE.md` | Status |
|---|---|
| 1. Detonation-validated evaluation (R1/R2) | **Not built.** The lab exists: Metasploit Pro at `10.10.11.198:3790`, reachable only over the lab's OpenVPN |
| 2. Cost–quality analysis of tiered cloud/local routing | **Blocked.** The Gemini key is suspended and every stage now runs on `qwen3-coder:30b` |
| 3. Security-pretrained model (Foundation-Sec-8B) | **Dropped** 2026-09-23 (base model unusable with our prompts; all stages stay on qwen) |
| — Assistant: evidence-backed report + analyst confirmation | **Proposed** 2026-09-23, not yet in the outline |

Until these are settled, every finding looks equally urgent. Phase 0 settles them.

---

## Working rules

1. **One active task at a time.** Its box is marked `[>]` below. Finish it or park
   it explicitly before starting another.
2. **New findings go to the Inbox, not into the code.** One line each. They are
   triaged at the end of the phase. The only exception: a finding that makes the
   *current* phase's measurement wrong.
3. **Definition of done for any code task:** tests written first and seen to fail
   → change → full suite passes offline → engineering-log entry → **chapter notes
   updated if the change or finding affects a thesis claim** (CH5/CH6/CH7, tagged,
   citing the log) → commit → push → this file updated.
4. **Behaviour changes are measured, one at a time.** A change that alters what
   the pipeline outputs gets a measurement (the 15-minute attack-vector probe or
   the 60-case harness run) before the next behaviour change starts.
5. **Every session starts by reading this file and ends by updating it.**
6. The user writes the thesis prose. Claude keeps notes, the log, and this plan.

Status legend: `[ ]` todo · `[>]` active · `[x]` done · `[-]` dropped

---

## Phase 0 — Settle the thesis (the user handles the professor)

Blocks Phases 3–5. Does **not** block Phases 1–2, which are needed whatever is
decided. Timing is the user's; no dates are tracked here (defence is next
semester).

- [x] **User study: none.** Decided by the user 2026-09-23. The assistant is
      therefore evaluated without people: the simulated-analyst experiment (5.3)
      and the evidence metrics (5.4). Limitation to state plainly: the thesis
      can show what analyst confirmation is *worth when the analyst is right*,
      not that real analysts are helped.
- [ ] **0.1** Which contributions the thesis claims (options below) — user and
      professor. Claude prepares notes only if asked.
- [ ] **0.2** Update `OUTLINE.md` to the agreed contributions (user decides the
      wording).

**Professor's feedback after the demo (2026-09-28, via the user):** (1) the thesis must *understand*
why rules are good one time and wrong another (the May rules vs later ones) — research, with
examples; (2) the assistant relies on the human; human input matters, but **the goal is to automate
the process and rely more on the AI**. First evidence for (1): log 2026-09-28 (three sources;
two runs of identical code disagree on 16/60 cases, the temperature-0 first stage on 12/60).
Proposed next research (awaiting the user and the professor):
- **P-A Consistency study**: the same cases run k times with frozen code (e.g. 20 cases × 5), per-stage
  agreement and which case types are unstable; pre-registered
- **P-B Where the non-determinism comes from**: one stage's call repeated on identical input (cheap),
  with the Spark idle vs busy and with Ollama's seed/single-request settings — can temperature 0 be
  made deterministic?
  → **probed 2026-09-29 (user chose it; log "P-B results")**: only the first request of a prompt answered
  differently (5 of 5); all 17 repeats identical, seed or not; concurrent requests are queued. Next,
  proposed: a follow-up that alternates prompts (is a fresh answer repeatable; does what came before matter?)
  → **follow-up done 2026-09-29 (user):** repeats identical within a session; first-time wording varies
  even after the same question; the label holds for hours but changed between the September runs a day
  apart; neither a seed nor a warm-up fixes it. **Consequence for P-C:** back-to-back asks agree by
  construction — votes need independent samples (temperature > 0, reworded prompts, or time apart).
- **P-C Self-consistency instead of the human**: run the analysis k times and take the majority log
  source; runs that disagree = uncertainty → only those go to the analyst. Measures: S3/S5 vs the
  single run, and how often a human would be needed — against the 5.3 upper bound (+0.14 S5)
  → **tool built + 2-case pilot 2026-10-03** (`eval/probe_self_consistency.py`; both pilot cases unanimous and wrong);
  **shelved by the user** the same day for detection fields (log 2026-10-03)
- **P-D Automated verification** of what analysts corrected most (e.g. the log source's platform
  against the attacked product: sudo → Linux), by code or a second model
Together: automate by default, measure confidence, escalate only uncertain cases to the human.

**Part (1), May reconstructed (2026-09-28, user: "go ahead with the prompt diff and the April chats"):**
done — `thesis/MAY_VS_NOW_NOTES.md`, `eval/prompt_history.py`, `eval/old_sessions.py` (log 2026-09-28).
5 of 8 prompts unchanged since May; the rule writer was Gemini 2.5 Flash with web search; the May
attack-vector prompt's examples were the demo reports (tuned on its test inputs); April rules 7/56 with a
log source SigmaHQ's rules use. Open, for the user and the professor:
- [ ] **Controlled rerun** May code (`2ec05f6`) vs `main` on frozen pages, k runs each — isolates code +
      prompts only (same local model unless a new Gemini key; April web results unrecoverable).
      Pre-register first; check the May retrieval collections still exist
      → **started 2026-09-28** (user: "rerun the may code on the same saved pages, several times
      each"): held-out 60, k = 3 per arm, plan fixed in the log ("May vs now rerun…"); then the
      results and a presentation for the professor (user)
      → **done 2026-09-29** (log "May vs now rerun: results"; CH6 §6.0d): log source right May 0.072 →
      now 0.439 (+0.367 [+0.250, +0.489]); detection-field F1 +0.158 [+0.096, +0.222]; same log source in all
      3 runs 18 → 43 of 60 (p = 1.1e-05). Presentation: web deck + `thesis/May_vs_Now.pptx` (local only,
      never in git — user)

Options to discuss, not decided:
- **A.** Assistant + measured grounding failures + static evaluation (drop 1–3,
  or move 1 to future work)
- **B.** A plus detonation testing (contribution 1). The lab exists and there is
  a semester of time. Open question: which rules to detonate — see the Inbox
  note on EVTX coverage
- **C.** Keep the original three — not viable as they stand (2 blocked, 3 dropped)
- **D. (raised by the user 2026-09-24)** The assistant's output goes past Sigma:
  (i) it states plainly what the rule is for — Windows, Linux, web, cloud… — and
  (ii) it converts the rule into queries a SIEM or EDR can run (e.g. Splunk SPL,
  Microsoft Sentinel KQL, Elastic). Rationale (user): organisations deploy native
  queries, not Sigma files. Notes for the discussion are in the Parking lot entry.

The evidence behind "measured grounding failures" is already in the log: bare
URLs skipped grounding in 57% of cases (defect 8); 4/60 cases lost their page
to a URL-fragment bug (defect 14); the analysis stage saw the whole article in
only 8% of cases and the attack-vector stage copied its own prompt examples in
22% (defect 15).

---

## Phase 1 — Trustworthy measurement

**Goal:** a new reference run ("baseline v2", after Change 12) that also records
the intermediate results needed to explain its scores.
**Why first:** every later step is judged against it, and the current run cannot
say *why* logsource is at chance.

- [x] **1.1** Harness records what diagnosis needs, per case: which stage made
      each LLM call; the attack-vector output; the analysis stage's logsource
      suggestions; `generation.ids_replaced`; the response text when no rule is
      extracted. *(offline)* Done in three changes, each measured-by-tests:
      **1.1a** stage label on every LLM call · **1.1b** pipeline crashes reach
      the harness (defect 17, found while starting 1.1: `agent.analyze_attack`
      swallows every exception, so gate 4 could never fire) · **1.1c** the row
      keeps the pipeline's intermediate outputs.
      **Done:** Changes 13–15 (`24e2a69`, `092d1de`, `ae91c46`). 156 tests pass.
- [x] **1.2** Defect 12: the harness refuses to write a row for a case with zero
      successful LLM calls, replacing the external guard. *(offline)* **Done, Change 16:**
      broadened to *any* failed call (the evidence has a 1-of-5 case); the run stops,
      exit status 2, and resumes from that case. Refuses exactly 14/21 evidence rows.
- [x] **1.3** Defect 16: the PoC stage's GitHub fetches go through the snapshots
      too, or are disclosed as a live input. *(decide, then offline)* Measured:
      43/303 cases (10/60) fetch GitHub live. Split, **decision needed first**:
  - [x] **1.3a** Reproducibility: save the PoC stage's GitHub fetches into the
        snapshots (recommended), or block them during evaluation. **Done, Change 17:**
        chosen A; 40 stored + 10 recorded 404s; gate 1 now covers PoC fetches.
  - [x] **1.3b** Contamination: 23/303 cases (5/60) put a detection rule in front
        of the pipeline (PoC downloads, rule-file references, Sigma rules printed
        in the page). Keep and report separately (recommended), drop them, or
        disclose only. **Done, Change 18:** chosen a; committed flag list; the
        summariser reports all / clean / flagged. Baseline v1 headline unchanged
        on the clean cases (at most 0.008).
- [x] **1.4** One-command preflight: tunnel, model warm, server context ≥ 32k,
      tests, 2-case smoke. *(offline to write)*
      Also: `summarise.py` prints the gates (it reports none today; they have been
      checked by hand), including the new `poc_snapshots_missed`; and a relaunch
      wrapper for exit status 2 (replaces the old watchdog).
      **1.4a done (Change 19):** gates + verdict in `summarise.py`.
      **1.4b done (Change 20):** `eval/preflight.py`, stops at the first failure.
      **1.4c done (Change 21):** `eval/run_resilient.py` relaunches on exit status 2.
- [x] **1.5** Run baseline v2: 60 cases, same sample. **Needs ~2 h on the VPN.**
      Exit: all five gates pass, results + log entry committed.
      **Done 2026-09-24:** CITABLE (all seven gates). Paired against v1: no detectable
      change on S1–S5; +45% tokens, +65% time per case; S3 0.123, still at chance.
      One network outage, caught by the stop rule (log: "Baseline v2").
      Recipe: USF VPN on, OpenVPN off → `eval/preflight.py` → `eval/run_resilient.py --
      --sample 60 --seed 0 --arm baseline_v2 --no-web-enrich --out eval/results/baseline60_v2.jsonl`
      → `eval/summarise.py eval/results/baseline60.jsonl eval/results/baseline60_v2.jsonl`.

**Exit criteria:** baseline v2 committed with intermediate outputs; S1–S5 and
cost read against both the null baselines and baseline v1.

---

## Phase 2 — Fix the logsource failure

**Goal:** S3 (logsource exact match) clearly above the null baseline of 0.173.
Currently 0.145, i.e. chance. A thesis cannot stand on a system that picks the
log source at random, whatever the framing.
**Time-box:** the changes listed below. If S3 is still at chance after them, stop
and report it as a finding rather than keep tuning.

- [x] **2.1** Diagnose from baseline v2 *(offline)*: where does the logsource go
      wrong — the analysis stage's suggestion vs gold, the attack-vector
      telemetry vs gold, or the rule ignoring a correct suggestion (defect 11)?
      **Done 2026-09-24** (`eval/diagnose_logsource.py`; log "Plan 2.1"): the
      analysis's top category is right in 29/57, generation overrides 14 of those
      (10 with the attack-vector label); 17/41 wrong rules use a non-Sigma category
      (`webserver_access_log`); the suggestion verbatim would score 0/57 (its
      service is `sysmon`). **Order agreed with the user:** (a) one vocabulary —
      attack-vector telemetry in Sigma categories; (b) fix the suggestion's
      service; (c) 2.2 precedence; (d) 2.3 web bias; 2.4 dropped. One run each.
- [x] **2.2a** One vocabulary: the attack-vector stage's telemetry reaches the
      analysis and generation stages in Sigma's terms. Measure: categories no
      SigmaHQ rule uses (17/41 wrong rules in v2), S3 paired against v2.
      **Blocked 2026-09-24 at 33/60:** case `9a2d8b3e` loops in the analysis
      stage on every attempt (defect 19). Needs a decision on defect 19 first.
      Decision (user): Change 24, then restart from scratch.
      **Done 2026-09-24** (`p2a_vocabulary60_r2.jsonl`, CITABLE): non-Sigma categories
      17 → 1; overrides 14 → 3; S3 paired 6 → 11 of 52 (p = 0.062); web bias now reaches
      the rule under a real name (18/44; was written 18/46 — corrected 2026-09-26). Next: 2.2b.
- [x] **Change 24** (defect 19, found during 2.2a): every LLM answer has a bounded
      length (16,384 tokens); a cut answer is retried, then recorded as the model's
      failure and measured with the case. 2.2a restarts from scratch on it
      (`p2a_vocabulary60_r2.jsonl`).
- [x] **2.2b** The analysis suggestion's `service` (44/57 `sysmon` in v2; 35/53 `sysmon`
      and 10 `webserver` after 2.2a). Measure against `p2a_vocabulary60_r2.jsonl`.
      Change 25 (user's rule): service only when there is no category; an unknown one is
      marked `service_to_confirm` for the analyst. Run `p2b_service60.jsonl`.
      **Done 2026-09-25** (CITABLE): suggestion's service right 0/53 → 51/58; S3-if-copied
      0 → 15/58; S3 paired 11 → 8 of 53 (3 lost, p = 0.25; 2 are rules written as `email`).
- [x] **2.2** (step c) Change 26 (prompt precedence, nothing enforced — user: "I want them to
      think"). Run `p2c_first_rule60.jsonl` vs `p2b_service60.jsonl`. Originally: make the (suggested or confirmed) logsource an explicit
      constraint in generation, checked after generation (defect 11); resolve the
      conflict with generation rule 2 ("initial access MANDATORY"). Measure.
      **Done 2026-09-25** (CITABLE): first rule follows the suggestion 24/58 → 44/57; S3 9 → 14
      of 56 (0 lost, p = 0.062); S5 +0.075 CI [+0.008, +0.146]. Cumulative vs v2: S3 7 → 14 of
      55, p = 0.016 (4 comparisons: not conclusive alone). 0 of 12 departures explained.
- [x] **2.3** (step d) Change 27 (prompt only: Example A →
      email/host malware; `primary_telemetry` = where the described activity is seen; "never invent
      a network request"). **Before the run:** a committed counter of example text in the rows'
      attack vectors, run on `p2c_first_rule60.jsonl` too. Run `p2d_web_bias60.jsonl`.
      **Done 2026-09-26** (CITABLE): attack-vector web on non-web gold 18/48 → 14/45 (half of it
      is cases leaving the count — read case by case: 3 relabelled off web, 1 on); first rule web
      16/48 → 8/45; old example text in vectors 4 → 0, **new example copied in 2** (its invented
      names reach both cases' rules); S3 13 → 13 of 54 (2 gained, 2 lost, p = 1.0); no web gold
      case lost. The web bias no longer limits S3; the suggestion does (2.6).
      Originally: remove the attack-vector prompt's web bias (21/48 non-web
      cases labelled web-server telemetry; 16/46 in v2; 18/44 after Change 22). Measure with
      the probe, then the harness. Includes (Inbox 2026-09-25): its worked examples were
      written from specific past cases (Example A is a real saved Citrix rule), and the stage
      still copies example text into answers (`/saml/login` on a rootkit report) — count that
      before and after, with a committed script.
- [ ] **Defect 15 at its cause — decided 2026-09-26: (a) + (b) as one change, in the shared run
      with 2.7 and 2.8; (c) in Phase 3.** Before that run: ~~extend the copy counter to the
      generated rules~~ **done 2026-09-26** (`in_rules`; v2 4, step c 4, step d 2 — every vector
      copy reached the rules); add the placeholders as markers (with the change). The model
      copies a concrete worked example into reports that resemble it; replacing the example
      moved the copying (web exploits → email malware), and the invented names reach rules.
      Options: (a) prompt — say the examples come from other, invented reports and none of
      their names may be reused; (b) examples with placeholders (`<name>.dll`) instead of
      realistic invented names; (c) code that validates and records — flag an example-only
      string in an answer that is absent from the input, shown in the assistant's report
      (Phase 3). (a)/(b) change prompts → one run each. S3 does not see these copies (both
      cases were right), so they do not block the Phase 2 exit.
- [x] **2.6** Change 28 (runs alone) vs
      `p2d_web_bias60.jsonl`: generated table (35 categories, 75 service sources, from
      `data/sigma/rules`); primary = top suggestion = gold over all 60 rows
      (`eval/compare_suggestions.py`), reference 13/60.
      **Done 2026-09-26** (`p2e_table60.jsonl`, CITABLE): **primary 13 → 23 of 60, p = 0.013**
      (web gold 0 → 9 of 12; on-table 39 → 59); **S3 12 → 13 of 53, p = 1.0** — in 6 web cases
      the rule writer adds a product the suggestion does not have (`fortigate`, `iis`…); the
      service form is never suggested. Originally: The analysis stage never suggests a log source without a category, so the 6 gold
      rules defined by a service (Windows Security ×3, …) are always missed. Give its prompt a
      complete reference table (service-based sources too; no "windows/sysmon"). Prompt
      change: the model chooses. Its own run.
      Also (Change 26 run): the table's "linux-windows/apache-iis" cell is copied into the
      web suggestions' `product` (5 of 12 departures); no gold web rule has a product.
      Why next (2026-09-26, step c run): of the 43 first rules that miss S3, 6 fail only on the
      product — 3 carry "linux-windows/apache-iis", 1 "iis" (gold web rules have none) — and
      the 5 gold rules defined by a service are always missed. The most likely step to move S3.
- [x] **2.6b** Change 29 — approved 2026-09-26 (user); run `p2f_product60.jsonl` vs
      `p2e_table60.jsonl`. **Done 2026-09-26** (CITABLE): **S3 14 → 21 of 55, p = 0.039**; added
      products 15 → 0; first rule on the suggestion 35 → 53/56; cumulative vs v2 6 → 21 of 54,
      p < 0.001 (tuning cases). `p2f_product60.jsonl` = reference for the shared run. Found in the 2.6 run: the rule
      writer adds a `product` to a recommended log source that has none (6 of 9 web gold cases
      with a right suggestion). Prompt only: the first-rule block states what the table says
      about the recommended source's absent fields (generated from the table, not written per
      case), and one sentence on what Sigma's `product` means (the platform that writes the
      log, not the attacked application). S3-relevant → its own run, before the shared run.
- [ ] **2.7** (user, was 2.2e) ATT&CK ID check: drop technique IDs that do not exist in
      ATT&CK (the `mitre` collection), like the rule-id check (Change 9). Changes finished
      answers → its own run. Measure S4 and invented-ID counts.
- [ ] **2.8** (user, was 2.2f) The analysis lists **the 10 most relevant techniques** at most.
      Data (Change 25 run): gold rules use 1 technique (28 of 40), at most 5; the analysis lists
      a median of 6, more than 10 in 14 of 58 cases, 108 in one; of the gold techniques it
      finds (24), 21 are in its first 10 but only 15 in its first 5. All 6 looping answers
      were in the analysis stage. Prompt change → its own run. Measure S4 and answers cut.
- [x] **2.9 Held-out confirmation** (user, 2026-09-26) — last Phase 2 step, after the shared
      run. Phase 2 frozen at `a6e9157`; `eval/manifest_heldout.jsonl` (60 of the 242 never-run cases).
      **Done 2026-09-27** (both runs CITABLE): **exit test met — S3 25/55 = 0.455, one-sided exact
      binomial p = 1.2 × 10⁻⁶**; paired vs baseline v2's code **10 → 21 of 50, p = 0.013** (2 cases
      excluded by the pre-registered rule; including one gives the same p). S4, S5 unchanged. CH6 §6.0. Why: every Phase 2 change was found by reading failures in the same 60 cases it was
      measured on, so its gains may be optimistic there (tuning to the test set).
      1. A committed script (tests first) draws **60 cases** — stratified, `stratified_sample`,
         seed 0 — from the **242 corpus cases that appear in no result file** (61 have ever been
         run, in 23 files), and writes `eval/manifest_heldout.jsonl`. The list is committed
         **before** anything runs on it. (A new seed is not enough: it shares 13–15 of the 60.)
      2. Nobody reads held-out outputs, and no pipeline file changes, until both runs are done.
      3. Run the final Phase 2 pipeline on it: `--manifest eval/manifest_heldout.jsonl`.
      4. Run **baseline v2's code** on the same cases (commit `5627e91`, the parent of the result
         commit — confirm first) in a separate checkout with the local data linked; its harness
         also takes `--manifest`. → paired before/after (`compare_runs.py`) on unseen cases.
      5. The pre-registered chance test is applied **once, to step 3's run** (revised
         2026-09-26, before any held-out result exists; log entry of that date).
      Checked: page snapshots exist for all 242. To check at preflight: PoC GitHub snapshots.
      ~3 h per run.
- [-] **2.5** Moved to Phase 3 (3.5) on 2026-09-26 — see there. Invented categories are ~2% of
      rules but 0 first rules after Change 26, so they no longer affect S3.
- [-] **2.4** Strip page boilerplate (defect 9) — dropped 2026-09-24: 2.1 showed
      nothing pointing to it.

Order agreed with the user (2026-09-24/25, revised 2026-09-26): (c) 2.2 → (d) 2.3 → 2.6 → 2.7 → 2.8;
2.5 moved to Phase 3. **Runs (2026-09-26):** 2.6 alone; then defect 15 (a+b) + 2.7 + 2.8 in one
run — the last run on the 60 tuning cases; then 2.9, the held-out confirmation (two runs).
**Shared run contents (2026-09-26):** Change 30 (defect 15, a+b), 31 (2.7 ID check), 32 (2.8, ≤ 10
techniques), 33 (prompt review item 1: the rule writer's example — hyphen tactic tags, no fixed id).
**Done 2026-09-26** (`p2g_shared60.jsonl`, CITABLE): example copies 1/1/6 → 0/0/0; tactic tags
141/8 → 0/144 (pySigma tag issues 145 → 2); technique lists over 10: 12 → 0 (but the cap became a
quota, median 5 → 10); 1 invented ID dropped; joint S3 18 → 20 of 49 (p = 0.63), S1 56 → 52 (3 are
defect 5), S4/S5 no change. Cumulative vs v2: S3 6 → 22 of 50. **Last run on the tuning cases.**

**Exit test (built 2026-09-26, `eval/summarise.py`):** exact binomial, one-sided, alpha 0.05,
against 0.173 — applied **once, to the final pipeline's held-out run (2.9, step 3)**
(pre-registered for "the final Phase 2 run"; revised 2026-09-26 before any held-out result, so
the test is not run on the cases the changes were tuned on). Descriptive so far:
after step (c) S3 = 14/57, p = 0.104; p < 0.05 needs ≥ 16/57. After step (d) 13/56, p = 0.160;
needs ≥ 16/56. After 2.6: 14/55, p = 0.082; needs ≥ 15/55. After 2.6b: 21/56, p < 0.001 (descriptive; tuning cases). After the shared run: 22/52.
**Exit criteria:** S3 significantly above the null baseline, or the time-box is
spent and the result is written up as a finding.
**→ Met 2026-09-27 on the held-out cases (plan 2.9). Phase 2 is complete.**

---

## Next pipeline change (user order, 2026-09-27)

- [x] **Change 36 — defect 5: the rule writer answers in YAML blocks, not JSON strings**
      (prompt review item 6, P5). Built on branch `defect5-yaml-rules` (off `analyst-review` at
      `c3f3e76`), so the simulated-analyst run (5.3) stays on the frozen pipeline.
      *Why:* generation returns every rule as a JSON string, so each backslash is escaped twice; a
      single bad escape (`Invalid \escape`, Windows paths) loses **every rule** of that answer. In
      the shared run 3 of the 7 lost first rules were this (log 2026-09-26); live, it emptied a
      review rewrite (2026-09-27). **Generation only** — one change at a time; a failed review
      already falls back to the rules as they were (review stays JSON; a later change).
      **Measurement plan — PROPOSED 2026-09-27, awaiting the user's approval; fixed before any run:**
      - *Cases and reference:* the 60 tuning cases (seed 0), paired against `p2g_shared60`
        (code `a6e9157`); `eval/compare_runs.py`.
      - *Primary:* **cases with no rule because generation's answer could not be read** — rows
        with zero rules whose response carries "Generation error" (both runs have it) — and **S1**
        (first rule parses), exact McNemar. Expected: fewer lost rules; S1 up if those cases come back.
      - *Recorded from this run on:* every generation call's parse failure in `generation_log`
        (`parse_error`), so first-attempt failures that a retry hid become countable.
      - *Watched for harm (paired, reported):* S3, S4, S5, rules per case, tokens, seconds — the
        worked example changes format, and examples are copied (Change 27); the example's content
        stays the same, only its encoding changes.
      - *Rules:* the harness's stop rule; a case that stops 3 times is excluded.
      - *Built 2026-09-27* (log); smoke on 2 cases: the new format was followed in 4 of 4 calls.
        **Run only on the user's approval**, after 5.3 or in its own worktree (never two runs from
        one checkout): `eval/run_resilient.py -- --sample 60 --seed 0 --no-web-enrich --arm c36_yaml
        --out eval/results/c36_yaml60.jsonl`; then `compare_runs.py` against `p2g_shared60` and
        `count_generation_failures.py` on both.
      - Seen: the PoC stage's JSON failed once in the smoke — the same defect in another stage (Inbox).
      - **MEASURED 2026-09-28 (log):** cases lost to an unreadable answer 3 → 0; unreadable generation
        calls 0 of 91; S1 52 → 57 (p = 0.125, the noise-floor pattern — not attributable); no harm
        detected on S3–S5, tokens, seconds; rules per case +0.52 (CI [0.12, 0.97]). The old format
        loses 0–3 cases per run, so the gain is the failure mode gone, not a significant S1 rise.
        **Kept (user, 2026-09-28).** Merged with the review work into `main` after the demo.

## Phase 3 — Assistant backend (after Phase 0 approves it)

Design: `thesis/ASSISTANT_DESIGN.md` — **reviewed with the user 2026-09-26**; decisions in its §9
(analyst-confirmed facts are final; state in the persisted session; the revise button in scope,
later; SIEM/EDR conversion pending Phase 0).

- [x] 3.0 Defect 13 fixed (`663f005`) — design step 1
- [x] **First slice of 3.2 + 3.4 + 4.1 — Change 34 (2026-09-27, branch `analyst-review`, user):**
      the web app's run stops after the analysis (`analyse_for_review`), the analysis waits in the
      session, the analyst confirms/rejects patterns, techniques and indicators, restores excluded
      strings, chooses the log source (validated against SigmaHQ's table) and adds a note; generation
      starts from the saved analysis (`generate_after_review`). `run_sync` untouched (P5). Tested live
      twice (sudo). **Change 35:** one decision per string (copies linked) and P4's check (log source and
      rejected techniques → one rewrite; rejected strings in detection shown). Not yet: editing values,
      the report builder (3.1), evidence quotes (3.3), rule validation (3.5).
- [ ] **3.1** Report builder: a pure function from pipeline context to the report *(offline)*
      Include (user, 2026-09-25): suggestions marked `service_to_confirm` (Change 25) are
      shown for the analyst to confirm, with `service_dropped` explained.
- [ ] **3.2** Split the orchestrator into analyse → checkpoint → generate, with the
      automated path unchanged *(offline)*
- [ ] **3.3** Evidence quotes, with code checking that each quote is on the page. Measure.
      User (2026-09-25): paraphrase is fine if it is faithful to the page. So evidence is
      shown either way; code marks the pieces found word for word on the page as
      "verified". Only ~26% of quotes are verbatim today.
- [ ] **3.4** API endpoints and saved state for the checkpoint
- [ ] **3.5** Validate edited rules (new endpoint; `PUT /rules/{id}` validates too)
      Includes former 2.5 (user: important): flag a logsource category that does not exist in
      Sigma (`email`, `security`, `network`: 4 of 237 rules in the step (c) run, none first) and
      ask the model to fix it — the same check for generated and analyst-edited rules.
- [-] **3.6** Regression: automated path against baseline v2, within run-to-run noise — **deferred
      2026-09-27:** `run_sync` stays separate from the review path, so it is unaffected by
      construction; needed only if it is ever routed through analyse → review → generate

Decisions needed before 3.4: where the checkpoint state is stored; whether "ask the
assistant to revise this rule" is in scope.

---

## Phase 4 — GUI (after Phase 3)

- [ ] **4.0** Decide: plain JavaScript or a framework (new tooling needs approval)
- [ ] **4.1** Screens built on the settled API: report, confirm/edit facts, rule
      editor with live validation

---

## Phase 5 — Thesis evaluation (after Phase 0)

Which of these run depends on the contributions agreed in Phase 0.

- [ ] **5.1** Final reference run on the finished system
- [ ] **5.2** Chosen ablations. Not all of A1–A7: the likely core is A1 (no RAG) and
      A5 (single prompt vs pipeline), and the naive-baseline arm
- [x] **5.3** Simulated-analyst experiment: confirm the gold logsource/techniques,
      regenerate, rescore. **Moved up 2026-09-27 (user accepted the order).**
      **DONE 2026-09-27 (log; CH6 §6.0b):** S5 0.388 → 0.531, +0.144, 95% CI [0.056, 0.241], n = 53 —
      all of it in the 19 cases whose log source became right (post-hoc). Adherence 49/58; the one
      rewrite fixed 3 of 12. By-product noise floor: S3 flips 6/51, S5 +0.086 (CI crosses 0).
      A techniques oracle remains possible (not run).
      **Measurement plan — PROPOSED 2026-09-27, awaiting the user's approval; fixed before any run:**
      - *Question:* when the analyst gets the log source right, how much better are the rules?
        An upper bound — what confirmation is worth when the analyst is right (no user study).
      - *Cases:* the **60 tuning cases** (`--sample 60 --seed 0`), snapshots, no web search.
        (First written as the held-out cases; changed the same day, before any run: reading
        oracle-run failures on held-out cases would spoil them for the next phase's confirmation.)
      - *Design, paired within case:* the analysis runs **once** (`analyse_for_review`); then two
        generations from that same analysis — arm **U** (unreviewed, no review: the automated path)
        and arm **O** (oracle): the gold rule's log source given as the analyst's choice, when that
        log source is in SigmaHQ's table (otherwise the case is out of O, counted). **Nothing else
        from the gold rule reaches the pipeline.** Same analysis in both arms, so only the
        analyst's decision differs.
      - *Primary measure:* **S5 (detection-field F1)**, O − U, paired on the cases in both, mean
        difference with a paired bootstrap 95% CI (`eval/compare_runs.py`). Does the right log
        source lead to the right detection fields? (The next direction: detection quality.)
      - *Reported, not tested:* S3 in O = **adherence** to the analyst's log source (high by
        construction — the check enforces it with one rewrite; never reported as a gain); rewrites
        and remaining departures; S1, S4; tokens and seconds per arm.
      - *By-product:* U against `p2g_shared60` (same pipeline `a6e9157`, same cases, another run) =
        the run-to-run noise floor (Inbox M2) — descriptive, no test.
      - *Rules:* the harness's stop rule (a failed LLM call → the case is redone); a case that
        stops 3 times is excluded (as in 2.9); both arms' rows are written only when both finished.
      - *Not in this run:* a techniques oracle (rejecting non-gold techniques makes S4 mechanical).
      - *Output:* `eval/results/oracle_ls60_unreviewed.jsonl`, `eval/results/oracle_ls60_oracle.jsonl`.
      - *Built and smoke-tested 2026-09-27* (log): 58 of 60 cases choosable; ~3–6 min per case in the
        smoke runs, so the run is likely 4–6 h — **start only on the user's approval**:
        `eval/run_resilient.py -- --sample 60 --seed 0 --no-web-enrich --oracle-logsource --arm oracle_ls --out eval/results/oracle_ls60.jsonl`
        (the stall watchdog watches `oracle_ls60_unreviewed.jsonl`: both rows are written together)
- [ ] **5.4** Evidence metrics from 3.3: verified-quote rate, report accuracy vs gold
- [-] **5.5** User study — dropped by the user 2026-09-23
- [ ] **5.6** Detonation testing (R1/R2) — only if agreed in Phase 0. Needs both
      VPNs at once (GlobalProtect for the Spark, OpenVPN for the lab). Tested
      2026-09-23: broken as configured — the lab profile is full-tunnel and its
      packets are too large once nested in GlobalProtect (TLS and larger Spark
      responses stall). **Not a blocker:** the steps separate — generate rules
      on the Spark (GlobalProtect only), detonate and export EVTX in the lab
      (OpenVPN only), score with Zircolite locally (no VPN). Both VPNs at once
      only if rules were generated live during an attack
      Note (Inbox 2026-09-25): SigmaHQ's `regression_data` has 138 EVTX files, but for only
      2 of our 437 emerging-threat rules and 0 of the 60-case sample — detonation needs the lab.

Run budget has to be planned before this phase. Measured: one 60-case run took
1 h 42 min before Change 12, and **~2 h 50 min of compute after it** (baseline v2,
2026-09-24; 3 h 30 min of wall time including an outage).
Seeds × arms × ~2 h adds up fast, so the number of seeds (the outline says k ≥ 5)
is a decision, not a default.

---

## Phase 6 — Writing support (continuous; the user writes)

- [x] **Notes catch-up, 2026-09-23:** `CH5_NOTES_EVALUATION.md` brought up to date (it had
      stopped at 2026-09-09); `CH6_NOTES_RESULTS.md` and `CH7_NOTES_LIMITATIONS.md` started;
      `LITERATURE_NOTES.md` and `DEFENSE_NOTES.md` moved into `thesis/`. Keeping them current
      is now part of the definition of done (rule 3).
- [ ] Chapter 4 notes (system design) once Phase 3 has settled the architecture

---

## Inbox — findings not yet triaged
- **(2026-09-28, found preparing the May rerun)** The review prompt (`COMBINED_REVIEW`, unchanged
  since May, in use) still carries an example from the Citrix demo report (`/metadata/samlidp/asdf`).
  Replace it with a placeholder example, as Change 27 did for the attack-vector prompt — after the
  May rerun, one change, measured.

*(one line each; triaged at the end of the current phase)*

*(Empty. Triaged with the user 2026-09-25 — see the Decisions log. Closed: the paired-test
script and the output limit (done); the no-rule cases (→ defect 5); the connection timeout
(appropriate since Change 24); the shared Spark and the VPN reconnect (one-off, ignored);
Foundation-Sec (out of the thesis entirely); the PoC dotted-tag quirk (known limitation,
CH7 item 27); `.env.example` (already done in H5a); sigma.nasbench.dev (already in the
web-search entry). Scheduled: 2.3, 2.5, 2.6, 2.8, 3.3, 5.6 notes, H7.)*

*(Everything below: next phase — Phase 2 is frozen, 2026-09-26.)*

From the prompt review (2026-09-26, `thesis/PROMPT_REVIEW.md` §5) — awaiting the user:
- M1 record the first rule before review in each row · M2 an A/A run (noise floor for S3)
- ~~1 generation example~~ → **scheduled as Change 33 in the shared run** (user, 2026-09-26)
- 2 honest labels for model-made inputs ("MUST produce", "MUST literally contain", REQUIRED patterns)
- 3 temperature 0 for generation (0.3) and review (0.2)
- 4 fewer, ordered imperatives in generation · 5 review told the log-source decision (after M1)
- 6 rules as YAML blocks, not JSON strings · 7 shorter analysis answer (after Change 32)
- H8 delete the five unused prompts
- (shared run) "at most the 10 most relevant techniques" became a quota: median 5 → 10 — reword?
- (shared run) defect 5 cluster: 6 generation JSON escape failures (1 in the run before), 3 cases with no rules

From the retrieval check (2026-09-26, user: a and b to the Inbox) — awaiting triage:
- a record what each retrieval returned (document ids per collection) in every row — measurement only
- b the analysis stage searches ATT&CK with `combined_text[:500]` — URLs plus, often, the site menu
  (Securelist case: the Kaspersky menu); the attack-vector summary exists by then. Mainly S4.

From Change 34's live test (2026-09-27) — awaiting triage:
- ~~**Defect 20**: the web app's coverage retry never runs~~ — **fixed 2026-09-27 on `analyst-review`**
  (user): decided once, as `run_sync` does; a test holds the stream to the harness path's calls
- the review stage merged 3 generated rules into 1 ("Merged duplicate rules") — measure how often review drops rules (needs M1)
- ~~P4 check~~ — **built 2026-09-27 (Change 35)**: log source + rejected techniques → one rewrite; rejected strings in detection shown, not rewritten; a rewrite with no rules keeps the rules before it. Retested live 2026-09-27 (sudo, SharePoint)
- remove the unused `feedback_data` / `_apply_user_feedback` path (superseded by Change 34)
- the Analysis panel (and so the review) is hidden under 900 px wide
- (5.3) the one rewrite fixes 3 of 12 log-source departures — a stronger rewrite, or the analyst's choice earlier in the prompt?
- (5.3) a service-form choice (`windows/security`, `linux/auditd`, `firewall`) gets a category added, although the block says "no `category`" (3 cases + live sudo)
- (5.3) stage order: the first rule stays the initial-access rule when the analyst's log source is a later stage (4 of 9 departures use it in a later rule)
- ~~M2 A/A run~~ — **done as 5.3's by-product** (CH6 §6.0b)
- the review can reject but not add: SharePoint's analysis once omitted T1190 (Exploit Public-Facing Application) — adding a technique/indicator = "editing values"
- ~~rejecting a pattern does not reject the same string as an indicator~~ — **linked 2026-09-27 (Change 35)**, exact match; PoC behaviours are display-only and do not reach generation

Assistant roadmap (proposed 2026-09-28, user: "add them to the plan") — awaiting triage:
- R1 the analyst can **add and edit** techniques, indicators, patterns — not only reject (T1190 was missing once)
- R2 **evidence "found in the report"**: code checks each quoted basis against the page; verified-quote rate (= plan 3.3)
- R3 **rule editor with live pySigma validation**, incl. log-source categories that do not exist in Sigma (= plan 3.5)
- R4 **"ask the assistant to revise this rule"** from a plain-words instruction, then validated (design decision 3)
- R5 **a stronger rewrite**: 3 of 12 departures fixed (5.3) — the analyst's decisions earlier in the prompt; service form; rule order
- R6 **an exportable report**: what the model understood, evidence, the analyst's decisions, the rules (= plan 3.1)
- R7 **better log-source suggestions** (analysis stage): the log source gates S5 (5.3); 45% held-out, weakest on host and service sources.
  **Tried 2026-09-29 to 10-03 (Change 38: rank by the specificity of the evidence; 3 iterations, tuning set): no gain, v3 worse → removed**
  (user, 2026-10-03; CH6 §6.5b, CH7 54). Change 37 (JSON escape repair) kept. Still open: about 25 of 60 picks match no human
  rule for the report; the product + service form is never picked; confirmation set 2 (`eval/manifest_confirm2.jsonl`) unused
- R8 **a value-level detection score**: S5 compares field names only (sudo: S5 = 1.0, the human's match broader)
- R9 **do the rules fire?** replay with Zircolite over SigmaHQ's 138 regression EVTX files; detonation in the lab (= 5.6, Phase 0)
- R10 **false positives**: the rules over benign logs
- R11 **"a rule already exists"**: search SigmaHQ for the same CVE/behaviour before generating (prior art: SIGMERGE)
- R12 **a realistic simulated analyst**: wrong 10–30% of the time — what a wrong confirmation costs (extends 5.3)

## Security — do first (the user's action)

- [x] **S1** Delete the Gemini API key in Google AI Studio / Cloud Console. The
      full key sits in the **public** git history (a UTF-16 log file committed in
      Feb 2026), which is almost certainly why Google suspended it. Deleting it
      makes the exposure harmless. Only then: note it in the engineering log, and
      decide whether to rewrite history (optional, destructive, affects both
      public repos). A new key, if ever needed, goes only in `.env`.
      **Done 2026-09-23:** deleted by the user; logged; history NOT rewritten.

## Housekeeping — each item needs the user's approval before anything is removed

From the read-only repo audit of 2026-09-23. Git history keeps every tracked file,
so removing one is reversible; untracked and ignored files have no such safety net.

- [x] **H1** Remove the stale worktree `.claude/worktrees/kind-davinci` (Feb 2026).
      All its commits are in main; of its 16 uncommitted files, 13 are identical
      to versions in history and 3 are older drafts that are strict subsets of
      main. Safe procedure: save its uncommitted state first (commit onto its own
      local branch), then `git worktree remove`. **Snapshot done** (`c871f69` on
      local branch `claude/kind-davinci`); worktree removed with `git worktree remove`. **Done.**
- [x] **H2** Remove `backend/pipeline/archive/` (5 old stages + README). Imported
      by nothing; its own README says it is safe to delete. **Done `2d01604`.**
- [x] **H3** Commit the evidence the engineering log cites but git does not hold:
      `baseline60.jsonl.corrupt.bak`, `baseline60.prefix-fix.bak` (ignored as
      `*.bak`), `baseline60.2026-09-13.jsonl`, `smoke.jsonl`. Keep, never delete.
      **Done `abb4667`:** the two cited `.bak` files committed under their original
      names; the two uncited files stay on disk, uncommitted.
- [-] **H4** Back up `eval/snapshots/` (158 MB, gitignored, exists only on this
      laptop). It is the one asset that cannot be rebuilt: pages change and
      disappear, so a re-crawl would produce a different dataset. **Decided by
      the user 2026-09-23: stays on this computer only, no backup.**
- [x] **H5a** Server binds to `127.0.0.1` (README, `run_mac.sh`, `backend/main.py`);
      `ALLOWED_ORIGINS` documented in `.env.example`. **Done.**
- [ ] **H5b** Docs refresh (Phase 6 timing): the three setup documents overlap
      (`README.md`, `README_MAC.md`, `SETUP_AND_ARCHITECTURE.md`), are Gemini-first
      and never mention the all-local Spark setup. Fold `README_MAC.md` and
      `run_mac.sh` into the README (the script also binds the server to
      `0.0.0.0` — fixed in H5a). Also: `.env.example` still says `gemini` is the only
      supported `LLM_PROVIDER`.
- [x] **H7** (user approved 2026-09-25; **done** after the step (c) run) Delete the unused `LOG_SOURCE_SUGGESTION` prompt in
      `backend/pipeline/prompts.py` (nothing calls it; it carries its own "sysmon" table).
      **After** the step (c) run finishes — no code changes during a run.
- [x] **H6** Decide in Phase 3: `backend/pipeline/schemas.py` is imported by
      nothing, but the report's data contract may reuse it. **Done: removed** — it had
      drifted (8 declared fields vs 15 real, no attack-vector model).

## Parking lot — good ideas, deliberately not scheduled

- **From the assistant roadmap (2026-09-28), beyond the thesis:** R13 conversion to SIEM/EDR
  queries (Splunk SPL, Sentinel KQL, Elastic) through pySigma backends with field mappings — Phase 0
  option D; new packages need the user's approval · R14 **prompt-injection hardening** — fetched
  pages are untrusted input; test with poisoned pages · R15 learn from the analyst's decisions (which
  stage errs most; later an evaluation or training set — examples are copied, so carefully) · R16
  detection-as-code: an approved rule becomes a pull request with its test data · R17 watch CTI feeds
  and queue new reports for review · R18 several analysts: logins and an audit trail of who confirmed
  what.

- **A run without retrieval (RAG ablation)** — user, 2026-09-26: later, with the proper testing
  (Phase 5). Answers "does the RAG help?"; never measured (`--arm` is a label, no ablation is wired).

- **Web search for local models**, and following links from the article.
  Researched 2026-09-23. **Provider settled: Ollama's web search API — the user
  has an API key** (to live in `.env` as `OLLAMA_API_KEY`, never in code or
  chat). Queries go to ollama.com. Needs a gold-leakage blocklist (SigmaHQ
  GitHub, sigma.nasbench.dev and other rule mirrors), snapshotting for the
  evaluation, and prompt-injection handling. Best done after Phase 3, as its own
  evaluation arm.
- Defects 4 (substring coverage check), 5 (`json_mode` on generation), 6 (dead
  `fast` tier) — unless Phase 2 data shows they matter. Evidence for 5 so far: every
  no-rule case since Change 15 is the generation JSON failing to parse ("Invalid control
  character", "Invalid \\escape"): 2 cases in the Change 22 run. Reconsider after Phase 2.
- S6 backend compilability.
- **Platform and SIEM/EDR queries** (user, 2026-09-24; Phase 0 option D). What
  exists: the review stage already converts every rule with one pySigma backend,
  InsightIDR (LEQL) — the only backend installed. What it would take:
  - *Platform* is the rule's logsource (`product` windows/linux/…, `category`
    process_creation/webserver/…): the assistant's report can state it in plain
    words from fields the pipeline already produces. It is only as right as the
    logsource — which is why Phase 2 comes first (product right in 26/57 today).
  - *Queries*: more pySigma backends (Splunk, Microsoft Sentinel/Defender,
    Elastic…) — **new dependencies, need the user's approval**. Conversion also
    needs a processing pipeline mapping Sigma's field names to each product's
    schema; a wrong logsource becomes a query against the wrong table or index.
  - *Evaluation*: S6 (does each backend compile the rule) is cheap; whether the
    query *detects* anything needs data in that product — the detonation question.
  - Wording for the thesis: Sigma is rarely deployed as-is but is widely used as
    the portable format that detections are written in and converted from —
    "not used at all" would draw an examiner's objection.
- Fine-tuning — out of scope; argued in Chapter 7.

---

## Decisions log

| Date | Decision | By |
|---|---|---|
| 2026-09-23 | Every stage on `qwen3-coder:30b`; Foundation-Sec dropped | user |
| 2026-09-23 | Pursue the assistant reframing, pending professor | user |
| 2026-09-23 | Slides/deck dropped | user |
| 2026-09-23 | Work follows this plan | user |
| 2026-09-23 | No user study | user |
| 2026-09-23 | No schedule tracking; defence next semester; meetings handled by the user | user |
| 2026-09-23 | Web-search provider, when scheduled: Ollama API (key obtained) | user |
| 2026-09-23 | `eval/snapshots/` stays on this computer only, no backup (H4) | user |
| 2026-09-24 | `thesis/DEFENSE_NOTES.md` stays local only (gitignored; the repository is public) | user |
| 2026-09-24 | Keep Change 12 (whole source): token and time cost is not a concern — everything is local and unbilled; rule quality is the priority, and full context matters for it | user |
| 2026-09-24 | Phase 2 order from 2.1: (a) one vocabulary, (b) the suggestion's service, (c) 2.2 precedence, (d) 2.3 web bias; 2.4 dropped | user |
| 2026-09-24 | One 60-case run per Phase 2 change, so each change's effect can be attributed | user |
| 2026-09-26 | Assistant design reviewed: analyst-confirmed facts are final (one model rewrite, then shown), model suggestions stay recommendations; Phase A state in the persisted session; "revise this rule" in scope later; SIEM/EDR conversion pending Phase 0 | user |
| 2026-09-26 | Phase 2 reordered: after (d), 2.6 (reference table) next — most likely to move S3; 2.5 (invented categories) moved to Phase 3.5 as a quality guard for generated and edited rules | user |
| 2026-09-26 | Runs regrouped (revises "one run per change"): 2.6 runs alone (the change expected to move S3); then defect 15 (a+b), 2.7 and 2.8 share one run — each keeps its own code-counted measure, their S3/S4/S5 effect is reported as joint | user |
| 2026-09-26 | Defect 15 at its cause: (a) the prompt says the examples are invented and their names are never reused, and (b) the examples use placeholders — one change; (c) flagging copies in the report goes to Phase 3 | user |
| 2026-09-26 | 2.6 table: complete (every log source in SigmaHQ's main rule set, one-rule sources included), generated by a committed script, never from the emerging-threats rules | user |
| 2026-09-26 | Prompt review item 1 (the rule writer's example: hyphen tactic tags, no fixed id) joins the shared run as Change 33 | user |
| 2026-09-27 | Interface: a visual-only polish before the live demo (no emojis, own sober look), one revertable commit; the real GUI work stays Phase 4 | user |
| 2026-09-27 | Direction after Phase 2: improve **detection quality**, and in the assistant keep the analyst in the loop to **verify what the LLM understood about the attack** — the tool must not depend on generated rules being right ("it is almost impossible to always produce Sigma rules that are true"). Pending the professor (Phase 0) | user |
| 2026-09-28 | Keep Change 36 (rules as YAML blocks): the failure mode is gone at no measured cost; merge with the review work after the demo. The two run worktrees removed | user |
| 2026-09-27 | Order after Changes 34–35: the simulated-analyst experiment (5.3) first, then defect 5 (rules as YAML blocks, prompt-review item 6); 3.6 only if `run_sync` is ever routed through the review path; merge `analyst-review` into `main` after the demo. No A/A run on its own (it comes as 5.3's by-product) | user |
| 2026-09-27 | Start the confirm/correct step now (Phases 3/4 before the professor's sign-off); first slice = log source + reject items (confirm/reject patterns, techniques, indicators; restore excluded; choose any SigmaHQ log source; a note). Built on a branch; `main` stays the demo's code | user |
| 2026-09-28 | Professor's feedback: explain the good-then-wrong rules (research, with examples); automate more and rely less on the human. Proposed P-A…P-D (consistency, the non-determinism's source, self-consistency with escalation, automated verification) — awaiting decision | professor (via user) |
| 2026-09-26 | Phase 2 frozen at `a6e9157` before the held-out confirmation; open items (quota, defect 5, prompt review, retrieval) go to the next phase | user |
| 2026-09-26 | 2.9 held-out confirmation added: final pipeline and baseline v2 on 60 cases never run before; the chance test moves to the final pipeline's held-out run | user |
| 2026-09-25 | Inbox triage: 2.5 (invented categories) and 2.6 (complete reference table) added after (d); order (d) → 2.5 → 2.6 → ATT&CK ID check → 10 most relevant techniques; Foundation-Sec out of the thesis; paraphrased evidence is fine; delete the unused suggestion prompt | user |
| 2026-09-25 | No hardcoding to get results: the LLM stages decide; code validates against a spec and records. Step (c) is a prompt change with no enforcement | user |
| 2026-09-25 | Step (b): a log source with a category carries no service; without a category the service stays, unknown ones go to the analyst to confirm | user |
| 2026-09-24 | Defect 19: bound every answer (Change 24), treat a cut answer as a model failure; restart the 2.2a run from scratch; add ATT&CK ID check (2.2e) and ≤ 10 techniques (2.2f) as their own steps | user |
