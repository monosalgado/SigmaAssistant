# Action plan

Created 2026-09-23. **This file decides what gets worked on.** Anything not in the
current phase goes to the Inbox or the Parking lot, not into the code.

**Current phase: 2 — Fix the logsource failure.** Phase 1 complete 2026-09-24
(its Inbox triaged with the user 2026-09-25). Phase 0 runs in parallel (it needs the
professor, not the code).

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
      the rule under a real name (18/46). Next: 2.2b.
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
- [ ] **2.3** (step d) Change: remove the attack-vector prompt's web bias (21/48 non-web
      cases labelled web-server telemetry; 16/46 in v2; 18/46 after Change 22). Measure with
      the probe, then the harness. Includes (Inbox 2026-09-25): its worked examples were
      written from specific past cases (Example A is a real saved Citrix rule), and the stage
      still copies example text into answers (`/saml/login` on a rootkit report) — count that
      before and after, with a committed script.
- [ ] **2.5** (user: important) The rule writer invents categories Sigma does not have
      (`email`, `security`: 3 in the Change 25 run). The review stage flags a category not in
      Sigma's taxonomy and the regeneration feedback asks the model to fix it — validation
      against the spec; the model does the fixing. Its own run.
- [ ] **2.6** The analysis stage never suggests a log source without a category, so the 6 gold
      rules defined by a service (Windows Security ×3, …) are always missed. Give its prompt a
      complete reference table (service-based sources too; no "windows/sysmon"). Prompt
      change: the model chooses. Its own run.
      Also (Change 26 run): the table's "linux-windows/apache-iis" cell is copied into the
      web suggestions' `product` (5 of 12 departures); no gold web rule has a product.
- [ ] **2.7** (user, was 2.2e) ATT&CK ID check: drop technique IDs that do not exist in
      ATT&CK (the `mitre` collection), like the rule-id check (Change 9). Changes finished
      answers → its own run. Measure S4 and invented-ID counts.
- [ ] **2.8** (user, was 2.2f) The analysis lists **the 10 most relevant techniques** at most.
      Data (Change 25 run): gold rules use 1 technique (28 of 40), at most 5; the analysis lists
      a median of 6, more than 10 in 14 of 58 cases, 108 in one; of the gold techniques it
      finds (24), 21 are in its first 10 but only 15 in its first 5. All 6 looping answers
      were in the analysis stage. Prompt change → its own run. Measure S4 and answers cut.
- [-] **2.4** Strip page boilerplate (defect 9) — dropped 2026-09-24: 2.1 showed
      nothing pointing to it.

Order agreed with the user (2026-09-24/25): (c) 2.2 → (d) 2.3 → 2.5 → 2.6 → 2.7 → 2.8.

**Before the exit decision:** a committed one-sample exact binomial test of S3 against the
null (0.173) — no tool does this yet (S3 14/57 = 0.246 after step c).
**Exit criteria:** S3 significantly above the null baseline, or the time-box is
spent and the result is written up as a finding.

---

## Phase 3 — Assistant backend (after Phase 0 approves it)

Design: `thesis/ASSISTANT_DESIGN.md` (draft, still to be reviewed by the user).

- [x] 3.0 Defect 13 fixed (`663f005`) — design step 1
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
- [ ] **3.6** Regression: automated path against baseline v2, within run-to-run noise

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
- [ ] **5.3** Simulated-analyst experiment: confirm the gold logsource/techniques,
      regenerate, rescore
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

*(one line each; triaged at the end of the current phase)*

*(Empty. Triaged with the user 2026-09-25 — see the Decisions log. Closed: the paired-test
script and the output limit (done); the no-rule cases (→ defect 5); the connection timeout
(appropriate since Change 24); the shared Spark and the VPN reconnect (one-off, ignored);
Foundation-Sec (out of the thesis entirely); the PoC dotted-tag quirk (known limitation,
CH7 item 27); `.env.example` (already done in H5a); sigma.nasbench.dev (already in the
web-search entry). Scheduled: 2.3, 2.5, 2.6, 2.8, 3.3, 5.6 notes, H7.)*

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
| 2026-09-25 | Inbox triage: 2.5 (invented categories) and 2.6 (complete reference table) added after (d); order (d) → 2.5 → 2.6 → ATT&CK ID check → 10 most relevant techniques; Foundation-Sec out of the thesis; paraphrased evidence is fine; delete the unused suggestion prompt | user |
| 2026-09-25 | No hardcoding to get results: the LLM stages decide; code validates against a spec and records. Step (c) is a prompt change with no enforcement | user |
| 2026-09-25 | Step (b): a log source with a category carries no service; without a category the service stays, unknown ones go to the analyst to confirm | user |
| 2026-09-24 | Defect 19: bound every answer (Change 24), treat a cut answer as a model failure; restart the 2.2a run from scratch; add ATT&CK ID check (2.2e) and ≤ 10 techniques (2.2f) as their own steps | user |
