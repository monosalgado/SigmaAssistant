# Action plan

Created 2026-09-23. **This file decides what gets worked on.** Anything not in the
current phase goes to the Inbox or the Parking lot, not into the code.

**Current phase: 2 — Fix the logsource failure.** Phase 1 complete 2026-09-24
(its Inbox triage is due, with the user). Phase 0 runs in parallel (it needs the
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
- [>] **2.2a** One vocabulary: the attack-vector stage's telemetry reaches the
      analysis and generation stages in Sigma's terms. Measure: categories no
      SigmaHQ rule uses (17/41 wrong rules in v2), S3 paired against v2.
- [ ] **2.2b** The analysis suggestion's `service` (44/57 `sysmon`). Measure.
- [ ] **2.2** (step c) Change: make the (suggested or confirmed) logsource an explicit
      constraint in generation, checked after generation (defect 11); resolve the
      conflict with generation rule 2 ("initial access MANDATORY"). Measure.
- [ ] **2.3** (step d) Change: remove the attack-vector prompt's web bias (21/48 non-web
      cases labelled web-server telemetry; 16/46 in v2). Measure with the probe, then
      the harness.
- [-] **2.4** Strip page boilerplate (defect 9) — dropped 2026-09-24: 2.1 showed
      nothing pointing to it.

2.1 decides the order of 2.2–2.4.

**Exit criteria:** S3 significantly above the null baseline, or the time-box is
spent and the result is written up as a finding.

---

## Phase 3 — Assistant backend (after Phase 0 approves it)

Design: `thesis/ASSISTANT_DESIGN.md` (draft, still to be reviewed by the user).

- [x] 3.0 Defect 13 fixed (`663f005`) — design step 1
- [ ] **3.1** Report builder: a pure function from pipeline context to the report *(offline)*
- [ ] **3.2** Split the orchestrator into analyse → checkpoint → generate, with the
      automated path unchanged *(offline)*
- [ ] **3.3** Evidence quotes, with code checking that each quote is on the page. Measure.
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

- Only ~26% of `derived_from` quotes are verbatim — the model paraphrases what it
  cites. Relevant to 3.3.
- 2 cases of the first baseline produced no rule (86-char non-YAML reply); cause
  unknown until 1.1 keeps the response text.
- `sigma.nasbench.dev` ("Phoenix") mirrors all SigmaHQ rules, including the 457
  emerging-threat rules that are our gold answers. **Must be on any web-search
  or link-following blocklist** (gold leakage).
- Phoenix lists Atomic Red Team mappings and EVTX downloads. SigmaHQ's own
  `regression_data` has 138 EVTX files, but only **2 of our 437** emerging-threat
  rules and **0 of the 60-case sample** have one. So ready-made EVTX would support
  detonation (5.6) only on a different rule set, or next to lab runs.
- The attack-vector prompt's worked examples were written from specific past
  cases: `data/saved_rules.json` holds a real "CVE-2026-3055 Citrix NetScaler SAML
  … NSC_TASS" rule, which is Example A. Examples this specific are what the model
  copied (defect 15). Relevant to 2.3.
- The PoC stage's GitHub link pattern has no dot in the branch/tag part, so links
  to tags like `v1.2` are never fetched (pinned by a test, not changed).
- The Foundation-Sec probe (CH6 §6.5) ran from uncommitted scratch scripts; rerun it from a
  committed script before citing it.
- `.env.example` lacks `ALLOWED_ORIGINS`, which `backend/main.py` reads. Trivial;
  fold into H5.
- ~~The v1 → v2 paired tests ran from a scratch script.~~ Done 2026-09-24:
  `eval/compare_runs.py` (Change 23, user-approved) reproduces them.
- Example copying persists in the full pipeline: in baseline v2 a Windows
  kernel-rootkit case got Example A's `/saml/login`. Count it over v2's recorded
  attack vectors with the probe's markers. Relevant to 2.1/2.3.
- A silent connection costs up to ~30 min before the stop rule sees it (OpenAI
  client defaults: 600 s per request × 3 attempts). A shorter timeout for local
  runs would lose less time; the stop rule already keeps the data clean.
- The Ollama client sets no output limit (`max_tokens`): a generation that never
  stops runs until the timeout — one hypothesis for baseline v2's hung analysis
  call. An output cap is a pipeline change (it could cut long legitimate answers),
  so it needs its own measurement.
- GlobalProtect's auto-restore ends at "select a gateway … manually", so a VPN drop
  needs the user; the relaunch wrapper gives up after ~12 min. Options: wait longer,
  or the user sets a default gateway in the app (their setting, not ours).

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
  `fast` tier) — unless Phase 2 data shows they matter.
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
