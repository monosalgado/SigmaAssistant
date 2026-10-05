# Chapter 4 — System design: working notes

Working notes for the system chapter. Not prose; the user writes the chapter. Started 2026-10-05 (user: "write the
chapter 4 notes first"), describing the system **as it is in `main` at `c81c989`**, read from the code, not from
memory. Tags as in the other chapter notes: `[DESIGN]` a decision and its reason, `[MEASURED]` a number with its
source, `[DISCLOSE]` something an examiner should hear from us first. "Change N" refers to the engineering log.

---

## 4.0 What the system does `[DESIGN]`

Input: the URL(s) of a cyber-threat-intelligence report (or pasted text). Output: Sigma detection rules, plus what
the model understood about the attack (attack vector, indicators, ATT&CK techniques, recommended log sources).
Two ways through the same stages:
- **Automated** (`PipelineOrchestrator.run_sync`) — every stage in one go; this is the path the evaluation measures.
- **Assisted** (`analyse_for_review` → the analyst's review → `generate_after_review`) — the run stops after the
  analysis, an analyst confirms or corrects it, and the rules are written from the reviewed analysis (Changes 34–35;
  design `thesis/ASSISTANT_DESIGN.md`). This is the web app's path.

## 4.1 Architecture at a glance `[DESIGN]`

| Part | What it is | Where |
|---|---|---|
| Web app | FastAPI backend, server-sent events for stage progress; plain-JavaScript front end; sessions and saved rules on disk; binds to `127.0.0.1` | `backend/main.py` (routes `/analyze_stream`, `/generate_stream`, `/sessions`, `/rules`, `/translate`, `/logsource_choices`), `frontend/` |
| Pipeline | eight stage classes over one shared `context` dict; prompts in one module | `backend/pipeline/` (`orchestrator.py`, `stage_*.py`, `prompts.py`) |
| Model | **every stage on `qwen3-coder:30b`**, served by Ollama on a DGX Spark, reached over an SSH tunnel (USF VPN); the client speaks Ollama's OpenAI-compatible API | `backend/llm_client.py` (`OllamaLLMClient`), `backend/tunnel.py` |
| Retrieval | ChromaDB, local embeddings (`all-MiniLM-L6-v2`, 384-dim, CPU) | `backend/vector_store.py`, `data/chroma_db/` |
| Validation | pySigma 0.11.23 core validators (deterministic) | `stage_review.py` |
| Conversion | pySigma InsightIDR (LEQL) backend — the only backend installed — behind `/translate` | `backend/translation/` |
| Telemetry | every model call records stage, tokens, latency, errors, cut answers | `backend/telemetry.py` (Change 13) |

`[MEASURED]` Retrieval collections (2026-10-05): `sigma_rules` 3,104 (SigmaHQ's **main** rule set only),
`mitre_attack` 691, `cwe_kb` 944, `sigma_taxonomy` 332, `sysmon_info` 18. **0 of the 437 emerging-threats rules**
(the evaluation's answers) are in the index (CH5 §5.1).
`[DISCLOSE]` The client still contains Gemini code paths (three tiers, rate limiter, web search, image input); they
are dormant since the Gemini key was withdrawn (2026-09-23). On the local setup **web enrichment returns nothing** and
**image/PDF input is not transcribed**.

## 4.2 The pipeline, stage by stage `[DESIGN]`

| # | Stage | Job | Model call | Notes (why it is like this) |
|---|---|---|---|---|
| 0 | Intent routing | chat vs rule request | none for a bare URL | A bare URL goes straight to rule generation (**Change 8**: the classifier sent about half of bare links to "chat", skipping every grounding stage — defect 8) |
| 1 | Preprocess | fetch the pages, split into segments, build `combined_text` | none (image transcription only via Gemini) | 10 s fetch timeout; URL fragments handled (Change 10) |
| 2 | Web enrichment | search the web for more context | — | no-op locally (Gemini grounding); parked (ACTION_PLAN Parking lot) |
| 3 | PoC analysis | code in the text and in linked GitHub files → behavioural indicators | T = 0, JSON | ≤ 5 snippets; the GitHub fetches are snapshotted for the evaluation (Change 17) |
| 3b | Attack vector | **anchors the pipeline**: how the attack starts, entry point, attacker input, **payload signatures** (1–8 patterns, where seen, the quote), **incidental strings** (researcher/patch artefacts to keep out of rules), primary telemetry | T = 0, JSON | reads the whole source up to 100,000 characters (**Change 12**); telemetry in Sigma's vocabulary (Change 22); worked examples as placeholders, no real-case values (Changes 27, 30, 39) |
| 4 | Analysis | indicators, attack summary, ATT&CK techniques, **log-source suggestions** — one combined call | T = 0, JSON | log-source table generated from SigmaHQ's main rules (Change 28); a service only without a category (Change 25); technique IDs checked against ATT&CK, invented ones dropped and recorded (Change 31); ≤ 10 techniques (Change 32); stray backslashes repaired before reading (Change 37) |
| 5 | Generation | write the Sigma rules | **T = 0.3**, answer as YAML blocks | see 4.3; rule IDs assigned in code, not by the model (Change 9); YAML blocks, not JSON strings (Change 36) |
| 6 | Review | pySigma validation, then the model optimises | T = 0.2, JSON | validation is deterministic; a validator that raises no longer discards the request (Change 11) |
| 7 | Coverage check | do the rules use the payload signatures and match the entry point; do they use incidental strings? | none (code) | substring matching (defect 4, open) |
| — | Retry | **at most one regeneration per request**: on validation errors, else on coverage gaps (≥ 50% of signatures unused, initial access not covered, an incidental string used) | — | skipped when the attack-vector stage's confidence < 0.4 |
| — | Record | which analysis indicators the final rules use | none | measurement only (kept from Change 40) |

`[MEASURED]` Every model answer is bounded at **16,384 tokens**; a cut answer is retried twice, then recorded as the
model's failure (**Change 24**, defect 19 — an answer once looped through 336 invented sub-techniques).

## 4.3 What the rule writer sees — and does not see `[DESIGN]` `[DISCLOSE]`

Inputs (`RULE_GENERATION`): the attack-vector summary; **a block recommending the analysis's log source for the first
rule** and what that log source leaves out (Changes 26, 29); the payload signatures (first 10, with where/quote) under
"strings a real attacker MUST produce — prefer these"; the incidental strings to avoid; the attack summary; the
analysis's indicators (as JSON) and ATT&CK mappings; retrieved context — 3 similar SigmaHQ rules and Sysmon notes, 10
taxonomy entries for the log source's fields, 3 CWE entries, 5 ATT&CK entries.
**It does not see the report itself.** Everything it knows about the attack passes through stages 3–4. This is a
deliberate anchor (earlier, rules picked up incidental strings from the page) and a measured bottleneck: of the human
rules' values that are in the report, about a third were never passed on by any stage (CH6 §6.5c).
`[MEASURED]` The rule writer follows the payload signatures (196 of 257 used in `c36_yaml60`, summed from the
coverage check's own record) and largely not the indicator list (35 of 609 reach the first rule where the log source
is right, `diagnose_detection.py`); framing the indicators as "the strings the report gives" did not change that (Change 40,
removed). It departs from a correct log-source recommendation in some cases (defect 11, open).

## 4.4 The assisted path — the analyst confirms what the model understood `[DESIGN]`

`analyse_for_review` runs stages 0–4 and stops at a **checkpoint**: the analysis is saved in the session
(`review_sessions.py`). The analyst (front end: the Analysis panel) can **confirm or reject** each technique, indicator
and attack pattern, **restore** an excluded string, **choose the log source** from SigmaHQ's table (validated —
`/logsource_choices`), and add a **note**. `apply_review` (`analyst_review.py`) applies it: rejected items do not
reach generation; one decision per string (copies of a rejected string are rejected with it, exact match); a choice
outside SigmaHQ's table is refused (`ReviewError`). `generate_after_review` writes the rules from the reviewed
analysis, then **checks them against the review** (Change 35): a rule departing from the analyst's log source or
using a rejected technique gets **one** rewrite; rejected strings found in a detection are shown, not rewritten.
**Principle (design §9):** what the analyst confirms is final; what the model suggests stays a recommendation.
`[MEASURED]` Upper bound of what a right analyst is worth (simulated analyst, CH6 §6.0b): S5 +0.144 [0.056, 0.241].

## 4.5 Design principles, each with its evidence `[DESIGN]`

- **The model decides; code validates against a specification and records** (user, 2026-09-25). Code never invents
  content: it checks log sources against SigmaHQ's table, technique IDs against ATT&CK, the analyst's choices, the
  coverage of payload signatures — and records what it found.
- **Anchor on the attack vector** so that later stages do not latch onto incidental strings (patch names, a
  researcher's tooling).
- **Placeholders, not realistic examples, in prompts** — the model copies concrete examples into reports that resemble
  them. Counted by code: Change 27 removed the old example's copies (4 → 0) but its replacement was copied in 2
  reports; Change 30 (placeholders) took the copies to 0 (1/1/6 → 0/0/0); Change 39 removed the inline example
  patterns (2 → 0 reports).
- **Bounded outputs and one retry** — a loop or a broken answer costs one case, not the run (Change 24; retry cap).
- **Graceful degradation per stage** — each stage catches its failure and continues on a default. Good for a user;
  dangerous for an evaluation (failures look like normal results) — hence the harness's counts and gates (CH5 §5.9).
- **Everything local** — cost and tokens are not a constraint (user, 2026-09-24: quality first); no report text leaves
  the machine except to the Spark.

## 4.6 Tried and removed (the system chapter should say they existed) `[DESIGN]`

| Change | Idea | Why removed | Where |
|---|---|---|---|
| 38 | rank log sources by how specific their evidence is (v3: a separate ranking call) | no gain in 3 iterations; v3 moved picks away from the human rules | CH6 §6.5b |
| 40 | show the indicators as "the strings the report gives" next to the payload signatures | failed its gate (S5vu −0.030) | CH6 §6.5c |
| 41 | a separate evidence step copying the report's strings verbatim, checked by code, added to the payload signatures | passed the tuning gate, **not confirmed** on 60 fresh reports | CH6 §6.5c |
| P-C | self-consistency: vote over several sampled analyses | shelved after a 2-case pilot (both unanimous and wrong) | log 2026-10-03 |

## 4.7 Known limits and open defects `[DISCLOSE]`

- Defect 4: the coverage check matches substrings. Defect 6: the dead `fast` tier. Defect 9: some pages extract to
  almost no text. Defect 11: the rule writer departs from a correct recommendation. Defect 15: example copying,
  reduced to 0 by Changes 30/39 but structurally possible.
- The review prompt still carries a worked example from a real report (Citrix `/metadata/samlidp/asdf`) — Inbox.
- Generation runs at T = 0.3 and review at 0.2; analysis stages at 0. Even at T = 0, answers vary between sessions on
  the shared server (P-B, CH6 §6.0c).
- No web search and no image input on the local setup; no SIEM conversion beyond InsightIDR (Phase 0 option D).

## 4.8 Size `[MEASURED]` (2026-10-05)

Backend ~7,800 lines with the front end (`backend/*.py`, `backend/pipeline/*.py`, `frontend/script.js`); the largest
files are the front end (1,255), prompts (835), orchestrator (766). Tests: 65 files, **746 passing**, all offline.
