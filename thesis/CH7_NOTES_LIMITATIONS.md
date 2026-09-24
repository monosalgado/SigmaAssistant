# Chapter 7 — Limitations and Future Work: working notes

**Purpose.** Every limitation the project has had to disclose, collected in one place so
none is lost between the engineering log and the thesis. Not prose. Each item says where
it comes from. Grouped by what it limits; within a group, the ones an examiner is most
likely to raise come first.

Started 2026-09-23, from the "Limitations to disclose" sections of `ENGINEERING_LOG.md`
and the `[DISCLOSE]` items of `CH5_NOTES_EVALUATION.md`. **Keep adding** — a new
limitation in the log belongs here too.

---

## A. What the evaluation can claim at all

1. **No detection-efficacy claim.** All metrics are static (S1–S5): they measure agreement
   with human-written rules and conformance to the Sigma spec, not whether a rule fires on
   an attack. True/false positive rates (R1/R2) need detonated telemetry; not built.
   Overclaiming here is the most obvious way to lose the defence. (CH5 §5.0, OUTLINE §5)
2. **S5 compares field names only**, not values: `Image|endswith: '\evil.exe'` and
   `'\good.exe'` score the same. It measures "looked at the right telemetry fields", not
   semantic equivalence. (CH5 §5.2)
3. **The null baseline is a discrimination control, not a competing system.** A naive
   baseline arm (e.g. always the most common logsource) is not built yet. (CH5 §5.3)
4. **Scores use the first rule of each response.** Deliberate (what a user sees), but a
   best-of-N view would score higher; all rules are stored so it can be computed.
   (baseline-run entry)
5. **No user study** (user decision, 2026-09-23). The assistant can be evaluated only by
   simulation: confirming the *correct* logsource/techniques shows what confirmation is
   worth **when the analyst is right**, not that real analysts are helped. (ACTION_PLAN
   Phase 0)

## B. The data

6. **Pretraining contamination.** SigmaHQ is public; the gold rules are very likely in the
   model's training data. Zero overlap with *our retrieval index* (0 of 437) does not fix
   this. It biases absolute scores upward; between-arm deltas are affected roughly
   equally. Partial mitigation: report post-cutoff (CVE-2024/2025) rules separately.
   (CH5 §5.1)
7. **Some inputs already contain a detection rule** — 23 of 303 (5 of 60), by a heuristic
   that over-counts (upper bound). Handled by flagging and reporting separately; on
   baseline v1 it did not move the headline (≤ 0.008). (Change 18)
8. **Category skew**: `process_creation` is ~40% of cases; an unweighted mean is largely a
   statement about that category. Per-category or weighted reporting still to decide.
   (CH5 §5.1)
9. **The ≥ 2,000-character threshold is a judgment call** (303 cases at ≥ 2k, 257 at ≥ 5k);
   results should be shown not to depend on it. (defence notes)
10. **robots.txt was not honoured** when building the dataset (250 cases with it, 303
    without); both datasets exist — report 303, with 250 as a robustness check.
    (CH5 §5.1, DEFENSE_NOTES)
11. **Snapshots may differ from what the rule author read**, and the web keeps changing:
    12 of 437 reference pages were already 404, and 10 of 45 linked GitHub files had
    disappeared by 2026-09-23. Frozen snapshots make runs reproducible, not identical to
    authoring time. (CH5 §5.1, Change 17)
12. **A Sysmon-based detonation lab can exercise only ~63% of the corpus** (the
    Sysmon-observable categories); the rest (web, proxy, cloud…) needs other telemetry.
    (defence notes)
13. **Page boilerplate survives extraction** (defect 9): since Change 12 the article is
    *included* in what the stages read, not *isolated* from the navigation around it.

## C. Statistics

14. **n = 60, one sample, one seed.** Enough to say S3 is indistinguishable from chance;
    not enough for fine comparisons between S4/S5 and their baselines. Measured size of
    the problem: comparing v1 and v2 paired, the 95% intervals on S4/S5 differences are
    about ±0.08 — smaller effects are invisible. (baseline-run entry; baseline v2 entry)
15. **Temperature 0 is not bit-for-bit repeatable** on Ollama; part of any case-level
    churn between two runs is run-to-run variation. (Change 12, defect-15 entries)
16. **Subgroups are tiny**: e.g. 5 contaminated cases, 3–5 per metric. No conclusion about
    them. (Change 18)
17. No correction for multiple comparisons yet (the outline plans Holm–Bonferroni across
    the ablation family). (OUTLINE §5)

## D. The model and the setup

18. **One model**, `qwen3-coder:30b`, on every stage (user decision, 2026-09-23). Results
    are about this pipeline with this model.
19. **All-local operation silently disables web enrichment and image/PDF input** — the
    base client's `web_search` returns empty text and the Ollama client does not support
    images (`backend/llm_client.py`: `LLMClient.web_search`, `OllamaLLMClient.make_image_part`).
    No error is raised; the stages just receive nothing.
20. **The Gemini thinking-token path was never verified live**; the key was suspended,
    then deleted. The thinking-token cost argument stays a design argument. (CH5 §5.4)
21. **The server's context size is not set by the code.** It is 262,144 on the Spark
    today and the preflight checks it is ≥ 32k before every run; a different server could
    truncate prompts silently. (Changes 12, 20)
22. **The Foundation-Sec result is narrow**: base model only, prompts designed for an
    instruction model, 3 cases, scripts not committed. Not evidence about the Instruct
    model. (CH6 §6.5)

## E. The fixes themselves

23. **Changes 1–3 have no measured quality effect** — they landed before the harness
    existed. Write them as audit findings, not improvements. (CH5 §5.7)
24. **The bare-URL rule (Change 8) is a heuristic**: fewer than 10 alphanumeric characters
    outside the URLs, tuned on 35 observed inputs; defensible as a bound, not an optimum.
    It constrains the classifier's input rather than improving the classifier.
25. **Change 9 repairs the symptom** (invalid ids), not the cause; ids are no longer
    reproducible run to run, so byte-exact comparisons must ignore `id:`.
26. **Change 12 cut example copying on its stage but showed no detectable effect on
    S1–S5** in baseline v2 (paired, n = 60), while costing +45% tokens and +65% time per
    case end to end. Report it as a grounding fix with a cost, not as a quality
    improvement. (Change 12; baseline v2 entry)
27. **The PoC stage never fetches GitHub links to tags containing a dot** (`v1.2`) — an
    existing quirk, pinned by a test, not changed. (Change 17)
28. **A deterministic LLM-call failure would stop a run at the same case every time**
    (Change 16's rule). Not observed; would need a decision if it happens.
29. **Baseline v1 carries two caveats**: its PoC inputs were fetched live, and a crash
    would not have been recorded as one. (Change 19)

## F. The measurement tools

30. The defect-15 **example-copy metric is a lower bound** (only invented marker strings
    count; a paraphrased copy does not), and the **verbatim-quote metric is an upper
    bound** on invention (honest paraphrase also misses). (defect-15 entry)
31. Both are heuristics, but with different histories — state them honestly:
    the defect-15 **example markers were fixed before the results were seen**
    (pre-registered in the script's docstring and tests); the **contamination definition
    was written during the first, exploratory measurement** and only then formalised in
    code, which reproduced the same counts exactly. Neither was tuned afterwards to move
    a result. (defect-15 entry, Change 18)

## G. Baseline v2 (added 2026-09-24)

32. **Baseline v1 → v2 is not a single-variable comparison**: Changes 11 and 12, PoC
    inputs from snapshots instead of live, and run-to-run variation all differ. A
    difference could not be attributed to one of them (none was found). (baseline v2 entry)
33. **One manual intervention in baseline v2**: during a network outage the tunnel was
    rebuilt by hand; the relaunch wrapper has not yet recovered a run on its own (its
    rebuild works when tested in isolation). (baseline v2 entry)
34. **The v1 → v2 paired tests ran from a scratch script** (scipy/numpy, installed but not
    declared). Until a committed script reproduces them, they are working numbers, not
    citable ones — the same standard as the Foundation-Sec probe (item 22). (baseline v2
    entry)
35. **The logsource diagnosis (plan 2.1) is category-level, one run, n = 57**, with counts
    and no inference. Product, a second failure, is not diagnosed. Its three post-hoc
    measures were chosen after reading the data. "No SigmaHQ rule uses this category" is
    judged against the local corpus copy, not the Sigma taxonomy specification. (2.1 entry)
36. **S3 scores the first rule only**, and the diagnosis shows it matters: the gold
    category is in *some* rule of the response in 29 of 57 cases, in the first in 16.
    First-rule scoring stays (it is what a user sees first), but the thesis should report
    the any-rule figure next to it — as an upper bound, since more rules also mean more
    chances to hit. (2.1 entry)

---

## Future work (collected, not prioritised)

- Detonation-validated evaluation (R1/R2) with the lab's Metasploit Pro → Sysmon → EVTX →
  Zircolite chain — contribution 1, if agreed.
- RAFT-style tuning of *how the model uses retrieval*; KTO with pySigma pass/fail as the
  free binary signal. No fine-tuning of facts (Ovadia et al.: RAG beats it).
- Web search for local models (Ollama's web search API) as its own evaluation arm, with a
  gold-leakage blocklist (SigmaHQ, rule mirrors such as sigma.nasbench.dev) and
  prompt-injection handling.
- Quantisation × structured-output correctness — an open gap in the literature.
