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
15. **Not every stage runs at temperature 0** (corrected 2026-09-26; it read "Temperature 0 is
    not bit-for-bit repeatable"). Attack vector, PoC and analysis run at 0 — still not
    bit-for-bit repeatable on Ollama — but **generation runs at 0.3 and review at 0.2**, and
    those two write and rewrite the scored rules. Part of any case-level churn between two
    runs is sampling; how much is unmeasured (an A/A run would measure it — prompt review
    M2). (Change 12, defect-15 entries; log correction 2026-09-26)
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
22. ~~Out of the thesis (user, 2026-09-25) — kept so item numbers stay stable.~~ **The Foundation-Sec result is narrow**: base model only, prompts designed for an
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
    (Change 16's rule). **Observed 2026-09-24** (defect 19: an analysis output that loops
    and never finishes, case `9a2d8b3e` under Change 22). The decision on how to treat
    such cases is open — see the log entry "Defect 19".
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
33. **One manual intervention in baseline v2**: after a VPN drop (the user reconnected) the
    tunnel was rebuilt by hand; the relaunch wrapper has not yet recovered a run on its own
    (its rebuild works when tested in isolation). A separate hung LLM call in the same case
    is unexplained. (baseline v2 entry and its correction)
34. ~~The v1 → v2 paired tests ran from a scratch script.~~ **Resolved 2026-09-24**
    (Change 23): `eval/compare_runs.py`, committed and tested, reproduces them; its
    intervals differ from the scratch ones in the last digits and are the ones to cite.
    Kept here so item numbers stay stable.
35. **The logsource diagnosis (plan 2.1) is category-level, one run, n = 57**, with counts
    and no inference. Product, a second failure, is not diagnosed. Its three post-hoc
    measures were chosen after reading the data. "No SigmaHQ rule uses this category" is
    judged against the local corpus copy, not the Sigma taxonomy specification. (2.1 entry)
36. **S3 scores the first rule only**, and the diagnosis shows it matters: the gold
    category is in *some* rule of the response in 29 of 57 cases, in the first in 16.
    First-rule scoring stays (it is what a user sees first), but the thesis should report
    the any-rule figure next to it — as an upper bound, since more rules also mean more
    chances to hit. (2.1 entry)

37. **The Spark is shared with other users.** Another user's application uses the same Ollama
    server, and requests compete. (The two long stalls first blamed on it — case 52 in v2,
    case 34 in the Change 22 run — are more likely defect 19, an output loop.) Time per case (C2) therefore partly
    measures other people's load; token counts do not. Checked: no prompt was cut by a
    smaller context. (log: "The Change 22 run paused…")

38. **The output limit (Change 24) rests on one run's longest answer** (12,374 tokens in
    baseline v2; limit 16,384). It bounds a loop's time but does not prevent the loop: at
    temperature 0 a retry can repeat it. On a loaded shared Spark an attempt could still hit
    the 600 s timeout first and count as an infrastructure failure. (Change 24)
39. **Model failures are scored, infrastructure failures are not** (Change 24's rule). A case
    whose answer is cut on every attempt is written with the stage's empty fallback and
    scored — the pipeline's real behaviour. The count is reported with every result. (Change 24)
40. **Worked examples are copied, whichever examples they are** (Change 27). Replacing the
    web example with an email-malware one removed the old example's text from the vectors
    (4 → 0) but the new one was copied into 2 look-alike reports, and its invented file names
    reached the generated rules. S3 does not detect this (both cases had the right log
    source); the example-copy count is a lower bound (item 30). Copies in the rules are counted
    by the committed counter since 2026-09-26. Defect 15 is reduced, not fixed.
    ("Change 27 measured")
41. **Some diagnosis counts compare different case sets.** The web-label counts are taken
    over cases whose first rule parses, so each run has its own denominator; they are
    reported as counts, not tested. Two denominators were once copied from an earlier run
    instead of the tool's output (numerators right, no conclusion changed; corrected in the
    log). (Chapter 5, "Comparing two runs"; log correction 2026-09-26)
42. **Planned: the last Phase 2 run on the tuning cases carries four changes** (defect 15's fix,
    2.7, 2.8, the rule writer's example — user, 2026-09-26). Their effects on S3–S5 cannot be separated; only each change's own mechanism
    measure can. (Chapter 5, "Attribution")
43. **The 2.6 table is built from SigmaHQ's main rule set, the same one retrieval uses.** The
    gold rules are held out (0 of 437 in it), but the table reflects SigmaHQ's conventions,
    which the gold rules share — intended, since the task is to write rules in that
    convention, and it would have to be said at the defence. The one gold log source only in
    the emerging-threats set (`fortios`/`sslvpnd`) is not on the table. (Change 28)
44. **Phase 2 was tuned on the cases it was measured on** (the 60 seed-0 cases): each change
    came from reading failures there. **Addressed 2026-09-27** by the held-out confirmation (60
    never-run cases): the gain held (S3 0.455, p = 1.2 × 10⁻⁶ against chance; paired vs baseline v2
    p = 0.013). Remaining: it is one held-out sample of 60, and the per-change results (Changes
    22–33) are still tuning-set results — only the final pipeline was confirmed. (Chapter 5,
    "Held-out confirmation"; log 2026-09-26 "Audit")
45. **Code edits model output in three places** — rule ids (Change 9), the length limit
    (Change 24), and the service of a suggestion with a category (Change 25) — plus Change
    8's routing of bare URLs. None looks at the gold. Change 25 is the only one that touches
    a log-source decision, and it acts on the suggestion, not the scored rule. (log "Audit")
46. **Two held-out cases are out of the paired comparison** — baseline v2's code (no output limit)
    could not finish them. Removed by a rule fixed in advance; one of them finished on a fourth
    attempt after three stops and was excluded as the rule says (decided before any score was read;
    including it gives the same p). Both were S3-correct in the final pipeline: the exclusion works
    against the result, not for it. (log 2026-09-27)
47. **The web app never ran its coverage retry (defect 20)** `[DISCLOSE]`. A side effect in the
    retry check is triggered by the progress message first, so the streaming path always skipped
    the retry while saying "regenerating". The harness's path (`run_sync`) calls the check once and
    retries as designed, so **no reported number is affected** — but a description of the web app
    must not claim the retry until it is fixed. (log 2026-09-27, Change 34) **Fixed 2026-09-27** on
    branch `analyst-review`; a test now holds the web app to the harness path's stage calls.
48. **The analyst's review is built but not measured** `[UNMEASURED]` (Change 34). Two live runs on
    one case showed the rules following the analyst's log source and technique choices — anecdotes,
    not evidence. Confirming an item is recorded but changes nothing the rule writer receives. Since
    Change 35 code checks the rules against the review and gives one rewrite for the analyst's log
    source and rejected techniques; **a rejected string used in a detection is only shown**, because
    code cannot tell "not on its own" from "never". The rewrite shares generation's JSON fragility
    (defect 5): once live it gave no rules, and the earlier rules are now kept. What the review is
    worth is for the simulated-analyst experiment (plan 5.3); there is no user study. (log 2026-09-27)

49. **The simulated analyst is an upper bound, on the log source only** `[DISCLOSE]` (CH6 §6.0b). The
    "analyst" is the gold rule: always right, on one decision. Real analysts err, confirm more than
    the log source, and were not studied. The gold is one human's rule — another valid log source
    sometimes exists, and a case where the model's own choice is also defensible counts as wrong. The
    S5 gain is concentrated in the 19 cases whose log source became right (post-hoc). 2 of 60 gold
    log sources are not in SigmaHQ's table and could not be chosen. (log 2026-09-27)
50. **Run-to-run noise is now measured** `[MEASURED]` (CH6 §6.0b): two runs of identical code flip S3
    in 6 of 51 cases and move S5 by +0.086 (CI crosses 0). Phase 2's per-change S3 results were
    paired tests on runs of this noise; the held-out confirmation stands, but single-run S5 changes
    below ~0.1 should not be read as effects. (log 2026-09-27)

51. **One run is one sample** `[MEASURED]` (CH6 §6.0c): two runs of identical code disagree on 16 of
    60 cases, and the temperature-0 first stage concluded differently in 12. Every per-case example
    in the thesis (a good rule, a wrong rule) can come out the other way on another run; results
    are reported as rates with intervals for this reason. The cause of the temperature-0 variation
    is not yet measured. (log 2026-09-28) *Update 2026-09-29 (P-B):* a repeated prompt gets identical
    answers; only the first request of a prompt differed (5 of 5) — the answer depends on the server's
    state, not on chance in the model; the mechanism is not yet tested. *Follow-up:* the label the log
    source follows held for hours today but differed between the September runs a day apart, for
    byte-identical prompts — a property of the deployment (a shared server), not fixable by a seed or a
    warm-up request. Every result is a rate over runs for this reason.
52. **The May demo cannot be rescored, and its prompt was tuned on its reports** `[DISCLOSE]`
    (`thesis/MAY_VS_NOW_NOTES.md`). Only 20 saved answers survive from before September, none
    dated in May, none with a gold rule; which model wrote each is not recorded, nor the prompt text
    between 15 April and 14 May, nor the web-search results. The May attack-vector prompt's worked
    examples were written from the Citrix and BeyondTrust reports it was being run on, so the good
    April/May rules for those reports are not evidence for new reports. The thesis's numbers come
    from September's runs on reports the prompts were not written from (the held-out set). (log
    2026-09-28)
53. **The May rerun measures the May code, not the May system** `[DISCLOSE]` (CH6 §6.0d). Its rule
    writer was qwen3-coder:30b, not Gemini 2.5 Flash; web search was off; the retrieval index was today's
    (the May index no longer exists); bare URLs went straight to rule generation, as today (the May
    classifier sent about half to chat, defect 8); today's LLM client carried the output limit. So the
    +0.37 log-source and +0.16 detection-field gains are what the code and prompts changed with the model
    held fixed. Three runs per version is a small k: consistency is estimated from 3 pairs of runs. (log
    2026-09-29)
54. **Change 38 was tuned and dropped on the tuning set only** `[DISCLOSE]` (CH6 §6.5b). Three
    iterations of one idea (rank log sources by the specificity of their evidence) were tried and judged
    on the 60 tuning cases; none moved the picks towards the human rules, and the change was removed. No
    version ran on unseen reports, so the negative result is as tuning-set-bound as a positive one would
    have been; the v3 comparison is one run against three. The benchmark scores agreement with one human
    rule (or another for the same report), so a pick on more specific evidence that SigmaHQ's authors did
    not choose counts as wrong. Whether such rules are better (fewer false positives) is not measured
    (future work: R10). Confirmation set 2 (`eval/manifest_confirm2.jsonl`, 60 cases) is still unused.
    (log 2026-10-03)

55. **The value score measures agreement, and most of the agreement is out of the report's reach** `[DISCLOSE]`
    (CH6 §6.5c). S5v was defined during the detection work (fixed in the log before it scored a compared run), as
    a post-hoc complement to S5's field names. Only 29–43% of the human rules' values occur in the report, so a
    method that reads only the report has a low ceiling against this benchmark; a rule on other, valid values of the
    same attack counts as wrong. Two changes aimed at the hand-off (40, 41) did not raise it, the second checked on
    60 fresh cases with 3 runs per arm. Whether generated rules detect the attack is not measured (R9, R10). Runs of
    2026-10-04 straddled a restart of the shared server (disclosed in the log). (log 2026-10-03/04)

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
