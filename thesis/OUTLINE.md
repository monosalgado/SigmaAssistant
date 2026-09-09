# Thesis Outline — SigmaAssistant

Working title: *Automated Generation and Detonation-Validated Evaluation of Sigma
Detection Rules from Unstructured Cyber Threat Intelligence*

Status legend: `[ ]` not started · `[~]` partial · `[x]` done

---

## 0. Positioning problem (read this first)

**SIGMERGE** (Cai et al., USENIX Security 2026) covers nearly the same topic:
LLM-based Sigma rule generation from CTI reports, 3-stage pipeline, 16 baselines,
13 LLMs, 23 metrics, 7 datasets, 4 rules accepted into SigmaHQ.

We cannot compete on scale. We compete on the axis they did not measure.

### Defensible novelty claims
1. **Detonation-validated evaluation** — measured false negatives and false positives
   from real telemetry (Metasploit Pro lab → Sysmon → EVTX → Zircolite). Every prior
   work evaluates rules statically; Bertiger et al. explicitly note false negatives
   "are incredibly hard to track."
2. **Cost–quality Pareto analysis of tiered local/cloud routing** for detection
   engineering. Framed with FrugalGPT / RouteLLM metrics (CPT, APGR).
3. **Evaluation of security-domain-pretrained models** (Foundation-Sec-8B) on Sigma
   generation.

Claims 1 and 3 are the strongest. Claim 2 is the most likely to produce a clean figure.

---

## 1. Introduction `[ ]`
- Problem: CTI is unstructured prose; detection rules are structured DSL; the gap is
  manual, slow, and expertise-bound.
- Why Sigma specifically: vendor-neutral, compiles to many backends, public corpus.
- Contributions = the three novelty claims above.

## 2. Background `[ ]`
- Sigma rule anatomy: `logsource` (category/product/service), `detection` selections,
  `condition` grammar, `tags`.
- pySigma: parsing, 31 validator classes, backend conversion.
- MITRE ATT&CK: tactics, techniques, the tactic↔technique consistency constraint.
- Sysmon / Windows Event Log telemetry model.

## 3. Related Work `[~]`
Citations verified — see `~/.claude/.../memory/thesis-literature.md` for full entries.

| Section | Key works |
|---|---|
| 3.1 LLMs for detection engineering | SIGMERGE (USENIX Sec 2026); LLMCloudHunter (ACSAC 2024, arXiv 2407.05194); CTI-REALM |
| 3.2 Benchmarks | CTIBench (NeurIPS 2024 D&B); Bertiger et al. (CAMLIS 2025, arXiv 2509.16749) |
| 3.3 Self-correction | Huang et al. (ICLR 2024, arXiv 2310.01798) — intrinsic self-correction degrades; external verifiers work |
| 3.4 Structured generation | Tam et al. (arXiv 2408.02442); XGrammar |
| 3.5 RAG | Hybrid dense+sparse + RRF; Self-RAG (2310.11511); CRAG |
| 3.6 Small models / tuning | Ovadia et al. (EMNLP 2024, 2312.05934); RAFT (2403.10131); Gudibande et al. (2305.15717); LIMA (2305.11206); KTO (2402.01306); Foundation-Sec-8B (2504.21039) |
| 3.7 Cost routing | FrugalGPT (2305.05176); RouteLLM (2406.18665) |

**Gap statement:** none of the above measures detection efficacy on detonated
telemetry. All evaluate rules as text.

## 4. System Design `[~]`
Describes the implemented pipeline. Source of truth for current behaviour:
`memory/architecture-audit.md` (verified by reading code, not inferred).

- 4.1 Pipeline decomposition (8 stages) and the rationale for each split
- 4.2 Model tier routing — **and its current defects** (see log entry 2026-08-06)
- 4.3 RAG corpus construction and retrieval
- 4.4 Validation and the regeneration loop

Write this chapter *after* the Tier 1 fixes land, so it describes the fixed system,
with the defects documented in Chapter 6 as findings.

## 5. Evaluation Methodology `[~]`  ← **the empirical backbone**

> **Working notes with all measured numbers: `CH5_NOTES_EVALUATION.md`.** Write this
> chapter from that file.
>
> **Metric IDs are S / R / C** (static, runtime, cost) — see the metric suite below.
> The old E0–E7 scheme is retired; it collided across three files. Resolved 2026-09-09.

### Datasets
- **D1 Holdout (leave-one-out):** remove a SigmaHQ rule, regenerate from its source CTI,
  compare. Methodology follows Bertiger et al.
- **D2 Temporal split:** rules published after the model cutoff. Guards against
  memorisation.
- **D3 Detonation set:** attacks executed in the Metasploit Pro lab, Sysmon telemetry
  captured as EVTX.
- **D4 Benign telemetry:** normal lab activity, for false-positive measurement.

> **Leakage trap:** SigmaHQ rules are *not* paired with source CTI. Do not synthesise
> pairs by reverse-generating a report from a rule — the report embeds the rule's own
> fields and results become meaningless. D1 requires hand-built real CTI→rule pairs.

### Metric suite

Three families. The split is deliberate: it makes visible which half of the evaluation
is built and which half is still the open novelty claim.

**S — Static.** Offline, from generated rule text alone. *Implemented, S1–S5.*

| ID | Metric | Oracle | Status |
|---|---|---|---|
| S0 | Generation produced non-empty output (refusal vs. malformed) | — | folded into S1 |
| S1 | Syntactic validity — parses via `SigmaCollection.from_yaml` | pySigma | built |
| S2 | Semantic validity — violations by validator class (31 classes) | pySigma `SigmaValidator` | built |
| S3 | Logsource accuracy — category/product/service vs. gold | gold rule | built |
| S4 | MITRE mapping accuracy — technique, exact + parent | gold rule / ATT&CK | built |
| S5 | Detection field-name overlap — P/R/F1 | gold rule | built |
| S6 | Backend compilability — converts to a target backend | pySigma backend | **not built** |

**R — Runtime.** Require detonated telemetry. *Not built — this is novelty claim 1.*

| ID | Metric | Oracle | Status |
|---|---|---|---|
| R1 | Detection efficacy — TPR on D3 | Zircolite over EVTX | **not built** |
| R2 | False-positive rate on D4 | Zircolite over EVTX | **not built** |

**C — Cost.** *Implemented in `backend/telemetry.py`.*

| ID | Metric | Oracle | Status |
|---|---|---|---|
| C1 | Tokens / cost per rule, per tier | instrumentation | built, **unverified live** |
| C2 | Latency per rule, per tier | instrumentation | built, **unverified live** |

S2 reporting **by validator class** is better than a binary valid/invalid — it gives a
richer dependent variable for the ablations.

> **Numbering note.** This replaces an earlier E0–E7 scheme that collided across three
> files (E3, E5, E6 and E7 each meant different things in `OUTLINE.md`,
> `eval/scorers.py` and `backend/telemetry.py`). Do not reintroduce E-numbers.
> `R` is used rather than `D` because D1–D4 already name the *datasets* above.

### Ablation matrix
| ID | Arm | Isolates |
|---|---|---|
| A1 | No RAG | whether local grounding helps at all |
| A2 | Exemplars as dict-repr (current) vs. real YAML | the `vector_store.py:163` bug |
| A3 | Windows-only corpus vs. full corpus | the `ingest_rules.py:38` filter |
| A4 | No pySigma feedback in the retry loop | external verifier value (Huang et al.) |
| A5 | Single-shot vs. full 8-stage pipeline | is the decomposition earning its cost |
| A6 | Per-stage tier assignment | cost–quality Pareto |
| A7 | Constrained decoding on `condition:` only | Tam et al. tension |

### Statistical rigour
- k seeds per condition (k ≥ 5), report variance not just means
- McNemar's test for paired binary outcomes (rule valid / invalid)
- Bootstrap confidence intervals for rates
- Holm–Bonferroni correction across the ablation family

## 6. Results and Discussion `[ ]`
- 6.1 Baseline system performance across S1–S5 and C1–C2
- 6.2 Ablation findings
- 6.3 Cost–quality Pareto frontier
- 6.4 Defects found by systematic evaluation (the Tier 1 bugs) — framed as evidence
  that static review misses grounding failures

## 7. Limitations and Future Work `[ ]`
- Lab telemetry is not production telemetry; single Windows environment
- No fine-tuning — justified, not merely omitted: Ovadia et al. (RAG beats FT for
  knowledge injection), Gudibande et al. (imitation copies style, not capability),
  LIMA (~1k example floor vs. our 7 saved rules)
- Future: RAFT-style tuning of retrieval-use behaviour; KTO using pySigma pass/fail as
  the free binary signal; quantization × structured-output correctness (an open gap)

## 8. Conclusion `[ ]`

---

## Artefacts this thesis must produce
- [ ] `eval/` harness runnable end-to-end with one command
- [ ] Results tables auto-generated from harness output (no hand-copied numbers)
- [ ] The four datasets D1–D4, documented and reproducible
- [ ] Engineering log — see `ENGINEERING_LOG.md`
