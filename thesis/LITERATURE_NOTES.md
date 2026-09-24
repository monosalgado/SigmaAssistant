# Literature notes

Working notes for Chapter 3 (Related Work) and for citations elsewhere. Not prose.
Gathered 2026-08-06 (arXiv IDs verified by web search then); updated 2026-09-23.
Moved into the repository from the assistant's private notes on 2026-09-23.

---

## Direct prior art — must cite and differentiate against

- **SIGMERGE — "From Texts to Rules: Generating Sigma Rules with LLMs from Cyber Threat
  Reports"**, Cai, Qiu, Li, Cheng, Chen. USENIX Security 2026.
  https://www.usenix.org/conference/usenixsecurity26/presentation/cai
  Essentially the same topic. 3-stage pipeline: fine-tuned domain LLM for ATT&CK
  extraction → preference-optimisation-tuned description generation with **closed-loop
  self-validation** → parameter-optimised retrieval. 16 baselines, 13 LLMs, 23 metrics,
  7 datasets, 4 rules accepted into SigmaHQ.
  *Differentiation to verify in the paper before claiming it:* their loop is closed by
  self-validation, not by an analyst — relevant if the thesis becomes the assistant
  (evidence-backed report + analyst confirmation). We cannot compete on scale.
- **LLMCloudHunter**, Schwartz, Benshimol, Mimran, Elovici, Shabtai. ACSAC 2024,
  arXiv 2407.05194. The paper SigmaAssistant's architecture is modelled on.
  GPT-4o, no fine-tuning. API-call extraction 92% P / 98% R; IoC 99% P / 98% R; 99.18% of
  rules compiled; condition-logic accuracy 100%; criticality 75.41%; overall extraction
  80% P / 83% R. Limits: 12 OSCTI sources, cloud-only; TTP extraction is their weakest
  component.
- **CTI-REALM**, Chakraborty, Ho, Cook, Meléndez. arXiv 2603.13517v2 (2026). Benchmarks
  agents on validity, detection efficacy and MITRE mapping.

## Benchmarks and evaluation methodology

- **CTIBench**, NeurIPS 2024 Datasets & Benchmarks (spotlight). ATT&CK mapping ceilings:
  ~94% tactic-level, ~82% technique-level — the bar for the S4 metric.
- **"Evaluating LLM Generated Detection Rules in Cybersecurity"**, Bertiger, Filar,
  Luthra, Meschiari, Mitchell, Scholten, Sharath (Sublime Security). CAMLIS 2025,
  arXiv 2509.16749. Metrics: detection accuracy ½(TP/(TP+FP) + uniqueTP/(TP+FP)); cost of
  syntactic correctness (pass@k 1–3, $1.51–$5.13 per rule); robustness 1 − B/100.
  Holdout methodology: remove human rules one at a time, regenerate, compare. LLM rules
  had narrower coverage but **fewer false positives** than human rules. Notes false
  negatives "are incredibly hard to track" — the gap a detonation evaluation would fill.

## Self-correction — why pySigma, not the model, is the verifier

- **Huang et al., "Large Language Models Cannot Self-Correct Reasoning Yet"**, ICLR 2024,
  arXiv 2310.01798. Intrinsic self-correction *degrades* GPT-4: GSM8K 95.5 → 91.5 → 89.0;
  CommonSenseQA 82.0 → 79.5 → 80.0; HotpotQA 49.0 → 49.0 → 43.0; GPT-3.5 CommonSenseQA
  75.8 → 38.1. Multi-agent debate (83.2%) loses to self-consistency (85.3%) at equal
  budget. External feedback (tools, executors, verifiers) does work → pySigma.

## Structured generation

- **Tam et al., "Let Me Speak Freely?"**, arXiv 2408.02442. Format restriction degrades
  reasoning; stricter is worse. Helps classification, hurts nuanced reasoning.
  Mitigation: reason in natural language, convert afterwards. Relevant to defect 5
  (`json_mode` on the generation stage).
- **XGrammar** (Nov 2024): production constrained decoding (pushdown automata, < 40 µs
  mask computation). Local/Ollama path only.

## Retrieval

- Hybrid dense + sparse with Reciprocal Rank Fusion: ~7% nDCG lift at near-zero latency;
  cross-encoder reranking is the largest single quality jump.
- Self-RAG (arXiv 2310.11511) and CRAG gate or correct retrieved context — relevant since
  the generation stage injects several RAG blocks with no relevance gate.
- MTEB/BEIR rank does not predict domain-specific retrieval: measure on our own corpus
  before changing embeddings.

## Small models and fine-tuning — for Chapter 7's "why no fine-tuning"

- **Foundation-Sec-8B** (Cisco Foundation AI): base arXiv 2504.21039, Instruct
  2508.01059, Reasoning 2601.21051. Llama-3.1-8B + ~5.1B tokens of security text.
  *Update 2026-09-23:* both base and Instruct document a **4,096-token** sequence length;
  61% of this pipeline's prompts exceed it; the installed base model could not do the
  attack-vector stage (CH6 §6.5). Contribution 3 dropped by the user.
- **Ovadia et al., "Fine-Tuning or Retrieval?"**, EMNLP 2024, arXiv 2312.05934: RAG
  consistently beats unsupervised fine-tuning for knowledge injection → justify not
  fine-tuning ATT&CK/Sysmon/taxonomy facts into weights.
- **RAFT** (Zhang et al., UC Berkeley), arXiv 2403.10131: fine-tune the model to *use*
  retrieval — ignore distractors, cite verbatim. The right framing for any future tuning.
- **Gudibande et al., "The False Promise of Imitating Proprietary LLMs"**, arXiv
  2305.15717: imitation copies style, not capability → against naive distillation.
- **LIMA** (Zhou et al.), NeurIPS 2023, arXiv 2305.11206: ~1,000 curated examples suffice
  for alignment; "almost all knowledge is learned in pretraining".
- **KTO** (Ethayarajh et al.), arXiv 2402.01306: alignment from a binary
  desirable/undesirable signal → pySigma pass/fail is exactly that signal, free.
- **FrugalGPT** (arXiv 2305.05176) and **RouteLLM** (arXiv 2406.18665, metrics CPT/APGR):
  the framing for cloud/local routing — contribution 2, currently blocked.

## Web search and fetched content (added 2026-09-23, for the parked web-search work)

- Ollama web search API: https://docs.ollama.com/capabilities/web-search (cloud
  endpoints; queries leave the machine; recommends ≥ 32k context).
- **Indirect prompt injection** — a fetched page can carry instructions aimed at the
  model; CTI pages are close to attackers by nature. Unit 42, "Fooling AI Agents:
  Web-Based Indirect Prompt Injection Observed in the Wild"
  (https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/); "Indirect Prompt
  Injection in the Wild: An Empirical Study…", arXiv 2604.27202. Argues for code, not the
  model, deciding what is fetched.

## Hardware constraint (verified 2026-08)

DGX Spark: 128 GB LPDDR5X unified memory, **273 GB/s** bandwidth — capacity is generous,
decode throughput is the limit.

## The leakage trap for any Sigma dataset

SigmaHQ rules are not paired with their source CTI. Reverse-generating a "report" from a
rule embeds the rule's own fields. This project's dataset avoids it by using each rule's
own `references:` as the input (CH5 §5.1).

## Thesis positioning — status 2026-09-23

The original three claims (detonation evaluation; cloud/local cost routing;
security-pretrained model) are **not current**: routing is blocked (no Gemini) and the
Foundation-Sec claim was dropped. The contributions are being settled with the professor
(ACTION_PLAN Phase 0).
