# SigmaAssistant

A detection-engineering workspace that turns threat-intel writeups, CVE
descriptions, and PoC documents into validated [Sigma](https://github.com/SigmaHQ/sigma)
detection rules. SigmaAssistant runs a multi-stage RAG pipeline backed by
Google Gemini (and optionally a local Ollama model) over a ChromaDB knowledge
base of MITRE ATT&CK, CWE, the SigmaHQ rule corpus, and a Sigma logsource /
field taxonomy.

The pipeline is inspired by the LLMCloudHunter paper: rather than asking one
LLM call to "write a Sigma rule," the system runs a sequence of targeted
stages (preprocess → web enrichment → PoC analysis → attack-vector
identification → analysis → rule generation → review) that each retrieve only
the context they need.

---

## Features

- **Multi-stage pipeline** with Server-Sent Events streaming of per-stage
  progress to the web UI
- **RAG over four corpora**: SigmaHQ rules, MITRE ATT&CK techniques (with
  authoritative tactic graph), CWE catalogue, and a Sigma logsource /
  field-name taxonomy synthesised from the SigmaHQ rule tree
- **MITRE tactic ↔ technique consistency check** built from the live ATT&CK
  data — catches misattributed `attack.txxxx` tags before they reach the user
- **PoC placeholder leakage check** during review — flags exploit-writeup
  example values that an attacker would change
- **Sigma → LEQL translation** for the Rapid7 InsightIDR backend
- **Saved-rules library** with per-rule notes, persisted to JSON
- **Hybrid LLM routing**: Gemini for rule generation (highest quality);
  optional local Ollama for cheap stages (classification, validation,
  translation)
- **Local embeddings** via `sentence-transformers/all-MiniLM-L6-v2` — no
  embedding-API quota, fully offline after first model download

---

## Quickstart

### 1. Clone

```bash
git clone <your-fork-url> SigmaAssistant
cd SigmaAssistant
```

### 2. Clone the SigmaHQ rule corpus into `data/sigma/`

The Sigma rules are not vendored here. Fetch them once:

```bash
git clone https://github.com/SigmaHQ/sigma data/sigma
# Optional: pin to a specific upstream commit so everyone uses the
# same baseline (replace with whichever commit your write-up cites)
# (cd data/sigma && git checkout dc3880459)
```

### 3. Install Python deps

Python 3.9+ recommended. The provided shell script handles the venv:

```bash
chmod +x run_mac.sh
./run_mac.sh         # creates .venv, installs deps, starts the server
```

…or do it manually:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4. Configure environment

```bash
cp .env.example .env
# Edit .env and set GEMINI_API_KEY (https://aistudio.google.com/apikey)
```

### 5. Build the knowledge base (one-time, ~5 min)

```bash
source .venv/bin/activate
python -m backend.run_expanded_ingestion       # Sysmon + MITRE + SigmaHQ rules
python -m scripts.ingest_sigma_taxonomy        # Sigma spec + per-logsource taxonomy
python -m scripts.ingest_cwe                   # MITRE CWE catalogue
```

### 6. Run

```bash
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Open <http://localhost:8000>.

Mac users: see [`README_MAC.md`](README_MAC.md) for a Mac-specific walkthrough.

---

## Project layout

```
backend/
├── agent.py                  Thin wrapper over the pipeline orchestrator
├── main.py                   FastAPI app + SSE streaming endpoint
├── llm_client.py             Gemini / Ollama abstraction with rate-limiting
├── vector_store.py           ChromaDB wrapper (5 collections)
├── ingest_mitre.py           Downloads & parses MITRE ATT&CK enterprise data
├── ingest_rules.py           Loads SigmaHQ YAML rules from data/sigma/rules
├── run_expanded_ingestion.py One-shot ingestion entrypoint
├── tunnel.py                 SSH port-forward to a remote Ollama server
├── sysmon_data.py            Hard-coded Sysmon event reference data
├── saved_rules.py            Persistence for user-saved rules
├── pipeline/                 Multi-stage rule-generation pipeline
│   ├── orchestrator.py
│   ├── base_stage.py
│   ├── prompts.py            All LLM prompt templates
│   ├── schemas.py
│   ├── domain_knowledge.py   RAG context formatting helpers
│   ├── stage_*.py            One file per stage
│   └── archive/              Superseded stages, kept for reference
└── translation/              Sigma → LEQL converter
scripts/
├── ingest_cwe.py
└── ingest_sigma_taxonomy.py
frontend/
├── index.html
├── script.js
└── style.css
data/                         (gitignored — see Quickstart step 2 & 5)
├── chroma_db/                ChromaDB persistent store
├── sigma/                    SigmaHQ rule corpus (cloned by the user)
├── sessions.json             Chat session history
└── saved_rules.json          Saved rule library
uploads/                      Runtime upload directory (contents gitignored)
```

---

## Hybrid LLM routing

By default everything runs through Gemini. To offload the cheap stages
(intent classification, validation, translation) to a local Ollama model
and keep only generation on Gemini, set in `.env`:

```
ECONOMY_PROVIDER=ollama
OLLAMA_MODEL=qwen3-coder:30b
OLLAMA_BASE_URL=http://localhost:11434
```

If Ollama is on a remote host reachable only via SSH, set
`SPARK_SSH_HOST` / `SPARK_SSH_USER` and the app will open a port-forward
on startup (see `backend/tunnel.py`).

---

## License

TBD — pick one before publishing publicly.
