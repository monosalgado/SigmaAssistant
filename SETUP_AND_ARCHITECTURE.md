# SigmaAssistant — Setup & Architecture Guide

This document explains **how SigmaAssistant works**, **how to set it up on a
fresh machine**, and **why the lab VPN + NVIDIA Spark connection matters** for
the LLM calls. If you just want to get running fast, jump to
[Setup](#2-setup-step-by-step). For the big picture, start at
[How it works](#1-how-it-works).

---

## 1. How it works

SigmaAssistant turns threat intelligence (a CVE writeup, a blog post, a PoC, a
screenshot) into a validated [Sigma](https://github.com/SigmaHQ/sigma)
detection rule. Instead of one giant "write me a rule" prompt, it runs a
**multi-stage pipeline** where each stage does one focused job and pulls only
the context it needs from a local knowledge base.

### 1.1 The pipeline

```
 user input (text / URL / file)
        │
        ▼
 ┌──────────────┐   classify: is this a chat question or a rule request?
 │ orchestrator │──────────────────────────────────────────────┐
 └──────┬───────┘                                               │ (chat)
        │ (generate_rule)                                       ▼
        ▼                                                  conversational
 1. preprocess        fetch URLs, extract text, transcribe images   reply
        ▼
 2. web_enrich        ground the report with live web search
        ▼
 3. poc_analysis      find code snippets / PoCs, extract behaviour
        ▼
 4. attack_vector     identify the PRIMARY technique being exploited
        ▼
 5. analysis          extract indicators + map MITRE TTPs + log sources
        ▼
   [feedback]         optional: show the user what was extracted
        ▼
 6. generate          write the Sigma rule(s)  ← highest-quality model
        ▼
 7. review            validate YAML, check MITRE tactics, flag PoC leftovers
        ▼
   coverage check     deterministic gap analysis (no LLM)
        ▼
   final Sigma rule + context panel
```

Progress streams to the browser live over **Server-Sent Events** (the
`/analyze_stream` endpoint), which is why you see each stage light up in the UI.

### 1.2 Retrieval-Augmented Generation (RAG)

Every stage that needs reference material queries a local **ChromaDB** vector
store instead of relying on the model's memory. Five collections are ingested
once and reused:

| Collection      | What it holds                                              |
|-----------------|------------------------------------------------------------|
| `sigma_rules`   | The SigmaHQ rule corpus — few-shot examples for generation |
| `mitre_attack`  | MITRE ATT&CK techniques + the authoritative tactic graph   |
| `sysmon_info`   | Sysmon event-ID → field reference                          |
| `sigma_taxonomy`| Sigma logsource / field-name spec                          |
| `cwe_kb`        | MITRE CWE catalogue                                         |

Embeddings are computed **locally** with
`sentence-transformers/all-MiniLM-L6-v2` — no embedding API, no quota, works
offline after the model downloads once.

### 1.3 The three LLM tiers (this is the important part)

Not every stage needs the same horsepower. SigmaAssistant routes calls to one
of three tiers:

| Tier        | Used for                                       | Default model            |
|-------------|------------------------------------------------|--------------------------|
| **Primary** | Rule generation, attack-vector identification  | Gemini `2.5-flash`       |
| **Fast**    | Web enrichment, PoC analysis, review           | Gemini `2.5-flash-lite`  |
| **Economy** | Intent classification, validation, translation | **configurable** (see below) |

The **economy tier is where the NVIDIA Spark comes in.** You can keep economy
on Gemini (simplest), or point it at a **local Ollama model running on the
lab's NVIDIA Spark workstation** to offload the cheap-but-frequent calls and
save Gemini quota. That routing is controlled entirely by `.env`
(`ECONOMY_PROVIDER`).

---

## 2. Setup (step by step)

### Prerequisites

- **Python 3.9+** (3.9 works; the code uses `from __future__ import annotations`)
- **git**
- A **Google AI Studio API key** (free): <https://aistudio.google.com/apikey>
- ~1 GB free disk (ChromaDB store + the embedding model + SigmaHQ corpus)
- *(Optional, for the economy tier)* access to the lab's NVIDIA Spark Ollama
  server — see [section 3](#3-the-lab-vpn--nvidia-spark-dependency).

### 2.1 Clone the project

```bash
git clone <your-fork-url> SigmaAssistant
cd SigmaAssistant
```

### 2.2 Clone the SigmaHQ rule corpus

The Sigma rules are **not** bundled (they're huge and update constantly).
Fetch them once into `data/sigma/`:

```bash
git clone https://github.com/SigmaHQ/sigma data/sigma
```

### 2.3 Create the virtual environment and install deps

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

> `requirements.txt` is fully version-pinned, so everyone gets the exact same
> dependency set — no "works on my machine" surprises.

### 2.4 Configure your environment

```bash
cp .env.example .env
```

Open `.env` and set **at minimum**:

```ini
GEMINI_API_KEY=your-google-ai-studio-key-here
```

Leave `ECONOMY_PROVIDER` empty for now (everything will run through Gemini).
You can switch to the Spark/Ollama economy backend later — see section 3.

> `.env` is gitignored. **Never commit it.** Each person uses their own key.

### 2.5 Build the knowledge base (one-time, a few minutes)

```bash
source .venv/bin/activate
python -m backend.run_expanded_ingestion    # Sysmon + MITRE + SigmaHQ rules
python -m scripts.ingest_sigma_taxonomy      # Sigma spec + logsource taxonomy
python -m scripts.ingest_cwe                 # MITRE CWE catalogue
```

The first run also downloads the ~80 MB embedding model.

### 2.6 Run the server

```bash
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Open <http://localhost:8000>. You should see the chat UI. Describe an attack or
paste a CVE writeup and watch the pipeline stages stream.

### 2.7 Quick health check

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/          # 200
curl -s http://127.0.0.1:8000/sessions                                   # []
```

---

## 3. The lab VPN + NVIDIA Spark dependency

This is specific to the lab deployment and the most common source of
confusion, so read carefully.

### 3.1 What the Spark is for

The **economy tier** (intent classification, rule validation, Sigma→LEQL
translation) makes a *lot* of small LLM calls. Sending all of them to Gemini
burns through the free-tier rate limit quickly. To avoid that, the lab runs a
local **Ollama** server (model `qwen3-coder:30b`) on the **NVIDIA Spark**
workstation, and SigmaAssistant routes the economy tier there.

To enable it, set in `.env`:

```ini
ECONOMY_PROVIDER=ollama
OLLAMA_MODEL=qwen3-coder:30b
OLLAMA_BASE_URL=http://localhost:11434

# The Spark is reachable only over SSH on the lab network:
SPARK_SSH_HOST=<spark-ip-on-lab-network>
SPARK_SSH_USER=<your-lab-username>
SPARK_SSH_KEY=~/.ssh/id_ed25519
```

### 3.2 Why the VPN matters

The NVIDIA Spark lives **on the lab's private network**. Its IP is not routable
from the public internet. So:

1. **You must be connected to the lab VPN** before starting the app.
   Without the VPN, your machine cannot reach the Spark's IP at all.
2. On startup, SigmaAssistant **automatically opens an SSH tunnel** to the
   Spark (`backend/tunnel.py`). It forwards your local port `11434` to Ollama
   on the Spark:
   ```
   ssh -N -L 11434:localhost:11434 <user>@<spark-ip>
   ```
3. Once the tunnel is up, the app talks to `localhost:11434` and the traffic is
   transparently forwarded over the VPN to the Spark's GPU.

So the chain is: **lab VPN connected → SSH key authorized on the Spark →
tunnel opens on startup → economy calls hit the Spark's Ollama.**

### 3.3 What happens if the VPN/Spark is unavailable

The app is designed to **degrade gracefully**. If you're off the VPN, the Spark
is offline, or the SSH key isn't set up, the tunnel fails to open and you'll see
a log line like:

```
[tunnel] ✗ SSH exited early: ...
[tunnel]   Economy tier will fall back to Gemini this session.
```

The app keeps working — economy calls simply go to Gemini instead. The only
downside is you consume more Gemini quota and may hit rate limits sooner.

> **Takeaway:** the VPN + Spark connection is **required to use the Spark for
> the economy tier**, but it is **not required for the app to function**. If you
> set `ECONOMY_PROVIDER=ollama`, connect the VPN *first* so the tunnel can open.

### 3.4 Verifying the tunnel

Watch the server startup log. A healthy connection prints:

```
[tunnel] Opening SSH tunnel → <user>@<spark-ip>:11434 ...
[tunnel] ✓ Tunnel ready — Ollama reachable at localhost:11434
```

You can also confirm the port manually while the app runs:

```bash
nc -z localhost 11434 && echo "Ollama reachable" || echo "tunnel down"
```

---

## 4. Security notes

The app is hardened for sharing and light hosting:

- **CORS** is locked to localhost by default. To host it elsewhere, set
  `ALLOWED_ORIGINS=https://your-domain` in `.env` (comma-separated for several).
- **File uploads** are restricted to images and PDF, capped at 10 MB, and
  filenames are sanitized to prevent path traversal.
- **Frontend output is sanitized** with DOMPurify, so a malicious payload
  embedded in a fetched advisory or generated rule cannot execute in the browser.
- **Secrets stay in `.env`** (gitignored). Never commit your Gemini key or the
  Spark SSH details.

---

## 5. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `Failed to initialize Agent` on startup | Knowledge base not built — run the section 2.5 ingestion commands. |
| Rule generation errors with `429` / rate limit | Gemini free-tier quota hit. Wait, or enable the Spark economy tier (section 3) to offload cheap calls. |
| `[tunnel] ✗ SSH exited early` | Not on the lab VPN, SSH key not authorized on the Spark, or wrong `SPARK_SSH_HOST`/`USER`. App falls back to Gemini regardless. |
| Empty context panel / "No context found" | ChromaDB collections missing or empty — re-run ingestion. |
| Browser can't reach the API from another origin | Add that origin to `ALLOWED_ORIGINS` in `.env`. |
| `ssh: command not found` in logs | OpenSSH client not installed; install it or leave `ECONOMY_PROVIDER` empty. |

---

## 6. File map (where to look)

| Path | Responsibility |
|------|----------------|
| `backend/main.py` | FastAPI app, endpoints, CORS, upload validation, SSE |
| `backend/agent.py` | Thin wrapper over the pipeline orchestrator |
| `backend/pipeline/orchestrator.py` | Runs the stages in order, streams progress |
| `backend/pipeline/stage_*.py` | One file per pipeline stage |
| `backend/pipeline/prompts.py` | All LLM prompt templates |
| `backend/llm_client.py` | Gemini / Ollama routing + rate limiting |
| `backend/tunnel.py` | SSH port-forward to the NVIDIA Spark Ollama |
| `backend/vector_store.py` | ChromaDB wrapper (the 5 collections) |
| `backend/translation/` | Sigma → LEQL (InsightIDR) translator |
| `frontend/` | Vanilla-JS UI (`script.js`, `style.css`, `index.html`) |
| `.env.example` | Template for your local `.env` |
