"""
Vector store wrapper around ChromaDB.

Embedding function is selectable via env var EMBEDDING_PROVIDER:
  - "local"  (default)  sentence-transformers, free, offline-capable
  - "gemini"            Gemini embeddings (requires GEMINI_API_KEY + quota)

Collections managed here:
  - sigma_rules        (existing)  known-good Sigma rules for few-shot RAG
  - mitre_attack       (existing)  MITRE ATT&CK technique descriptions
  - sysmon_info        (existing)  Sysmon event-ID field reference
  - sigma_taxonomy     (new)       Official Sigma logsource spec + platform field refs
  - cwe_kb             (new)       MITRE CWE entries keyed by CWE-ID and class

Per-collection metadata: Chroma persists the embedding function name at create
time. Changing EMBEDDING_PROVIDER later does not retroactively rewrite existing
collections — you must wipe `data/chroma_db/` and re-ingest if you change.
"""

from __future__ import annotations

import os

# Disable HuggingFace tokenizers parallelism BEFORE importing sentence-transformers
# / transformers. Without this, macOS + Python 3.9 leaks a semaphore on shutdown:
#   "resource_tracker: There appear to be N leaked semaphore objects"
# The parallel tokenizer workers conflict with fork-based multiprocessing; disabling
# the feature is safe (tiny perf hit on batch embedding, none on single queries).
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import time
import chromadb
from chromadb import Documents, EmbeddingFunction, Embeddings
from dotenv import load_dotenv

load_dotenv()


# ---------------------------------------------------------------------------
# Embedding functions
# ---------------------------------------------------------------------------

class LocalEmbeddingFunction(EmbeddingFunction):
    """Local sentence-transformers embedding — free, offline-capable.

    Uses `all-MiniLM-L6-v2` by default: 384-dim, ~80MB, CPU-fast.
    Override with env var LOCAL_EMBEDDING_MODEL (e.g. BAAI/bge-small-en-v1.5).
    """

    _model_cache = {}  # class-level to share one model across VectorStore instances

    def __init__(self, model_name: str | None = None):
        model_name = model_name or os.getenv(
            "LOCAL_EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"
        )
        self.model_name = model_name
        if model_name not in LocalEmbeddingFunction._model_cache:
            # Lazy import so the dependency isn't required when using Gemini.
            from sentence_transformers import SentenceTransformer
            print(f"[embeddings] Loading local model: {model_name}")
            LocalEmbeddingFunction._model_cache[model_name] = SentenceTransformer(model_name)
        self._model = LocalEmbeddingFunction._model_cache[model_name]

    def __call__(self, input: Documents) -> Embeddings:
        # SentenceTransformer returns numpy arrays; convert to plain lists for Chroma.
        vectors = self._model.encode(
            list(input), show_progress_bar=False, convert_to_numpy=True
        )
        return [v.tolist() for v in vectors]

    # Chroma uses this identifier to detect mismatches between the embedding
    # function saved with the collection and the one supplied at runtime.
    def name(self) -> str:
        return f"local::{self.model_name}"


class GeminiEmbeddingFunction(EmbeddingFunction):
    """Legacy Gemini embedding — kept for backward compatibility."""

    def __init__(self, api_key: str):
        from google import genai
        self.client = genai.Client(api_key=api_key)

    def __call__(self, input: Documents) -> Embeddings:
        model = "models/gemini-embedding-001"
        embeddings = []
        for text in input:
            retry_count = 0
            while retry_count < 5:
                try:
                    response = self.client.models.embed_content(
                        model=model, contents=text
                    )
                    embeddings.append(response.embeddings[0].values)
                    time.sleep(1)
                    break
                except Exception as e:
                    s = str(e)
                    if "429" in s or "ResourceExhausted" in s or "quota" in s.lower():
                        wait = (2 ** retry_count) * 5
                        print(f"[embeddings] Rate limit — retrying in {wait}s")
                        time.sleep(wait)
                        retry_count += 1
                    else:
                        print(f"[embeddings] Error: {e}")
                        raise
        return embeddings

    def name(self) -> str:
        return "gemini::gemini-embedding-001"


def _build_embedding_function() -> EmbeddingFunction:
    """Factory — picks embedding provider from env."""
    provider = (os.getenv("EMBEDDING_PROVIDER") or "local").lower()
    if provider == "gemini":
        key = os.getenv("GEMINI_API_KEY")
        if not key:
            raise ValueError("EMBEDDING_PROVIDER=gemini but GEMINI_API_KEY not set")
        return GeminiEmbeddingFunction(api_key=key)
    # default: local
    return LocalEmbeddingFunction()


# ---------------------------------------------------------------------------
# Vector store
# ---------------------------------------------------------------------------

class VectorStore:
    def __init__(self, persistence_path: str = "data/chroma_db"):
        self.client = chromadb.PersistentClient(path=persistence_path)
        self.embedding_fn = _build_embedding_function()

        # Existing collections
        self.sigma_collection = self.client.get_or_create_collection(
            name="sigma_rules", embedding_function=self.embedding_fn
        )
        self.mitre_collection = self.client.get_or_create_collection(
            name="mitre_attack", embedding_function=self.embedding_fn
        )
        self.sysmon_collection = self.client.get_or_create_collection(
            name="sysmon_info", embedding_function=self.embedding_fn
        )

        # New collections (populated by scripts/ingest_sigma_taxonomy.py
        # and scripts/ingest_cwe.py).
        self.taxonomy_collection = self.client.get_or_create_collection(
            name="sigma_taxonomy", embedding_function=self.embedding_fn
        )
        self.cwe_collection = self.client.get_or_create_collection(
            name="cwe_kb", embedding_function=self.embedding_fn
        )

    # --- Add methods (existing + new) ---

    def add_rules(self, rules):
        if not rules:
            return
        ids = [r["id"] for r in rules]
        documents = []
        metadatas = []
        for r in rules:
            doc_text = (
                f"Title: {r['title']}\n"
                f"Description: {r['description']}\n"
                f"Log Source: {r['logsource']}\n"
                f"Detection: {r['detection']}"
            )
            documents.append(doc_text)
            metadatas.append({
                "type": "sigma_rule",
                "title": r["title"],
                "path": r["path"],
                "product": r["logsource"].get("product", "unknown"),
                "service": r["logsource"].get("service", "unknown"),
            })
        self._batch_add(self.sigma_collection, ids, documents, metadatas)

    def add_mitre_techniques(self, techniques):
        if not techniques:
            return
        ids = [t["id"] for t in techniques]
        documents = []
        metadatas = []
        for t in techniques:
            tactics_str = t.get("tactics", "") or ""
            platforms_str = t.get("platforms", "") or ""
            header_lines = [f"Technique: {t['name']} ({t['external_id']})"]
            if tactics_str:
                header_lines.append(f"Tactics: {tactics_str}")
            if platforms_str:
                header_lines.append(f"Platforms: {platforms_str}")
            header_lines.append(f"Description: {t['description']}")
            doc_text = "\n".join(header_lines)
            documents.append(doc_text)
            metadatas.append({
                "type": "mitre_technique",
                "name": t["name"],
                "external_id": t["external_id"],
                "url": t.get("url", ""),
                "tactics": tactics_str,
                "platforms": platforms_str,
            })
        self._batch_add(self.mitre_collection, ids, documents, metadatas)

    def add_sysmon_info(self, sysmon_data):
        if not sysmon_data:
            return
        ids = [f"sysmon_{e['id']}" for e in sysmon_data]
        documents = []
        metadatas = []
        for e in sysmon_data:
            doc_text = (
                f"Sysmon Event ID {e['id']}: {e['name']}\n"
                f"Description: {e['description']}\n"
                f"Fields: {', '.join(e['fields'])}"
            )
            documents.append(doc_text)
            metadatas.append({
                "type": "sysmon_info",
                "event_id": e["id"],
                "name": e["name"],
            })
        self._batch_add(self.sysmon_collection, ids, documents, metadatas)

    def add_taxonomy_docs(self, entries: list[dict]):
        """Add Sigma-taxonomy / log-format reference docs.

        Each entry should be a dict with:
          - id:        unique string id
          - document:  the full text to embed
          - metadata:  dict with at least {"source": <url>, "category": <str>}
        """
        if not entries:
            return
        ids = [e["id"] for e in entries]
        documents = [e["document"] for e in entries]
        metadatas = [e.get("metadata", {}) for e in entries]
        self._batch_add(self.taxonomy_collection, ids, documents, metadatas)

    def add_cwe_entries(self, entries: list[dict]):
        """Add CWE knowledge-base entries.

        Each entry should be a dict with:
          - id:        unique string id (e.g. "CWE-78")
          - document:  full text to embed
          - metadata:  dict with at least {"cwe_id": <str>, "name": <str>}
        """
        if not entries:
            return
        ids = [e["id"] for e in entries]
        documents = [e["document"] for e in entries]
        metadatas = [e.get("metadata", {}) for e in entries]
        self._batch_add(self.cwe_collection, ids, documents, metadatas)

    # --- Batch helper ---

    def _batch_add(self, collection, ids, documents, metadatas):
        batch_size = 100
        total = len(ids)
        print(f"Adding {total} items to {collection.name}...")
        for i in range(0, total, batch_size):
            end = min(i + batch_size, total)
            collection.upsert(
                ids=ids[i:end],
                documents=documents[i:end],
                metadatas=metadatas[i:end],
            )
            print(f"Processed {end}/{total}")

    # --- Search ---

    def search(self, query: str, collections: list[str] | None = None, n_results: int = 5) -> dict:
        """Search specific collections.

        `collections` can contain any of:
          sigma, mitre, sysmon, taxonomy, cwe
        Unknown names are silently ignored.
        Returns a dict keyed by the short name above.
        """
        collections = collections or ["sigma"]
        results: dict = {}

        lookup = {
            "sigma":    self.sigma_collection,
            "mitre":    self.mitre_collection,
            "sysmon":   self.sysmon_collection,
            "taxonomy": self.taxonomy_collection,
            "cwe":      self.cwe_collection,
        }
        for key in collections:
            col = lookup.get(key)
            if col is None:
                continue
            try:
                results[key] = col.query(query_texts=[query], n_results=n_results)
            except Exception as e:
                print(f"[vector_store] Query against {key} failed: {e}")
                results[key] = {"documents": [[]], "metadatas": [[]], "distances": [[]]}
        return results


if __name__ == "__main__":
    try:
        vs = VectorStore()
        print("Vector Store initialized.")
        print(f"  embedding fn: {vs.embedding_fn.name()}")
        for name in ("sigma_rules", "mitre_attack", "sysmon_info", "sigma_taxonomy", "cwe_kb"):
            col = vs.client.get_or_create_collection(name=name, embedding_function=vs.embedding_fn)
            print(f"  {name}: {col.count()} items")
    except Exception as e:
        print(f"Failed to initialize Vector Store: {e}")
