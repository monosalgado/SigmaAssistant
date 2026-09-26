#!/usr/bin/env python3
"""Write backend/pipeline/attack_technique_ids.json from the local ATT&CK collection.

Every technique and sub-technique ID in the `mitre_attack` collection of the local vector
store (data/chroma_db) — the ATT&CK data the retrieval uses (Change 31, plan 2.7). Reads
the collection's metadata only; no embedding model is loaded.

Usage:
    .venv/bin/python scripts/build_attack_technique_ids.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from backend.pipeline.attack_ids import ATTACK_IDS_PATH, ids_from_metadatas  # noqa: E402


def main() -> int:
    import chromadb

    store = REPO / "data/chroma_db"
    if not store.is_dir():
        print(f"{store} not found: build the vector store first.")
        return 1
    collection = chromadb.PersistentClient(path=str(store)).get_collection("mitre_attack")
    ids = ids_from_metadatas(collection.get(include=["metadatas"])["metadatas"])
    ATTACK_IDS_PATH.write_text("[\n" + ",\n".join(json.dumps(i) for i in ids) + "\n]\n", encoding="utf-8")
    print(f"{len(ids)} technique IDs ({collection.count()} documents) written to "
          f"{ATTACK_IDS_PATH.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
