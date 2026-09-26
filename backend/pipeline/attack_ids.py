"""Technique IDs that exist in ATT&CK (Change 31, plan 2.7).

The analysis stage writes technique IDs ATT&CK does not have — in a loop, T1562.001 →
T1562.339 (defect 19). Like the rule-id check (Change 9), code validates the model's answer
against a specification and records what it removed: an ID that is not in ATT&CK is dropped
from the list (never repaired — an invalid sub-technique is not truncated to its parent),
and the dropped IDs are kept for the record.

The valid IDs are `attack_technique_ids.json`, built by
`scripts/build_attack_technique_ids.py` from the local ATT&CK collection (the one the
retrieval uses), so the check and its measure (`eval/count_techniques.py`) read one file.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ATTACK_IDS_PATH = Path(__file__).with_name("attack_technique_ids.json")
_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def ids_from_metadatas(metadatas) -> list:
    """Technique and sub-technique IDs in the collection's metadata, sorted."""
    ids = set()
    for md in metadatas or []:
        if isinstance(md, dict):
            ext = str(md.get("external_id") or "").strip().upper()
            if _TECHNIQUE_ID.match(ext):
                ids.add(ext)
    return sorted(ids)


def load_attack_ids(path: Path = ATTACK_IDS_PATH) -> set:
    return {str(i).strip().upper() for i in json.loads(Path(path).read_text(encoding="utf-8"))}


def split_known(mappings, valid: set) -> tuple:
    """(kept, dropped): the model's own mappings whose ID ATT&CK has, unchanged and in
    order; and the IDs of the rest ('' when an entry has no usable ID)."""
    kept, dropped = [], []
    for m in mappings or []:
        if not isinstance(m, dict):
            dropped.append(str(m).strip().upper())
            continue
        tid = str(m.get("technique_id") or "").strip().upper()
        if tid and tid in valid:
            kept.append(m)
        else:
            dropped.append(tid)
    return kept, dropped
