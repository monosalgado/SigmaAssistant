"""
Ingest the MITRE CWE knowledge base into the `cwe_kb` Chroma collection.

Source: https://cwe.mitre.org/data/csv/1000.csv.zip  (research view, authoritative)

What we embed (per CWE entry):
  * Name + description + extended description
  * Common consequences
  * Potential mitigations
  * Observed examples
  * Related Attack Patterns (CAPEC)

Metadata keeps the CWE-ID and a short name so stage_generate can filter by
`cwe_hint` from the attack_vector stage.

Run once, or whenever CWE publishes an update:

    python -m scripts.ingest_cwe
"""

from __future__ import annotations

import csv
import io
import os
import sys
import zipfile
import requests

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.vector_store import VectorStore  # noqa: E402


CWE_ZIP_URLS = [
    # Research view — most complete weaknesses list
    "https://cwe.mitre.org/data/csv/1000.csv.zip",
    # Fallback: all CWEs (smaller cross-section) if 1000.csv.zip is ever offline
    "https://cwe.mitre.org/data/csv/699.csv.zip",
]


def _fetch_zip() -> bytes | None:
    for url in CWE_ZIP_URLS:
        try:
            print(f"[ingest-cwe] downloading {url}")
            r = requests.get(url, timeout=60)
            r.raise_for_status()
            return r.content
        except Exception as e:
            print(f"[ingest-cwe] failed ({url}): {e}")
    return None


def _parse_csv(zip_bytes: bytes) -> list[dict]:
    """Extract the single CSV from the zip and return a list of row dicts."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        csv_names = [n for n in z.namelist() if n.lower().endswith(".csv")]
        if not csv_names:
            print("[ingest-cwe] no CSV inside zip")
            return []
        with z.open(csv_names[0]) as f:
            # The CWE CSV uses UTF-8-sig; newline='' avoids Excel-style breaks.
            text = f.read().decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    return list(reader)


def _format_document(row: dict) -> str:
    """Produce a readable chunk from a CWE CSV row."""
    cwe_id = (row.get("CWE-ID") or "").strip()
    name = (row.get("Name") or "").strip()
    weak = (row.get("Weakness Abstraction") or "").strip()
    status = (row.get("Status") or "").strip()
    description = (row.get("Description") or "").strip()
    extended = (row.get("Extended Description") or "").strip()
    consequences = (row.get("Common Consequences") or "").strip()
    mitigations = (row.get("Potential Mitigations") or "").strip()
    examples = (row.get("Observed Examples") or "").strip()
    capec = (row.get("Related Attack Patterns") or "").strip()
    detection = (row.get("Detection Methods") or "").strip()

    lines = [f"# CWE-{cwe_id}: {name}" if cwe_id else f"# {name}"]
    if weak or status:
        lines.append(f"Abstraction: {weak or '-'}   Status: {status or '-'}")
    if description:
        lines.append("")
        lines.append("## Description")
        lines.append(description)
    if extended:
        lines.append("")
        lines.append("## Extended")
        lines.append(extended)
    if consequences:
        lines.append("")
        lines.append("## Common Consequences")
        lines.append(consequences)
    if detection:
        lines.append("")
        lines.append("## Detection Methods")
        lines.append(detection)
    if mitigations:
        lines.append("")
        lines.append("## Potential Mitigations")
        lines.append(mitigations)
    if examples:
        lines.append("")
        lines.append("## Observed Examples")
        lines.append(examples)
    if capec:
        lines.append("")
        lines.append("## Related Attack Patterns (CAPEC)")
        lines.append(capec)

    return "\n".join(lines)


def _build_entries(rows: list[dict]) -> list[dict]:
    entries: list[dict] = []
    for row in rows:
        cwe_id = (row.get("CWE-ID") or "").strip()
        name = (row.get("Name") or "").strip()
        if not cwe_id:
            continue
        entries.append({
            "id": f"CWE-{cwe_id}",
            "document": _format_document(row),
            "metadata": {
                "cwe_id": f"CWE-{cwe_id}",
                "name": name,
                "abstraction": (row.get("Weakness Abstraction") or "").strip(),
                "status": (row.get("Status") or "").strip(),
            },
        })
    return entries


def main() -> int:
    zip_bytes = _fetch_zip()
    if not zip_bytes:
        print("[ingest-cwe] could not download any CWE CSV; aborting")
        return 1

    rows = _parse_csv(zip_bytes)
    print(f"[ingest-cwe] parsed {len(rows)} CWE row(s)")
    entries = _build_entries(rows)
    print(f"[ingest-cwe] built {len(entries)} chunks")
    if not entries:
        return 1

    vs = VectorStore()
    vs.add_cwe_entries(entries)
    final_count = vs.cwe_collection.count()
    print(f"[ingest-cwe] done. cwe_kb now holds {final_count} entries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
