"""
Ingest the official Sigma specification + logsource taxonomy into the
`sigma_taxonomy` Chroma collection.

Sources (all free, public, license: CC-BY 4.0 / permissive):
  * SigmaHQ/sigma-specification  — Sigma spec + taxonomy + appendix tables
  * SigmaHQ/sigma                — sigmahq_category_list.md + logsource tables

What we embed:
  * Each H2/H3 section of the spec docs as a separate chunk (with source URL
    in metadata) so retrieval returns topically focused passages.
  * Each (category, product, service) row from the taxonomy table as a chunk.

Run once, or any time the Sigma spec updates:

    python -m scripts.ingest_sigma_taxonomy

Requires: requests, backend.vector_store on PYTHONPATH.
"""

from __future__ import annotations

import os
import re
import sys
import hashlib
import requests
from collections import defaultdict
from pathlib import Path
from typing import Iterable

import yaml

# Allow running as `python scripts/ingest_sigma_taxonomy.py` from repo root.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.vector_store import VectorStore  # noqa: E402


# ---------------------------------------------------------------------------
# Source URLs (raw GitHub)
# ---------------------------------------------------------------------------

_SPEC_BASE = "https://raw.githubusercontent.com/SigmaHQ/sigma-specification/main"
_SIGMA_BASE = "https://raw.githubusercontent.com/SigmaHQ/sigma/master"

SOURCES: list[dict] = [
    # --- Core spec files ---
    {
        "name": "sigma-rules-specification",
        "url": f"{_SPEC_BASE}/specification/sigma-rules-specification.md",
        "category": "sigma_spec",
    },
    {
        "name": "sigma-correlation-rules-specification",
        "url": f"{_SPEC_BASE}/specification/sigma-correlation-rules-specification.md",
        "category": "sigma_spec",
    },
    {
        "name": "sigma-filters-specification",
        "url": f"{_SPEC_BASE}/specification/sigma-filters-specification.md",
        "category": "sigma_spec",
    },
    # --- Appendixes ---
    {
        "name": "sigma-appendix-taxonomy",
        "url": f"{_SPEC_BASE}/specification/sigma-appendix-taxonomy.md",
        "category": "sigma_taxonomy",
    },
    {
        "name": "sigma-appendix-modifiers",
        "url": f"{_SPEC_BASE}/specification/sigma-appendix-modifiers.md",
        "category": "sigma_modifiers",
    },
    {
        "name": "sigma-appendix-tags",
        "url": f"{_SPEC_BASE}/specification/sigma-appendix-tags.md",
        "category": "sigma_tags",
    },
    # --- SigmaHQ conventions ---
    {
        "name": "sigmahq-rule-convention",
        "url": f"{_SPEC_BASE}/sigmahq/sigmahq-rule-convention.md",
        "category": "sigmahq_convention",
    },
    {
        "name": "sigmahq-title-convention",
        "url": f"{_SPEC_BASE}/sigmahq/sigmahq-title-convention.md",
        "category": "sigmahq_convention",
    },
    {
        "name": "sigmahq-filename-convention",
        "url": f"{_SPEC_BASE}/sigmahq/sigmahq-filename-convention.md",
        "category": "sigmahq_convention",
    },
    # --- Logsource guides (Windows categories) ---
    {
        "name": "logsource-windows-process_creation",
        "url": f"{_SIGMA_BASE}/documentation/logsource-guides/windows/category/process_creation.md",
        "category": "logsource_guide_windows",
    },
    {
        "name": "logsource-windows-ps_module",
        "url": f"{_SIGMA_BASE}/documentation/logsource-guides/windows/category/ps_module.md",
        "category": "logsource_guide_windows",
    },
    {
        "name": "logsource-windows-ps_script",
        "url": f"{_SIGMA_BASE}/documentation/logsource-guides/windows/category/ps_script.md",
        "category": "logsource_guide_windows",
    },
    {
        "name": "logsource-windows-registry_add",
        "url": f"{_SIGMA_BASE}/documentation/logsource-guides/windows/category/registry_add.md",
        "category": "logsource_guide_windows",
    },
    {
        "name": "logsource-windows-registry_delete",
        "url": f"{_SIGMA_BASE}/documentation/logsource-guides/windows/category/registry_delete.md",
        "category": "logsource_guide_windows",
    },
    {
        "name": "logsource-windows-registry_event",
        "url": f"{_SIGMA_BASE}/documentation/logsource-guides/windows/category/registry_event.md",
        "category": "logsource_guide_windows",
    },
    {
        "name": "logsource-windows-registry_rename",
        "url": f"{_SIGMA_BASE}/documentation/logsource-guides/windows/category/registry_rename.md",
        "category": "logsource_guide_windows",
    },
    {
        "name": "logsource-windows-registry_set",
        "url": f"{_SIGMA_BASE}/documentation/logsource-guides/windows/category/registry_set.md",
        "category": "logsource_guide_windows",
    },
    # --- Logsource guides (Windows services) ---
    {
        "name": "logsource-windows-powershell",
        "url": f"{_SIGMA_BASE}/documentation/logsource-guides/windows/service/powershell.md",
        "category": "logsource_guide_windows",
    },
    {
        "name": "logsource-windows-security",
        "url": f"{_SIGMA_BASE}/documentation/logsource-guides/windows/service/security.md",
        "category": "logsource_guide_windows",
    },
    # --- Logsource guides (other) ---
    {
        "name": "logsource-other-antivirus",
        "url": f"{_SIGMA_BASE}/documentation/logsource-guides/other/antivirus.md",
        "category": "logsource_guide_other",
    },
]


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------

def _split_markdown_by_headings(md_text: str) -> list[tuple[str, str]]:
    """Return list of (heading, body) for every H2/H3 section in the doc.

    The first chunk (before any heading) is returned with heading="(intro)".
    """
    lines = md_text.splitlines()
    sections: list[tuple[str, list[str]]] = []
    current_heading = "(intro)"
    current_body: list[str] = []

    heading_re = re.compile(r"^(#{2,3})\s+(.+?)\s*$")

    for ln in lines:
        m = heading_re.match(ln)
        if m:
            if current_body:
                sections.append((current_heading, current_body))
            current_heading = m.group(2).strip()
            current_body = []
        else:
            current_body.append(ln)
    if current_body:
        sections.append((current_heading, current_body))

    return [(h, "\n".join(b).strip()) for h, b in sections if "\n".join(b).strip()]


def _chunk_long_body(body: str, max_chars: int = 2000) -> list[str]:
    """If a section is too long, split on blank lines into <=max_chars chunks."""
    if len(body) <= max_chars:
        return [body]
    paras = [p for p in re.split(r"\n\s*\n", body) if p.strip()]
    chunks: list[str] = []
    buf = ""
    for p in paras:
        if not buf:
            buf = p
        elif len(buf) + len(p) + 2 <= max_chars:
            buf = f"{buf}\n\n{p}"
        else:
            chunks.append(buf)
            buf = p
    if buf:
        chunks.append(buf)
    return chunks


def _stable_id(text: str) -> str:
    return "taxo_" + hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


def _fetch(url: str, optional: bool = False) -> str | None:
    try:
        r = requests.get(url, timeout=20)
        r.raise_for_status()
        return r.text
    except Exception as e:
        if optional:
            print(f"[ingest-sigma] optional source skipped ({url}): {e}")
            return None
        print(f"[ingest-sigma] failed to fetch {url}: {e}")
        return None


def _build_entries(source: dict) -> Iterable[dict]:
    """Turn one source document into multiple retrieval chunks."""
    text = _fetch(source["url"], optional=source.get("optional", False))
    if not text:
        return []

    entries: list[dict] = []
    sections = _split_markdown_by_headings(text)
    if not sections:
        # Not markdown — embed as a single chunk.
        sections = [("(full)", text)]

    for heading, body in sections:
        for idx, chunk in enumerate(_chunk_long_body(body)):
            document = (
                f"# {source['name']} — {heading}\n\n{chunk}"
                if heading != "(intro)"
                else f"# {source['name']}\n\n{chunk}"
            )
            entries.append({
                "id": _stable_id(f"{source['url']}::{heading}::{idx}"),
                "document": document,
                "metadata": {
                    "source": source["url"],
                    "source_name": source["name"],
                    "category": source["category"],
                    "heading": heading,
                    "chunk_index": idx,
                },
            })
    return entries


# ---------------------------------------------------------------------------
# Walk the local SigmaHQ rules corpus and synthesize per-logsource chunks.
#
# For every YAML file under data/sigma/rules, we parse the logsource: and
# detection: blocks.  We group rules by the (category, product, service)
# tuple declared in logsource, then emit ONE chunk per group containing:
#   * The exact logsource block that is valid for that group
#   * The union of every detection field name observed across those rules
#   * A short sample detection block from a real rule
#
# This gives the retriever high-signal, authoritative content for every
# logsource combination SigmaHQ actually uses (apache, nginx, iis, tomcat,
# webserver generic, cloud/aws, cloud/azure, linux/auditd, etc.).  No
# hand-authored taxonomy — the data comes entirely from SigmaHQ/sigma.
# ---------------------------------------------------------------------------

def _extract_field_names_from_detection(detection: dict) -> set[str]:
    """Return the set of log-field names referenced inside a Sigma detection block.

    Every top-level key except `condition` is a search identifier.  Inside a
    search identifier, dict keys name the log fields (possibly suffixed with
    a |modifier such as |contains, |endswith, |re, ...).  List-shaped search
    identifiers (keywords-style) do not reference field names.
    """
    fields: set[str] = set()
    if not isinstance(detection, dict):
        return fields
    for search_id, body in detection.items():
        if search_id == "condition":
            continue
        if isinstance(body, dict):
            for k in body.keys():
                if not isinstance(k, str):
                    continue
                base = k.split("|", 1)[0].strip()
                if base and not base.startswith("_"):
                    fields.add(base)
        # list-typed (keywords) search identifiers contribute no field names
    return fields


def _first_nontrivial_detection_snippet(detection: dict, max_chars: int = 1200) -> str | None:
    """Serialize a detection block as YAML, trimmed to max_chars.  Returns
    None if the block is empty or degenerate."""
    if not isinstance(detection, dict) or not detection:
        return None
    try:
        snippet = yaml.safe_dump(
            {"detection": detection},
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )
    except Exception:
        return None
    if len(snippet) > max_chars:
        snippet = snippet[:max_chars].rsplit("\n", 1)[0] + "\n# ... (truncated)\n"
    return snippet


def _walk_sigma_rules_for_taxonomy(rules_root: Path) -> list[dict]:
    """Build one taxonomy chunk per distinct (category, product, service)
    observed under `rules_root`."""
    groups: dict[tuple, dict] = defaultdict(
        lambda: {"fields": set(), "count": 0, "example": None, "example_title": None}
    )

    total_rules = 0
    parse_errors = 0
    for p in rules_root.rglob("*.yml"):
        try:
            with open(p, "r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)
        except Exception:
            parse_errors += 1
            continue
        if not isinstance(rule, dict):
            continue
        total_rules += 1

        ls = rule.get("logsource") or {}
        if not isinstance(ls, dict):
            continue
        key = (
            (ls.get("category") or "").strip(),
            (ls.get("product") or "").strip(),
            (ls.get("service") or "").strip(),
        )
        if key == ("", "", ""):
            continue

        detection = rule.get("detection")
        fields = _extract_field_names_from_detection(detection or {})
        g = groups[key]
        g["fields"].update(fields)
        g["count"] += 1

        # Keep the first rule that has at least two distinct field names as the
        # example — more representative than keywords-only rules.
        if g["example"] is None and len(fields) >= 2:
            snippet = _first_nontrivial_detection_snippet(detection)
            if snippet:
                g["example"] = snippet
                g["example_title"] = rule.get("title") or p.name

    print(
        f"[ingest-sigma] walked {total_rules} rules across {len(groups)} "
        f"(category,product,service) groups (skipped {parse_errors} parse errors)"
    )

    entries: list[dict] = []
    for (cat, prod, svc), data in sorted(groups.items()):
        if data["count"] < 1 or not data["fields"]:
            # Skip keyword-only logsources (no named fields → nothing to teach).
            continue
        ls_human = ", ".join(
            part for part in [
                f"category={cat}" if cat else "",
                f"product={prod}" if prod else "",
                f"service={svc}" if svc else "",
            ] if part
        )
        heading = (
            f"logsource-{cat or 'none'}-{prod or 'none'}-{svc or 'none'}"
        )
        body_parts: list[str] = []
        body_parts.append(f"# Sigma logsource: {ls_human}")
        body_parts.append(
            f"Derived from {data['count']} real SigmaHQ rule(s) using exactly "
            f"this logsource combination."
        )
        body_parts.append("## Valid logsource block for this source:")
        yaml_logsource = "logsource:\n"
        if cat:
            yaml_logsource += f"    category: {cat}\n"
        if prod:
            yaml_logsource += f"    product: {prod}\n"
        if svc:
            yaml_logsource += f"    service: {svc}\n"
        body_parts.append(f"```yaml\n{yaml_logsource}```")
        body_parts.append(
            f"## Detection field names observed in real rules "
            f"({len(data['fields'])} distinct):"
        )
        # Sort for stable output.  Join as a single comma-separated line
        # plus a bulleted list for better retrieval matching.
        sorted_fields = sorted(data["fields"])
        body_parts.append(", ".join(sorted_fields))
        body_parts.append("\n".join(f"- {f}" for f in sorted_fields))
        if data["example"]:
            body_parts.append(
                f"## Example detection block from a real SigmaHQ rule "
                f"(title: {data['example_title']}):"
            )
            body_parts.append(f"```yaml\n{data['example']}```")

        document = "\n\n".join(body_parts)
        entries.append({
            "id": _stable_id(f"sigmarules_aggregate::{cat}::{prod}::{svc}"),
            "document": document,
            "metadata": {
                "source": "sigmahq_rules_aggregate",
                "source_name": heading,
                "category": cat,
                "product": prod,
                "service": svc,
                "heading": heading,
                "chunk_index": 0,
                "rule_count": int(data["count"]),
            },
        })
    return entries


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    vs = VectorStore()
    all_entries: list[dict] = []

    # --- Phase 1: fetch upstream Sigma spec / appendix / convention docs ---
    for src in SOURCES:
        print(f"[ingest-sigma] fetching: {src['name']}")
        entries = list(_build_entries(src))
        print(f"[ingest-sigma]   -> {len(entries)} chunk(s)")
        all_entries.extend(entries)

    # --- Phase 2: walk the local SigmaHQ rule corpus to synthesize
    # per-(category,product,service) taxonomy chunks from real rules.
    rules_root = Path(_REPO_ROOT) / "data" / "sigma" / "rules"
    if rules_root.is_dir():
        print(f"[ingest-sigma] walking local rules tree at {rules_root}")
        rule_entries = _walk_sigma_rules_for_taxonomy(rules_root)
        print(
            f"[ingest-sigma]   -> {len(rule_entries)} per-logsource aggregate chunks"
        )
        all_entries.extend(rule_entries)
    else:
        print(
            f"[ingest-sigma] NOTE: {rules_root} not found — skipping the "
            "per-logsource aggregation phase.  Taxonomy will contain only "
            "the upstream Sigma spec docs."
        )

    if not all_entries:
        print("[ingest-sigma] no entries produced; aborting")
        return 1

    print(f"[ingest-sigma] embedding {len(all_entries)} total chunks...")
    vs.add_taxonomy_docs(all_entries)
    final_count = vs.taxonomy_collection.count()
    print(f"[ingest-sigma] done. sigma_taxonomy now holds {final_count} chunks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
