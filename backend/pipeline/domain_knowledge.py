"""
Pipeline helper formatters — **no hardcoded taxonomy**.

Previous versions of this module shipped hardcoded dicts mapping
`logsource_primary -> field list` and `vuln_class -> allowed/forbidden TTPs`.
All such lookups have been removed; authoritative taxonomy now comes from RAG
collections `sigma_taxonomy` (SigmaHQ spec) and `cwe_kb` (MITRE CWE) + the
existing `mitre_attack` collection.

What remains here is purely STRUCTURAL logic — text formatters that turn
pipeline context (lists, dicts, strings) into prompt-ready blocks. None of
these helpers encode CVE-, product-, or technique-specific knowledge.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Kill-chain rule-splitting requirement
# ---------------------------------------------------------------------------

def format_kill_chain_requirement(kill_chain_stages: list) -> str:
    """Tell the generator to produce one rule per kill-chain stage when applicable.

    Pure structural logic — does not name any specific tactic, technique, or
    product. Operates only on the count and labels of stages present.
    """
    stages = [s for s in (kill_chain_stages or []) if s]
    if not stages:
        return ""
    if len(stages) == 1:
        return (
            "### Kill-chain coverage\n"
            f"This attack has one kill-chain stage: `{stages[0]}`. "
            "One well-targeted rule is sufficient."
        )
    lines = [
        "### Kill-chain coverage (MANDATORY)",
        f"This attack spans {len(stages)} kill-chain stages: "
        + ", ".join(f"`{s}`" for s in stages) + ".",
        "Generate AT LEAST one rule PER stage. Each rule should target indicators "
        "that appear in ONE stage only. Do NOT AND together indicators from different "
        "stages (e.g. do not combine a reconnaissance-stage query-string indicator "
        "with an execution-stage body indicator in a single `all of selection_*` — "
        "they will never co-occur in a single log line).",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Coverage-feedback block (for the regeneration retry)
# ---------------------------------------------------------------------------

def format_coverage_feedback(coverage_check: dict) -> str:
    """Turn a coverage_gap_check result into a correction directive for the LLM.

    Returns empty string if there's nothing to fix. Pure structural — surfaces
    only the gaps detected by `AttackVectorStage.coverage_gap_check`.
    """
    if not coverage_check:
        return ""
    warnings = coverage_check.get("warnings", [])
    missed = coverage_check.get("payload_signatures_missed", [])
    violations = coverage_check.get("blacklist_violations", [])
    ia_ok = coverage_check.get("initial_access_covered", True)
    kc_gap = coverage_check.get("kill_chain_gap")
    vpins = coverage_check.get("version_pin_violations", [])
    if not warnings:
        return ""

    lines = [
        "### PREVIOUS GENERATION HAD COVERAGE GAPS — FIX THEM NOW",
        "The previous attempt produced rules with the following problems. "
        "Your new output must resolve every one:",
    ]
    if not ia_ok:
        lines.append(
            "- NO rule detected the primary attack vector. "
            "At least one rule MUST match the entry point / attacker-controlled input."
        )
    if missed:
        lines.append(
            "- These payload signatures were NOT referenced in any rule; at least one rule "
            "MUST literally contain each of them:"
        )
        for m in missed[:10]:
            lines.append(f"    - `{m}`")
    if violations:
        lines.append(
            "- These strings were used as detection criteria but are "
            "researcher/patch-workflow artifacts — REMOVE them:"
        )
        for v in violations[:10]:
            lines.append(f"    - `{v}`")
    if kc_gap:
        lines.append(f"- {kc_gap} Split the detection into multiple rules (one per stage).")
    if vpins:
        lines.append(
            "- Remove `version:` from `logsource:` (it's for log-format versions, not product versions). "
            f"Offending values: {', '.join(repr(v) for v in vpins[:3])}."
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# RAG context formatter
# ---------------------------------------------------------------------------

def format_rag_block(title: str, documents: list[str], empty_message: str = "") -> str:
    """Format a list of retrieved RAG chunks as a labelled prompt block.

    Generic: any collection, any content. Used by stage_generate.py for
    Sigma-taxonomy and CWE retrievals.
    """
    docs = [d for d in (documents or []) if d and d.strip()]
    if not docs:
        return f"### {title}\n{empty_message or '(no relevant context retrieved)'}"
    body = "\n\n---\n\n".join(docs)
    return f"### {title}\n{body}"
