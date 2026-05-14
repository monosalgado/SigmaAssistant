"""
Attack Vector Extraction Stage.

Runs BEFORE combined analysis. Forces the pipeline to explicitly identify the
primary attack vector before any IOC extraction, so downstream stages don't
over-index on incidental strings (patch-analysis artifacts, background text,
researcher workflow, etc.).

Key outputs consumed downstream:
  - attack_vector.initial_access_vector  -> anchor for rule generation
  - attack_vector.payload_signatures     -> concrete detection patterns
  - attack_vector.incidental_artifacts   -> BLACKLIST for indicator extraction
  - attack_vector.kill_chain_stages      -> coverage-gap check
  - attack_vector.primary_telemetry      -> log source hint

Generic by design: uses CWE categories + MITRE tactics, no CVE-specific logic.
Uses the PRIMARY model because this single decision anchors the whole pipeline.
"""

from __future__ import annotations
import json
from backend.pipeline.base_stage import PipelineStage
from backend.pipeline import prompts


class AttackVectorStage(PipelineStage):
    name = "attack_vector"
    description = "Identifying the primary attack vector"

    # Default (empty) structure - used when the stage skips or fails. Downstream
    # stages MUST handle these empty defaults gracefully.
    EMPTY_RESULT = {
        "initial_access_vector": "",
        "protocol": "unknown",
        "entry_point": "",
        "attacker_controlled_input": "",
        "preconditions": "unknown",
        "vuln_class": "other",
        "cwe_hint": "",
        "cvss_attack_vector": "unknown",
        "payload_signatures": [],
        "primary_telemetry": "other",
        "secondary_telemetry": [],
        "kill_chain_stages": [],
        "incidental_artifacts": [],
        "confidence": 0.0,
        "reasoning": "",
    }

    def run(self, context: dict) -> dict:
        preprocessed = context.get("preprocessed", {})
        combined_text = preprocessed.get("combined_text", "")
        poc = context.get("poc_analysis", {})
        poc_behaviors = poc.get("behavioral_indicators", [])

        # Skip if there's truly nothing to analyze (no text AND no PoC). We still
        # run for short text because classification is cheap and anchors downstream.
        if not combined_text.strip() and not poc_behaviors:
            print(f"[{self.name}] No input text or PoC behaviors; skipping")
            context["attack_vector"] = dict(self.EMPTY_RESULT)
            return context

        # Format PoC behaviors compactly
        if poc_behaviors:
            poc_text = json.dumps(poc_behaviors[:15], indent=2)
        else:
            poc_text = "No PoC behaviors extracted."

        prompt = prompts.ATTACK_VECTOR_EXTRACTION.format(
            text=combined_text[:8000],
            poc_behaviors=poc_text,
        )

        try:
            # economy=True → Spark/Ollama (qwen3-coder:30b) when tunnel is up,
            # falls back to Gemini fast (gemini-2.0-flash) if Ollama unreachable.
            response_text = self.llm_call(
                prompt, temperature=0.0, json_mode=True, economy=True
            )
            result = self.parse_json(response_text)
        except Exception as e:
            print(f"[{self.name}] Attack vector extraction failed: {e}")
            result = dict(self.EMPTY_RESULT)
            result["reasoning"] = f"Extraction failed: {e}"

        # Normalize/harden output (LLM can omit keys)
        normalized = dict(self.EMPTY_RESULT)
        for k, default in self.EMPTY_RESULT.items():
            v = result.get(k, default)
            # Basic type coercion
            if isinstance(default, list) and not isinstance(v, list):
                v = []
            if isinstance(default, str) and not isinstance(v, str):
                v = str(v) if v is not None else ""
            normalized[k] = v

        # Confidence clamp
        try:
            c = float(normalized.get("confidence", 0.0) or 0.0)
            normalized["confidence"] = max(0.0, min(1.0, c))
        except (TypeError, ValueError):
            normalized["confidence"] = 0.0

        context["attack_vector"] = normalized

        # Log summary
        av = normalized
        print(
            f"[{self.name}] vector: {av['vuln_class']} via {av['protocol']}; "
            f"entry_point={av['entry_point'] or '-'}; "
            f"payload_signatures={len(av['payload_signatures'])}; "
            f"incidental={len(av['incidental_artifacts'])}; "
            f"confidence={av['confidence']:.2f}"
        )
        return context

    # --- Helpers consumed by downstream stages ---

    @staticmethod
    def format_vector_summary(attack_vector: dict) -> str:
        """Compact human-readable anchor line for downstream prompts.
        Returns empty string if the stage produced nothing useful."""
        if not attack_vector or not attack_vector.get("initial_access_vector"):
            return "No primary attack vector identified. Analyze the text conservatively."

        parts = [
            f"- Initial access vector: {attack_vector['initial_access_vector']}",
            f"- Vulnerability class: {attack_vector.get('vuln_class', 'unknown')}"
            + (f" ({attack_vector['cwe_hint']})" if attack_vector.get("cwe_hint") else ""),
            f"- Protocol: {attack_vector.get('protocol', 'unknown')}",
            f"- Entry point: {attack_vector.get('entry_point') or 'n/a'}",
            f"- Attacker-controlled input: {attack_vector.get('attacker_controlled_input') or 'n/a'}",
            f"- Preconditions: {attack_vector.get('preconditions', 'unknown')}",
            f"- Primary telemetry: {attack_vector.get('primary_telemetry', 'unknown')}",
            f"- Kill-chain stages evidenced: {', '.join(attack_vector.get('kill_chain_stages', [])) or 'n/a'}",
            f"- Extractor confidence: {attack_vector.get('confidence', 0.0):.2f}",
        ]
        return "\n".join(parts)

    @staticmethod
    def format_payload_signatures(attack_vector: dict) -> str:
        """Bullet list of payload signatures for generation prompt."""
        sigs = (attack_vector or {}).get("payload_signatures", [])
        if not sigs:
            return "No explicit payload signatures identified."
        lines = []
        for s in sigs[:10]:
            pattern = s.get("pattern", "")
            where = s.get("where", "")
            derived = s.get("derived_from", "")
            lines.append(f"- `{pattern}` (in {where}) — {derived}")
        return "\n".join(lines)

    @staticmethod
    def format_incidental_blacklist(attack_vector: dict) -> str:
        """Bullet list of strings to EXCLUDE from detection rules."""
        items = (attack_vector or {}).get("incidental_artifacts", [])
        if not items:
            return "None identified."
        lines = []
        for it in items[:20]:
            value = it.get("value", "") if isinstance(it, dict) else str(it)
            reason = it.get("reason", "") if isinstance(it, dict) else ""
            if reason:
                lines.append(f"- `{value}` — {reason}")
            else:
                lines.append(f"- `{value}`")
        return "\n".join(lines)

    @staticmethod
    def coverage_gap_check(attack_vector: dict, generated_rules: list[dict]) -> dict:
        """Deterministic coverage check after generation.

        Returns a dict with:
          - initial_access_covered: bool
          - payload_signatures_covered: list of signatures that ARE referenced
          - payload_signatures_missed:  list of signatures that are NOT referenced
          - blacklist_violations: list of blacklist entries found in any rule
          - warnings: human-readable warning strings for the user
        """
        av = attack_vector or {}
        rules = generated_rules or []

        # Flatten all rule YAML content for substring matching
        all_yaml = "\n".join(
            (r.get("yaml_content", "") or "") for r in rules
        ).lower()

        # Check payload signatures
        sigs = av.get("payload_signatures", [])
        covered, missed = [], []
        for s in sigs:
            pat = (s.get("pattern", "") or "").lower().strip()
            if not pat:
                continue
            # Strip regex-ish noise to make the substring match forgiving
            simplified = pat.strip("^$.*+?").replace("\\", "")
            if simplified and simplified in all_yaml:
                covered.append(s.get("pattern"))
            else:
                missed.append(s.get("pattern"))

        # Check blacklist violations (strings that shouldn't be in rules)
        blacklist = av.get("incidental_artifacts", [])
        violations = []
        for it in blacklist:
            val = (it.get("value", "") if isinstance(it, dict) else str(it)).lower().strip()
            if not val or len(val) < 4:  # ignore super-short strings to avoid false matches
                continue
            if val in all_yaml:
                violations.append(it.get("value") if isinstance(it, dict) else val)

        # Initial-access coverage heuristic: rule references entry_point OR
        # attacker_controlled_input OR any payload signature.
        entry = (av.get("entry_point") or "").lower().strip()
        input_name = (av.get("attacker_controlled_input") or "").lower().strip()
        ia_evidence = bool(covered)  # at least one signature covered
        if entry and len(entry) >= 3 and entry in all_yaml:
            ia_evidence = True
        if input_name and len(input_name) >= 3 and input_name in all_yaml:
            ia_evidence = True
        # If the analyst said there's no initial_access stage, we don't need it.
        needs_ia = "initial_access" in av.get("kill_chain_stages", [])
        initial_access_covered = (not needs_ia) or ia_evidence

        # Kill-chain coverage: if the write-up spans N stages, at least N rules
        # should exist. This catches the "one mega-rule AND-ing everything"
        # failure mode observed in prior generations.
        kc_stages = [s for s in av.get("kill_chain_stages", []) if s]
        kill_chain_gap = None
        if len(kc_stages) >= 2 and len(rules) < len(kc_stages):
            kill_chain_gap = (
                f"Attack spans {len(kc_stages)} kill-chain stages "
                f"({', '.join(kc_stages)}) but only {len(rules)} rule(s) were produced. "
                "Each stage should have its own rule — indicators from different "
                "requests cannot co-occur in a single log line."
            )

        # Bad logsource.version pinning detector. A common mistake is copying the
        # AFFECTED or PATCHED product version into `logsource.version`. That field
        # is only meant for log-format versions, which almost never differ.
        version_pin_violations = []
        for r in rules:
            y = (r.get("yaml_content", "") or "")
            # Cheap, permissive scan — we don't parse YAML here to avoid pulling a dep.
            # Look for `version:` inside a `logsource:` block.
            lo = y.lower()
            if "logsource:" in lo and "version:" in lo:
                # Heuristic: if `version:` appears within ~200 chars of `logsource:`
                # and the value looks like a product semver, flag it.
                idx_ls = lo.find("logsource:")
                idx_v = lo.find("version:", idx_ls)
                if 0 < idx_v - idx_ls < 200:
                    # Grab the version value
                    tail = y[idx_v + len("version:"):].splitlines()[0].strip().strip("'\"")
                    # Flag any value that looks like 1.2.3 / 2.4 / etc.
                    if tail and any(c.isdigit() for c in tail):
                        version_pin_violations.append(tail)

        # NOTE: Previous versions also flagged "wrong" `service:` values using a
        # small whitelist of web-server service names. That check has been
        # removed because it encoded product-specific assumptions (e.g. which
        # service strings are "legitimate" for which product). Validity of
        # `logsource.service` now belongs to the prompt-time taxonomy RAG and
        # to the review stage — both operate on authoritative data, not a
        # hardcoded list.
        warnings = []
        if needs_ia and not initial_access_covered:
            warnings.append(
                "No rule appears to detect the primary attack vector. "
                f"Expected coverage of entry point `{av.get('entry_point') or '?'}` "
                f"or input `{av.get('attacker_controlled_input') or '?'}`."
            )
        if missed and sigs:
            warnings.append(
                f"{len(missed)}/{len(sigs)} payload signatures were not referenced by any rule: "
                + ", ".join(f"`{m}`" for m in missed[:5])
                + ("…" if len(missed) > 5 else "")
            )
        if violations:
            warnings.append(
                "Rules reference strings flagged as researcher/patch-workflow artifacts "
                "(these would NOT appear in real attacks): "
                + ", ".join(f"`{v}`" for v in violations[:5])
                + ("…" if len(violations) > 5 else "")
            )
        if kill_chain_gap:
            warnings.append(kill_chain_gap)
        if version_pin_violations:
            warnings.append(
                "Rule(s) set `logsource.version` — this field is for log-format versions, "
                "not product versions. Remove it: "
                + ", ".join(f"`{v}`" for v in version_pin_violations[:3])
            )

        return {
            "initial_access_covered": initial_access_covered,
            "payload_signatures_covered": covered,
            "payload_signatures_missed": missed,
            "blacklist_violations": violations,
            "kill_chain_gap": kill_chain_gap,
            "version_pin_violations": version_pin_violations,
            "warnings": warnings,
        }
