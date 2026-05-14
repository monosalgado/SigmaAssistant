"""
Combined Review Stage: Validation + Optimization in a single LLM call.

First does deterministic YAML syntax validation (no LLM needed),
then a single LLM call for semantic review AND optimization.
Uses the FAST model (gemini-2.0-flash) since this is a lighter task.
"""

from __future__ import annotations
import json
import re
import yaml
from backend.pipeline.base_stage import PipelineStage
from backend.pipeline import prompts


REQUIRED_FIELDS = {"title", "logsource", "detection", "level"}
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}

# attack.<tactic_name> — normalize Sigma tag form (underscores) to MITRE
# phase_name form (dashes). Example: attack.initial_access -> initial-access.
_TACTIC_TAG_RE = re.compile(r"^attack\.([a-z_]+)$")
# attack.tXXXX or attack.tXXXX.YYY — technique ids.
_TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


class ReviewStage(PipelineStage):
    name = "review"
    description = "Validating and optimizing detection rules"

    def __init__(self, client, model_name: str = "", vector_store=None):
        super().__init__(client, model_name)
        self.vector_store = vector_store
        # Lazy-built cache of {technique_id_upper: set(tactic_phase_names)}
        self._mitre_tactics_cache: dict[str, set[str]] | None = None

    def _load_mitre_tactics_map(self) -> dict[str, set[str]]:
        """Build {external_id: set(tactic_phase_names)} from the MITRE RAG
        collection once. Data-driven — never hardcoded; re-ingestion auto-refreshes.
        """
        if self._mitre_tactics_cache is not None:
            return self._mitre_tactics_cache
        mapping: dict[str, set[str]] = {}
        if self.vector_store is None:
            self._mitre_tactics_cache = mapping
            return mapping
        try:
            col = self.vector_store.mitre_collection
            res = col.get(include=["metadatas"])
            for md in res.get("metadatas", []) or []:
                if not md:
                    continue
                ext_id = (md.get("external_id") or "").upper()
                tactics_str = md.get("tactics") or ""
                if not ext_id:
                    continue
                mapping[ext_id] = {
                    t.strip() for t in tactics_str.split(",") if t.strip()
                }
        except Exception as e:
            print(f"[{self.name}] Could not load MITRE tactic map: {e}")
        self._mitre_tactics_cache = mapping
        return mapping

    def _validate_mitre_tactics(self, rules: list[dict]) -> list[dict]:
        """Return list of issue dicts describing tactic↔technique mismatches
        by cross-referencing the rule's `tags:` block against the authoritative
        MITRE ATT&CK tactic graph (loaded from the RAG collection).
        """
        issues: list[dict] = []
        tactic_map = self._load_mitre_tactics_map()
        if not tactic_map:
            return issues  # no source of truth → skip silently

        for i, rule_data in enumerate(rules):
            yaml_content = rule_data.get("yaml_content", "")
            try:
                parsed = yaml.safe_load(yaml_content)
            except yaml.YAMLError:
                continue
            if not isinstance(parsed, dict):
                continue
            tags = parsed.get("tags", []) or []

            declared_tactics: set[str] = set()
            declared_techniques: list[str] = []
            for tag in tags:
                if not isinstance(tag, str):
                    continue
                tac_m = _TACTIC_TAG_RE.match(tag.strip().lower())
                tech_m = _TECHNIQUE_TAG_RE.match(tag.strip().lower())
                if tech_m:
                    declared_techniques.append(tech_m.group(1).upper())
                elif tac_m:
                    declared_tactics.add(tac_m.group(1).replace("_", "-"))

            if not declared_techniques:
                continue

            for tech_id in declared_techniques:
                legit = tactic_map.get(tech_id)
                if legit is None:
                    issues.append({
                        "severity": "warning",
                        "field": f"rule[{i}].tags",
                        "message": (
                            f"Technique {tech_id} is not in the current MITRE "
                            f"ATT&CK data (may be revoked/deprecated). Consider "
                            f"removing this tag or replacing with an active technique."
                        ),
                    })
                    continue
                # Only flag if rule declared tactics AND none overlap with the
                # technique's legitimate tactics.
                if declared_tactics and not (declared_tactics & legit):
                    issues.append({
                        "severity": "warning",
                        "field": f"rule[{i}].tags",
                        "message": (
                            f"Technique {tech_id} is tagged under tactic(s) "
                            f"{sorted(declared_tactics)} but MITRE defines it "
                            f"only under {sorted(legit)}. Remove the mismatched "
                            f"tactic tag, drop the technique, or choose a "
                            f"technique whose tactic matches the behavior."
                        ),
                    })
        return issues

    def run(self, context: dict) -> dict:
        generation = context["generation"]
        rules = generation.get("rules", [])
        extraction = context.get("extraction", {})

        if not rules:
            context["validation"] = {
                "is_valid": False,
                "issues": [{"severity": "error", "field": "rules", "message": "No rules generated"}],
                "corrected_rules": [],
            }
            context["optimization"] = {"rules": [], "summary": "No rules to review", "all_changes": []}
            return context

        # --- Part 1: Deterministic syntax validation (no LLM) ---
        all_syntax_issues = []
        for i, rule_data in enumerate(rules):
            yaml_content = rule_data.get("yaml_content", "")
            issues = self._validate_syntax(yaml_content, i)
            all_syntax_issues.extend(issues)

        has_syntax_errors = any(i["severity"] == "error" for i in all_syntax_issues)

        # If there are syntax errors, skip LLM review - report them for retry
        if has_syntax_errors:
            context["validation"] = {
                "is_valid": False,
                "issues": all_syntax_issues,
                "corrected_rules": [r.get("yaml_content", "") for r in rules],
            }
            context["optimization"] = {
                "rules": [{"yaml_content": r.get("yaml_content", ""), "changes_made": []} for r in rules],
                "summary": "Skipped optimization due to syntax errors",
                "all_changes": [],
            }
            return context

        # --- Part 2: Combined LLM review + optimization (FAST model) ---
        rules_text = "\n---\n".join(r.get("yaml_content", "") for r in rules)
        indicators = extraction.get("indicators", [])
        indicators_text = json.dumps(indicators, indent=2) if indicators else "None"

        # Collect IoCs for enrichment
        ioc_types = {"ip_address", "domain", "user_agent", "hash"}
        iocs = [ind for ind in indicators if ind.get("type") in ioc_types]
        iocs_text = json.dumps(iocs, indent=2) if iocs else "No IoCs extracted."

        # Pre-compute MITRE tactic ↔ technique mismatches from the authoritative
        # RAG collection so the LLM can fix them in this same pass.
        tactic_issues = self._validate_mitre_tactics(rules)
        if tactic_issues:
            tactic_block_lines = []
            for iss in tactic_issues:
                tactic_block_lines.append(f"- [{iss['field']}] {iss['message']}")
            tactic_issues_text = "\n".join(tactic_block_lines)
        else:
            tactic_issues_text = "No tactic↔technique mismatches detected."

        prompt = prompts.COMBINED_REVIEW.format(
            rules=rules_text,
            attack_summary=extraction.get("attack_summary", ""),
            indicators=indicators_text,
            iocs=iocs_text,
            tactic_issues=tactic_issues_text,
        )

        try:
            response_text = self.llm_call(
                prompt, temperature=0.2, json_mode=True, economy=True
            )
            result = self.parse_json(response_text)
        except Exception as e:
            print(f"[{self.name}] LLM review failed, using rules as-is: {e}")
            result = {
                "is_valid": True,
                "issues": [],
                "optimized_rules": [
                    {"yaml_content": r.get("yaml_content", ""), "changes_made": []}
                    for r in rules
                ],
                "review_summary": "Review skipped due to error",
            }

        # Unpack into validation context
        llm_issues = result.get("issues", [])
        all_issues = all_syntax_issues + tactic_issues + llm_issues
        is_valid = not any(i["severity"] == "error" for i in all_issues)

        optimized_rules = result.get("optimized_rules", [])

        # Build corrected_rules list (for potential retry)
        corrected_rules = [r.get("yaml_content", "") for r in optimized_rules] if optimized_rules else [r.get("yaml_content", "") for r in rules]

        context["validation"] = {
            "is_valid": is_valid,
            "issues": all_issues,
            "corrected_rules": corrected_rules,
        }

        # Unpack into optimization context
        all_changes = []
        for rule in optimized_rules:
            all_changes.extend(rule.get("changes_made", []))

        context["optimization"] = {
            "rules": optimized_rules,
            "summary": result.get("review_summary", ""),
            "all_changes": all_changes,
        }

        error_count = sum(1 for i in all_issues if i["severity"] == "error")
        warning_count = sum(1 for i in all_issues if i["severity"] == "warning")
        print(f"[{self.name}] Valid: {is_valid}, {error_count} errors, "
              f"{warning_count} warnings, {len(all_changes)} optimizations")
        return context

    def _validate_syntax(self, yaml_content: str, rule_index: int) -> list:
        """Deterministic YAML and Sigma structure validation (no LLM)."""
        issues = []
        prefix = f"rule[{rule_index}]"

        # 1. YAML parse
        try:
            parsed = yaml.safe_load(yaml_content)
            if not isinstance(parsed, dict):
                issues.append({
                    "severity": "error",
                    "field": prefix,
                    "message": "YAML did not parse to a dictionary",
                })
                return issues
        except yaml.YAMLError as e:
            issues.append({
                "severity": "error",
                "field": prefix,
                "message": f"Invalid YAML syntax: {e}",
            })
            return issues

        # 2. Required fields
        for field in REQUIRED_FIELDS:
            if field not in parsed:
                issues.append({
                    "severity": "error",
                    "field": f"{prefix}.{field}",
                    "message": f"Missing required field: {field}",
                })

        # 3. Logsource check
        logsource = parsed.get("logsource", {})
        if isinstance(logsource, dict):
            if not logsource.get("category") and not logsource.get("product"):
                issues.append({
                    "severity": "warning",
                    "field": f"{prefix}.logsource",
                    "message": "Logsource should have at least 'category' or 'product'",
                })

        # 4. Detection check
        detection = parsed.get("detection", {})
        if isinstance(detection, dict):
            if "condition" not in detection:
                issues.append({
                    "severity": "error",
                    "field": f"{prefix}.detection.condition",
                    "message": "Detection missing 'condition' field",
                })
            selection_keys = [k for k in detection if k != "condition"]
            if not selection_keys:
                issues.append({
                    "severity": "error",
                    "field": f"{prefix}.detection",
                    "message": "Detection has no selection fields",
                })

        # 5. Level check
        level = parsed.get("level", "")
        if level and level.lower() not in VALID_LEVELS:
            issues.append({
                "severity": "warning",
                "field": f"{prefix}.level",
                "message": f"Level '{level}' is not standard. Use: {', '.join(VALID_LEVELS)}",
            })

        # 6. Tags format check
        tags = parsed.get("tags", [])
        if isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, str) and tag.startswith("attack."):
                    continue
                elif isinstance(tag, str):
                    issues.append({
                        "severity": "info",
                        "field": f"{prefix}.tags",
                        "message": f"Tag '{tag}' doesn't follow 'attack.*' convention",
                    })

        return issues
