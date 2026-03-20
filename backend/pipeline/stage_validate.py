"""Stage 5: Rule Validation - YAML syntax + semantic LLM review."""

from __future__ import annotations
import json
import yaml
from backend.pipeline.base_stage import PipelineStage
from backend.pipeline import prompts


REQUIRED_FIELDS = {"title", "logsource", "detection", "level"}
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


class ValidateStage(PipelineStage):
    name = "validation"
    description = "Validating rule syntax and detection logic"

    def run(self, context: dict) -> dict:
        generation = context["generation"]
        rules = generation.get("rules", [])

        if not rules:
            context["validation"] = {
                "is_valid": False,
                "issues": [{"severity": "error", "field": "rules", "message": "No rules generated"}],
                "corrected_rules": [],
            }
            return context

        all_issues = []
        corrected_rules = []

        for i, rule_data in enumerate(rules):
            yaml_content = rule_data.get("yaml_content", "")
            issues = self._validate_syntax(yaml_content, i)
            all_issues.extend(issues)
            corrected_rules.append(yaml_content)

        has_errors = any(issue["severity"] == "error" for issue in all_issues)

        # LLM semantic review (only if syntax is mostly OK)
        if not has_errors and rules:
            try:
                llm_issues, llm_corrected = self._llm_review(rules, context)
                all_issues.extend(llm_issues)
                if llm_corrected:
                    corrected_rules = llm_corrected
            except Exception as e:
                print(f"[{self.name}] LLM review failed: {e}")

        is_valid = not any(issue["severity"] == "error" for issue in all_issues)

        context["validation"] = {
            "is_valid": is_valid,
            "issues": all_issues,
            "corrected_rules": corrected_rules,
        }

        error_count = sum(1 for i in all_issues if i["severity"] == "error")
        warning_count = sum(1 for i in all_issues if i["severity"] == "warning")
        print(f"[{self.name}] Valid: {is_valid}, {error_count} errors, {warning_count} warnings")
        return context

    def _validate_syntax(self, yaml_content: str, rule_index: int) -> list[dict]:
        """Deterministic YAML and Sigma structure validation."""
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

    def _llm_review(self, rules: list[dict], context: dict) -> tuple[list[dict], list[str] | None]:
        """LLM-based semantic review of rules."""
        extraction = context.get("extraction", {})
        rules_text = "\n---\n".join(
            r.get("yaml_content", "") for r in rules
        )
        indicators_text = json.dumps(
            extraction.get("indicators", []), indent=2
        )

        prompt = prompts.RULE_VALIDATION.format(
            rules=rules_text,
            attack_summary=extraction.get("attack_summary", ""),
            indicators=indicators_text,
        )

        response_text = self.llm_call(prompt, temperature=0.0, json_mode=True)
        result = self.parse_json(response_text)

        issues = result.get("issues", [])
        corrected = result.get("corrected_rules", None)

        return issues, corrected
