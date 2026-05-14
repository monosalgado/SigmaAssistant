"""Stage 6: Rule Optimization - selection unification, IoC enrichment, deduplication."""

import json
from backend.pipeline.base_stage import PipelineStage
from backend.pipeline import prompts


class OptimizeStage(PipelineStage):
    name = "optimization"
    description = "Optimizing detection rules and enriching with IoCs"

    def run(self, context: dict) -> dict:
        validation = context["validation"]
        extraction = context.get("extraction", {})
        corrected_rules = validation.get("corrected_rules", [])

        if not corrected_rules:
            context["optimization"] = {"rules": [], "summary": "No rules to optimize"}
            return context

        # Collect IoCs from extracted indicators
        ioc_types = {"ip_address", "domain", "user_agent", "hash"}
        iocs = [
            ind for ind in extraction.get("indicators", [])
            if ind.get("type") in ioc_types
        ]

        rules_text = "\n---\n".join(corrected_rules)
        iocs_text = json.dumps(iocs, indent=2) if iocs else "No IoCs extracted."

        prompt = prompts.RULE_OPTIMIZATION.format(
            rules=rules_text,
            iocs=iocs_text,
        )

        try:
            response_text = self.llm_call(prompt, temperature=0.2, json_mode=True)
            result = self.parse_json(response_text)
        except Exception as e:
            print(f"[{self.name}] Optimization failed, using validated rules: {e}")
            result = {
                "rules": [{"yaml_content": r, "changes_made": []} for r in corrected_rules],
                "summary": "Optimization skipped due to error",
            }

        optimized_rules = result.get("rules", [])
        summary = result.get("summary", "")

        # Collect all changes for metadata
        all_changes = []
        for rule in optimized_rules:
            all_changes.extend(rule.get("changes_made", []))

        context["optimization"] = {
            "rules": optimized_rules,
            "summary": summary,
            "all_changes": all_changes,
        }

        print(f"[{self.name}] Optimized {len(optimized_rules)} rule(s). Changes: {len(all_changes)}")
        return context
