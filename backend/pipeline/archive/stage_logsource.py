"""Stage 5: Log Source Suggestion - dedicated reasoning about detection log sources."""

from __future__ import annotations
import json
from backend.pipeline.base_stage import PipelineStage
from backend.pipeline import prompts


class LogSourceStage(PipelineStage):
    name = "logsource_suggestion"
    description = "Analyzing optimal log sources for detection"

    def run(self, context: dict) -> dict:
        extraction = context["extraction"]
        ttp_mapping = context["ttp_mapping"]

        attack_summary = extraction["attack_summary"]
        indicators = extraction["indicators"]
        ttp_mappings = ttp_mapping["mappings"]

        indicators_text = json.dumps(indicators, indent=2) if indicators else "No indicators."
        ttps_text = json.dumps(ttp_mappings, indent=2) if ttp_mappings else "No TTP mappings."

        prompt = prompts.LOG_SOURCE_SUGGESTION.format(
            attack_summary=attack_summary,
            indicators=indicators_text,
            ttp_mappings=ttps_text,
        )

        try:
            # economy=True → Spark/Ollama (structured JSON task, no rule-quality risk)
            response_text = self.llm_call(prompt, temperature=0.0, json_mode=True, economy=True)
            result = self.parse_json(response_text)
        except Exception as e:
            print(f"[{self.name}] Log source suggestion failed: {e}")
            result = {"suggestions": [], "primary_source": ""}

        suggestions = result.get("suggestions", [])
        primary_source = result.get("primary_source", "")

        context["logsource_suggestion"] = {
            "suggestions": suggestions,
            "primary_source": primary_source,
        }

        # Log findings
        if suggestions:
            top = suggestions[0]
            print(f"[{self.name}] Primary: {primary_source} | "
                  f"Top suggestion: {top.get('category', '?')}/{top.get('product', '?')} "
                  f"(confidence: {top.get('confidence', '?')})")
        else:
            print(f"[{self.name}] No log source suggestions generated")

        return context
