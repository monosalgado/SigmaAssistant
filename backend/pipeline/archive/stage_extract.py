"""Stage 2: Entity/Indicator Extraction from preprocessed text."""

from backend.pipeline.base_stage import PipelineStage
from backend.pipeline import prompts


class ExtractStage(PipelineStage):
    name = "extraction"
    description = "Extracting threat indicators and attack patterns"

    def run(self, context: dict) -> dict:
        preprocessed = context["preprocessed"]
        combined_text = preprocessed["combined_text"]

        prompt = prompts.ENTITY_EXTRACTION.format(text=combined_text[:6000])

        try:
            # economy=True → Spark/Ollama (IoC/entity extraction — pattern-matching task)
            response_text = self.llm_call(prompt, temperature=0.0, json_mode=True, economy=True)
            result = self.parse_json(response_text)
        except Exception as e:
            print(f"[{self.name}] Extraction failed: {e}")
            result = {
                "indicators": [],
                "attack_summary": combined_text[:500],
                "suggested_log_sources": [],
            }

        indicators = result.get("indicators", [])
        attack_summary = result.get("attack_summary", "")
        suggested_log_sources = result.get("suggested_log_sources", [])

        context["extraction"] = {
            "indicators": indicators,
            "attack_summary": attack_summary,
            "suggested_log_sources": suggested_log_sources,
        }

        print(f"[{self.name}] Extracted {len(indicators)} indicators, "
              f"log sources: {suggested_log_sources}")
        return context
