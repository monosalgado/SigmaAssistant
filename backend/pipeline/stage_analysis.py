"""
Combined Analysis Stage: Entity Extraction + TTP Mapping + Log Source Suggestion.

Merges three former stages into a single LLM call to reduce API usage.
Uses the PRIMARY model (gemini-2.5-flash) since this is a critical stage.
"""

from __future__ import annotations
import json
from backend.pipeline.base_stage import PipelineStage
from backend.pipeline.stage_attack_vector import AttackVectorStage
from backend.pipeline import prompts
from backend.pipeline.sigma_logsource import load_known_services, normalise_suggestion

# Loaded once: the (product, service) pairs SigmaHQ uses without a category (Change 25).
_KNOWN_SERVICES = load_known_services()


class AnalysisStage(PipelineStage):
    name = "analysis"
    description = "Extracting indicators, mapping TTPs, and suggesting log sources"

    def __init__(self, client, model_name: str, vector_store):
        super().__init__(client, model_name)
        self.vector_store = vector_store

    def run(self, context: dict) -> dict:
        preprocessed = context["preprocessed"]
        combined_text = preprocessed["combined_text"]

        # 1. RAG: Retrieve MITRE ATT&CK context for better TTP mapping
        mitre_context = "No MITRE context available."
        mitre_docs = []
        try:
            results = self.vector_store.search(
                combined_text[:500], collections=["mitre"], n_results=5
            )
            mitre_docs = results.get("mitre", {}).get("documents", [[]])[0]
            if mitre_docs:
                mitre_context = "\n".join(mitre_docs)
        except Exception as e:
            print(f"[{self.name}] MITRE RAG search failed: {e}")

        context["rag_mitre"] = mitre_docs

        # 2. Pull attack-vector anchor context (may be empty on error/skip)
        attack_vector = context.get("attack_vector", {})
        attack_vector_summary = AttackVectorStage.format_vector_summary(attack_vector)
        incidental_blacklist = AttackVectorStage.format_incidental_blacklist(attack_vector)

        # 3. Single LLM call for combined analysis (ECONOMY → Spark)
        # Routes to qwen3-coder:30b on Spark when tunnel is up; falls back to
        # Gemini fast (gemini-2.0-flash) if Ollama unreachable.
        # The whole source up to SOURCE_TEXT_MAX_CHARS: a 4000-char window held
        # only site navigation on many pages (see base_stage).
        prompt = prompts.COMBINED_ANALYSIS.format(
            text=self.source_text(combined_text),
            attack_vector_summary=attack_vector_summary,
            incidental_blacklist=incidental_blacklist,
            mitre_context=mitre_context,
        )

        try:
            response_text = self.llm_call(
                prompt, temperature=0.0, json_mode=True, economy=True
            )
            result = self.parse_json(response_text)
        except Exception as e:
            print(f"[{self.name}] Combined analysis failed: {e}")
            result = {
                "indicators": [],
                "attack_summary": combined_text[:500],
                "suggested_log_sources": [],
                "ttp_mappings": [],
                "logsource_suggestions": [],
                "logsource_primary": "",
            }

        # 3. Unpack results into the same context keys the pipeline expects
        indicators = result.get("indicators", [])
        attack_summary = result.get("attack_summary", "")
        suggested_log_sources = result.get("suggested_log_sources", [])

        context["extraction"] = {
            "indicators": indicators,
            "attack_summary": attack_summary,
            "suggested_log_sources": suggested_log_sources,
        }

        ttp_mappings = result.get("ttp_mappings", [])
        context["ttp_mapping"] = {"mappings": ttp_mappings}

        # A suggestion with a category carries no service (Sigma's convention); an
        # unknown service without a category is marked for the analyst to confirm.
        logsource_suggestions = [
            normalise_suggestion(s, _KNOWN_SERVICES) if isinstance(s, dict) else s
            for s in result.get("logsource_suggestions", [])
        ]
        logsource_primary = result.get("logsource_primary", "")
        context["logsource_suggestion"] = {
            "suggestions": logsource_suggestions,
            "primary_source": logsource_primary,
        }

        # Log summary
        techniques = [
            f"{m.get('technique_id', '?')} ({m.get('technique_name', '?')})"
            for m in ttp_mappings
        ]
        print(
            f"[{self.name}] {len(indicators)} indicators, "
            f"{len(ttp_mappings)} TTPs ({', '.join(techniques[:3])}), "
            f"primary logsource: {logsource_primary}"
        )
        return context
