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
from backend.pipeline.attack_ids import load_attack_ids, split_known
from backend.pipeline.stage_logsource_ranking import LogSourceRankingStage
from backend.pipeline.sigma_logsource import (
    format_category_table,
    format_service_table,
    load_known_services,
    load_logsource_table,
    normalise_suggestion,
)

# Loaded once: the (product, service) pairs SigmaHQ uses without a category (Change 25).
_KNOWN_SERVICES = load_known_services()
# Loaded once: every log source SigmaHQ's rules use, for the prompt's tables (Change 28).
_LOGSOURCE_TABLE = load_logsource_table()
_LOGSOURCE_CATEGORIES = format_category_table(_LOGSOURCE_TABLE)
_LOGSOURCE_SERVICES = format_service_table(_LOGSOURCE_TABLE)
# Loaded once: every technique ID in the local ATT&CK data (Change 31).
_ATTACK_IDS = load_attack_ids()


class AnalysisStage(PipelineStage):
    name = "analysis"
    description = "Extracting indicators, mapping TTPs, and suggesting log sources"

    def __init__(self, client, model_name: str, vector_store):
        super().__init__(client, model_name)
        self.vector_store = vector_store
        # A short second call orders the suggestions by their evidence (Change 38 v3).
        self.ranker = LogSourceRankingStage(client, model_name)

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
            logsource_categories=_LOGSOURCE_CATEGORIES,
            logsource_services=_LOGSOURCE_SERVICES,
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

        # Technique IDs ATT&CK does not have are dropped and recorded, never repaired (Change 31).
        ttp_mappings, dropped_ids = split_known(result.get("ttp_mappings", []), _ATTACK_IDS)
        context["ttp_mapping"] = {"mappings": ttp_mappings, "dropped_ids": dropped_ids}
        if dropped_ids:
            print(f"[{self.name}] Dropped {len(dropped_ids)} technique ID(s) not in ATT&CK: "
                  f"{', '.join(i or '(blank)' for i in dropped_ids[:5])}"
                  f"{'…' if len(dropped_ids) > 5 else ''}")

        # A suggestion with a category carries no service (Sigma's convention); an
        # unknown service without a category is marked for the analyst to confirm.
        logsource_suggestions = [
            normalise_suggestion(s, _KNOWN_SERVICES) if isinstance(s, dict) else s
            for s in result.get("logsource_suggestions", [])
        ]
        logsource_primary = result.get("logsource_primary", "")
        # The text's evidence, each item with the log source that records it and whether it is specific
        # to the attack (Change 38); the ranking step orders the suggestions from it (v3).
        evidence_inventory = result.get("evidence_inventory", [])
        logsource_suggestions, ranking = self.ranker.rank(
            logsource_suggestions, evidence_inventory, _LOGSOURCE_TABLE, _KNOWN_SERVICES)
        context["logsource_suggestion"] = {
            "suggestions": logsource_suggestions,
            "primary_source": logsource_primary,
            "evidence_inventory": evidence_inventory,
            "ranking": ranking,
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
