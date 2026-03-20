"""Stage 3: MITRE ATT&CK TTP Mapping using RAG + LLM."""

import json
from backend.pipeline.base_stage import PipelineStage
from backend.pipeline import prompts


class TTPMapStage(PipelineStage):
    name = "ttp_mapping"
    description = "Mapping to MITRE ATT&CK techniques"

    def __init__(self, client, model_name: str, vector_store):
        super().__init__(client, model_name)
        self.vector_store = vector_store

    def run(self, context: dict) -> dict:
        extraction = context["extraction"]
        attack_summary = extraction["attack_summary"]
        indicators = extraction["indicators"]

        # 1. Query MITRE collection for relevant techniques
        search_query = attack_summary
        if indicators:
            # Add high-confidence indicator values to the search
            top_indicators = [
                ind["value"] for ind in indicators
                if ind.get("confidence") == "high"
            ][:5]
            search_query += " " + " ".join(top_indicators)

        mitre_context = "No MITRE context available."
        try:
            results = self.vector_store.search(
                search_query, collections=["mitre"], n_results=5
            )
            mitre_docs = results.get("mitre", {}).get("documents", [[]])[0]
            if mitre_docs:
                mitre_context = "\n".join(mitre_docs)
        except Exception as e:
            print(f"[{self.name}] MITRE RAG search failed: {e}")

        # Also store mitre_docs for use in generation stage context panel
        context["rag_mitre"] = mitre_docs if mitre_docs else []

        # 2. LLM call for TTP mapping
        indicators_text = json.dumps(indicators, indent=2) if indicators else "No indicators extracted."

        prompt = prompts.TTP_MAPPING.format(
            attack_summary=attack_summary,
            indicators=indicators_text,
            mitre_context=mitre_context,
        )

        try:
            response_text = self.llm_call(prompt, temperature=0.0, json_mode=True)
            result = self.parse_json(response_text)
        except Exception as e:
            print(f"[{self.name}] TTP mapping failed: {e}")
            result = {"mappings": []}

        mappings = result.get("mappings", [])
        context["ttp_mapping"] = {"mappings": mappings}

        techniques = [f"{m.get('technique_id', '?')} ({m.get('technique_name', '?')})" for m in mappings]
        print(f"[{self.name}] Mapped {len(mappings)} TTPs: {', '.join(techniques[:5])}")
        return context
