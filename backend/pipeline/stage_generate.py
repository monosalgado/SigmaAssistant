"""Stage 4: Sigma Rule Generation using enriched context."""

import json
import datetime
from backend.pipeline.base_stage import PipelineStage
from backend.pipeline import prompts


class GenerateStage(PipelineStage):
    name = "generation"
    description = "Generating Sigma detection rules"

    def __init__(self, client, model_name: str, vector_store):
        super().__init__(client, model_name)
        self.vector_store = vector_store

    def run(self, context: dict) -> dict:
        extraction = context["extraction"]
        ttp_mapping = context["ttp_mapping"]
        preprocessed = context["preprocessed"]
        history = context.get("history", [])
        original_query = context["original_query"]

        attack_summary = extraction["attack_summary"]
        indicators = extraction["indicators"]
        ttp_mappings = ttp_mapping["mappings"]
        current_date = datetime.date.today().strftime("%Y-%m-%d")

        # 1. RAG: Retrieve similar Sigma rules and Sysmon info
        search_query = attack_summary
        sigma_context = "No similar rules found."
        sysmon_context = "No Sysmon context found."

        try:
            results = self.vector_store.search(
                search_query, collections=["sigma", "sysmon"], n_results=3
            )
            sigma_docs = results.get("sigma", {}).get("documents", [[]])[0]
            sysmon_docs = results.get("sysmon", {}).get("documents", [[]])[0]

            if sigma_docs:
                sigma_context = "\n---\n".join(sigma_docs)
            if sysmon_docs:
                sysmon_context = "\n---\n".join(sysmon_docs)

            # Store for context panel
            context["rag_sigma"] = sigma_docs or []
            context["rag_sysmon"] = sysmon_docs or []
        except Exception as e:
            print(f"[{self.name}] RAG search failed: {e}")
            context["rag_sigma"] = []
            context["rag_sysmon"] = []

        # 2. Format history
        history_text = ""
        if history:
            recent = history[-10:]
            for msg in recent:
                role = "User" if msg["role"] == "user" else "AI"
                history_text += f"{role}: {msg.get('content', '')}\n\n"

        # 3. Format indicators and TTPs for prompt
        indicators_text = json.dumps(indicators, indent=2) if indicators else "None"
        ttps_text = json.dumps(ttp_mappings, indent=2) if ttp_mappings else "None"

        # 4. Build prompt - include validation feedback if this is a retry
        validation_feedback = context.get("validation_feedback", "")
        user_query = original_query
        if validation_feedback:
            user_query += f"\n\n### Validation Feedback (fix these issues):\n{validation_feedback}"

        # Include log source suggestions if available
        logsource_info = context.get("logsource_suggestion", {})
        logsource_text = ""
        if logsource_info.get("suggestions"):
            logsource_text = "\n\n### Recommended Log Sources (from analysis)\n"
            primary = logsource_info.get("primary_source", "")
            if logsource_info.get("user_confirmed"):
                logsource_text += f"**User confirmed primary log source: {primary}** - USE THIS.\n"
            elif primary:
                logsource_text += f"Primary recommendation: {primary}\n"
            for sug in logsource_info["suggestions"][:3]:
                logsource_text += (
                    f"- {sug.get('category', '?')}/{sug.get('product', '?')}/{sug.get('service', '?')} "
                    f"(confidence: {sug.get('confidence', '?')}): {sug.get('reasoning', '')}\n"
                    f"  Fields: {', '.join(sug.get('relevant_fields', []))}\n"
                )

        # Include user feedback notes if any
        user_notes = context.get("user_feedback_notes", "")
        if user_notes:
            user_query += f"\n\n### User Instructions:\n{user_notes}"

        prompt = prompts.RULE_GENERATION.format(
            current_date=current_date,
            attack_summary=attack_summary,
            indicators=indicators_text,
            ttp_mappings=ttps_text,
            sigma_context=sigma_context,
            sysmon_context=sysmon_context + logsource_text,
            history=history_text,
            user_query=user_query,
        )

        # 5. Generate with slightly creative temperature
        try:
            response_text = self.llm_call(prompt, temperature=0.3, json_mode=True)
            result = self.parse_json(response_text)
        except Exception as e:
            print(f"[{self.name}] Generation failed: {e}")
            result = {"rules": [], "notes": f"Generation error: {e}"}

        rules = result.get("rules", [])
        context["generation"] = {
            "rules": rules,
            "notes": result.get("notes", ""),
        }

        print(f"[{self.name}] Generated {len(rules)} rule(s)")
        return context
