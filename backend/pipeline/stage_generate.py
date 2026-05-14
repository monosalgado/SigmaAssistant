"""Stage 4: Sigma Rule Generation using enriched context.

All domain knowledge (valid logsource fields, TTP selection guidance, CWE
context) now comes from RAG collections. Nothing about specific CVEs,
products, TTPs, or log formats is hardcoded in this file.
"""

import json
import datetime
from backend.pipeline.base_stage import PipelineStage
from backend.pipeline.stage_attack_vector import AttackVectorStage
from backend.pipeline import prompts
from backend.pipeline import domain_knowledge as dk


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

        # Attack vector (may be empty)
        attack_vector = context.get("attack_vector", {})
        attack_vector_summary = AttackVectorStage.format_vector_summary(attack_vector)
        payload_signatures_text = AttackVectorStage.format_payload_signatures(attack_vector)
        incidental_blacklist = AttackVectorStage.format_incidental_blacklist(attack_vector)

        # Log source info (from the analysis stage)
        logsource_info = context.get("logsource_suggestion", {})

        # --- RAG: similar Sigma rules + Sysmon info (existing collections) ---
        sigma_context = "No similar rules found."
        sysmon_context = "No Sysmon context found."
        try:
            results = self.vector_store.search(
                attack_summary, collections=["sigma", "sysmon"], n_results=3
            )
            sigma_docs = results.get("sigma", {}).get("documents", [[]])[0]
            sysmon_docs = results.get("sysmon", {}).get("documents", [[]])[0]
            if sigma_docs:
                sigma_context = "\n---\n".join(sigma_docs)
            if sysmon_docs:
                sysmon_context = "\n---\n".join(sysmon_docs)
            context["rag_sigma"] = sigma_docs or []
            context["rag_sysmon"] = sysmon_docs or []
        except Exception as e:
            print(f"[{self.name}] RAG (sigma/sysmon) search failed: {e}")
            context["rag_sigma"] = []
            context["rag_sysmon"] = []

        # --- RAG: Sigma logsource taxonomy (NEW — replaces LOGSOURCE_FIELDS dict) ---
        # Query is constructed from whatever the pipeline has inferred about
        # the log source: primary source string, first few suggestions, and the
        # attack-vector stage's primary telemetry hint. Fully generic.
        taxonomy_query_parts = [
            logsource_info.get("primary_source") or "",
            attack_vector.get("primary_telemetry") or "",
        ]
        for sug in (logsource_info.get("suggestions") or [])[:3]:
            taxonomy_query_parts.append(
                " ".join(
                    v for v in (sug.get("category"), sug.get("product"), sug.get("service")) if v
                )
            )
        taxonomy_query = " ".join(p for p in taxonomy_query_parts if p).strip()
        taxonomy_docs: list[str] = []
        if taxonomy_query:
            try:
                tres = self.vector_store.search(
                    taxonomy_query, collections=["taxonomy"], n_results=10
                )
                taxonomy_docs = tres.get("taxonomy", {}).get("documents", [[]])[0] or []
            except Exception as e:
                print(f"[{self.name}] Taxonomy RAG failed: {e}")
        context["rag_taxonomy"] = taxonomy_docs
        logsource_taxonomy_context = dk.format_rag_block(
            "Sigma logsource / field taxonomy (authoritative — derive valid field names from here)",
            taxonomy_docs,
            empty_message=(
                "(no taxonomy chunks retrieved — validate every field manually "
                "against the Sigma specification before emitting)"
            ),
        )

        # --- RAG: CWE knowledge (NEW — replaces TTP_BY_VULN_CLASS dict) ---
        cwe_hint = (attack_vector.get("cwe_hint") or "").strip()
        vuln_class = (attack_vector.get("vuln_class") or "").strip()
        cwe_query = " ".join(
            p for p in (cwe_hint, vuln_class, attack_summary[:300]) if p
        ).strip()
        cwe_docs: list[str] = []
        if cwe_query:
            try:
                cres = self.vector_store.search(
                    cwe_query, collections=["cwe"], n_results=3
                )
                cwe_docs = cres.get("cwe", {}).get("documents", [[]])[0] or []
            except Exception as e:
                print(f"[{self.name}] CWE RAG failed: {e}")
        context["rag_cwe"] = cwe_docs
        cwe_context_block = dk.format_rag_block(
            "CWE context for this vulnerability class (use to pick semantically correct MITRE techniques)",
            cwe_docs,
            empty_message="(no CWE entry retrieved)",
        )

        # --- RAG: extra MITRE technique descriptions keyed on vuln class ---
        # The analysis stage already ran one MITRE RAG; this second pass uses
        # the attack_vector signal to pull technique docs that match the
        # vulnerability class. Generic — works for any CWE.
        mitre_docs_extra: list[str] = []
        mitre_query = " ".join(p for p in (vuln_class, cwe_hint, attack_summary[:300]) if p).strip()
        if mitre_query:
            try:
                mres = self.vector_store.search(
                    mitre_query, collections=["mitre"], n_results=5
                )
                mitre_docs_extra = mres.get("mitre", {}).get("documents", [[]])[0] or []
            except Exception as e:
                print(f"[{self.name}] MITRE (vuln-class) RAG failed: {e}")
        mitre_context_block = dk.format_rag_block(
            "MITRE ATT&CK technique descriptions relevant to this vulnerability class "
            "(pick TTPs whose description matches the attack mechanics; skip any whose "
            "description is unrelated regardless of keyword similarity)",
            mitre_docs_extra,
            empty_message="(no additional MITRE chunks retrieved)",
        )

        # --- Kill-chain requirement (structural, generic) ---
        kill_chain_requirement = dk.format_kill_chain_requirement(
            attack_vector.get("kill_chain_stages", [])
        )

        # --- Coverage-feedback block (only set on the regeneration retry) ---
        coverage_feedback_block = dk.format_coverage_feedback(
            context.get("coverage_feedback_for_retry", {})
        )

        # --- Conversation history ---
        history_text = ""
        if history:
            recent = history[-10:]
            for msg in recent:
                role = "User" if msg["role"] == "user" else "AI"
                history_text += f"{role}: {msg.get('content', '')}\n\n"

        # --- Format indicators and TTPs ---
        indicators_text = json.dumps(indicators, indent=2) if indicators else "None"
        ttps_text = json.dumps(ttp_mappings, indent=2) if ttp_mappings else "None"

        # --- Reference URLs ---
        reference_urls: list[str] = []
        for uc in preprocessed.get("url_content", []):
            url = uc.get("url", "")
            if url:
                reference_urls.append(url)
        enrichment = context.get("enrichment", {})
        for src in enrichment.get("sources", []):
            url = src.get("url", "")
            if url and url not in reference_urls:
                reference_urls.append(url)
        for m in ttp_mappings:
            tid = m.get("technique_id", "")
            if tid:
                mitre_url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
                if mitre_url not in reference_urls:
                    reference_urls.append(mitre_url)
        references_text = (
            "\n".join(f"- {url}" for url in reference_urls)
            if reference_urls else "No references available."
        )

        # --- Build user-query with any validation feedback / user notes ---
        validation_feedback = context.get("validation_feedback", "")
        user_query = original_query
        if validation_feedback:
            user_query += f"\n\n### Validation Feedback (fix these issues):\n{validation_feedback}"

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

        user_notes = context.get("user_feedback_notes", "")
        if user_notes:
            user_query += f"\n\n### User Instructions:\n{user_notes}"

        # --- Assemble prompt ---
        prompt = prompts.RULE_GENERATION.format(
            current_date=current_date,
            attack_vector_summary=attack_vector_summary,
            payload_signatures=payload_signatures_text,
            incidental_blacklist=incidental_blacklist,
            attack_summary=attack_summary,
            indicators=indicators_text,
            ttp_mappings=ttps_text,
            sigma_context=sigma_context,
            sysmon_context=sysmon_context + logsource_text,
            logsource_taxonomy_context=logsource_taxonomy_context,
            cwe_context=cwe_context_block,
            mitre_context=mitre_context_block,
            kill_chain_requirement=kill_chain_requirement,
            coverage_feedback=coverage_feedback_block,
            history=history_text,
            user_query=user_query,
            references=references_text,
        )

        # --- LLM call ---
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
