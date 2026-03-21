"""
Pipeline Orchestrator - Runs stages in sequence, handles intent classification,
validation retries, and formats output for the frontend.
"""

from __future__ import annotations
import json
import datetime
from typing import Generator

from backend.pipeline.base_stage import PipelineStage
from backend.pipeline.stage_preprocess import PreprocessStage
from backend.pipeline.stage_web_enrich import WebEnrichStage
from backend.pipeline.stage_poc_analysis import PoCAnalysisStage
from backend.pipeline.stage_extract import ExtractStage
from backend.pipeline.stage_ttp_map import TTPMapStage
from backend.pipeline.stage_logsource import LogSourceStage
from backend.pipeline.stage_generate import GenerateStage
from backend.pipeline.stage_validate import ValidateStage
from backend.pipeline.stage_optimize import OptimizeStage
from backend.pipeline import prompts


class PipelineOrchestrator:
    """Orchestrates the multi-stage Sigma rule generation pipeline."""

    def __init__(self, client, model_name: str, vector_store):
        self.client = client
        self.model_name = model_name
        self.vector_store = vector_store

        # Initialize stages
        self.preprocess = PreprocessStage(client, model_name)
        self.web_enrich = WebEnrichStage(client, model_name)
        self.poc_analysis = PoCAnalysisStage(client, model_name)
        self.extract = ExtractStage(client, model_name)
        self.ttp_map = TTPMapStage(client, model_name, vector_store)
        self.logsource = LogSourceStage(client, model_name)
        self.generate = GenerateStage(client, model_name, vector_store)
        self.validate = ValidateStage(client, model_name)
        self.optimize = OptimizeStage(client, model_name)

        # Track whether user feedback is pending (for feedback loop)
        self._pending_feedback = None

    def classify_intent(self, message: str, history: list[dict] = None) -> dict:
        """Classify user intent to decide whether to run the full pipeline."""
        history_text = ""
        if history:
            for msg in history[-6:]:
                role = "User" if msg["role"] == "user" else "AI"
                history_text += f"{role}: {msg.get('content', '')}\n"

        prompt = prompts.INTENT_CLASSIFICATION.format(
            history=history_text or "No prior conversation.",
            message=message,
        )

        try:
            from google.genai import types
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=[prompt],
                config=types.GenerateContentConfig(
                    temperature=0.0,
                    response_mime_type="application/json",
                ),
            )
            result = json.loads(response.text)
            return result
        except Exception as e:
            print(f"[orchestrator] Intent classification failed: {e}")
            # Default to generate_rule to avoid blocking
            return {"intent": "generate_rule", "reasoning": "Classification failed, defaulting to rule generation"}

    def handle_conversational(self, message: str, history: list[dict] = None) -> str:
        """Handle chat/question intents with a simple conversational response."""
        current_date = datetime.date.today().strftime("%Y-%m-%d")

        history_text = ""
        if history:
            for msg in history[-10:]:
                role = "User" if msg["role"] == "user" else "AI"
                history_text += f"{role}: {msg.get('content', '')}\n\n"

        # Light RAG for questions
        sigma_context = "No context."
        mitre_context = "No context."
        sysmon_context = "No context."
        try:
            results = self.vector_store.search(
                message, collections=["sigma", "mitre", "sysmon"], n_results=3
            )
            sigma_docs = results.get("sigma", {}).get("documents", [[]])[0]
            mitre_docs = results.get("mitre", {}).get("documents", [[]])[0]
            sysmon_docs = results.get("sysmon", {}).get("documents", [[]])[0]
            if sigma_docs:
                sigma_context = "\n".join(sigma_docs)
            if mitre_docs:
                mitre_context = "\n".join(mitre_docs)
            if sysmon_docs:
                sysmon_context = "\n".join(sysmon_docs)
        except Exception:
            pass

        prompt = prompts.CONVERSATIONAL.format(
            current_date=current_date,
            history=history_text or "No prior conversation.",
            message=message,
            sigma_context=sigma_context,
            mitre_context=mitre_context,
            sysmon_context=sysmon_context,
        )

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=[prompt],
            )
            return response.text
        except Exception as e:
            return f"I apologize, I encountered an error: {e}"

    def run_sync(self, description: str, history: list[dict] = None, media_file: dict = None) -> dict:
        """Run the full pipeline synchronously. Returns same format as old analyze_attack."""
        # Step 0: Intent classification
        intent_result = self.classify_intent(description, history)
        intent = intent_result.get("intent", "generate_rule")
        print(f"[orchestrator] Intent: {intent} ({intent_result.get('reasoning', '')})")

        if intent in ("chat", "question"):
            response_text = self.handle_conversational(description, history)
            return {
                "rule": response_text,
                "context": {"sigma": [], "mitre": [], "sysmon": []},
                "pipeline_metadata": None,
            }

        # Run full pipeline
        context = {
            "original_query": description,
            "history": history or [],
            "media_file": media_file,
        }

        # Stage 1: Preprocess
        context = self.preprocess.run(context)

        # Stage 1b: Web Search Enrichment
        context = self.web_enrich.run(context)

        # Stage 1c: PoC Code Analysis
        context = self.poc_analysis.run(context)

        # Stage 2: Extract
        context = self.extract.run(context)

        # Stage 3: TTP Map
        context = self.ttp_map.run(context)

        # Stage 3b: Log Source Suggestion
        context = self.logsource.run(context)

        # Stage 4: Generate (includes logsource suggestions)
        context = self.generate.run(context)

        # Stage 5: Validate
        context = self.validate.run(context)

        # Retry generation once if validation has errors
        if not context["validation"]["is_valid"]:
            issues = context["validation"]["issues"]
            error_msgs = [i["message"] for i in issues if i["severity"] == "error"]
            if error_msgs:
                print(f"[orchestrator] Validation failed, retrying generation with feedback")
                context["validation_feedback"] = "\n".join(error_msgs)
                context = self.generate.run(context)
                context.pop("validation_feedback", None)
                context = self.validate.run(context)

        # Stage 6: Optimize
        context = self.optimize.run(context)

        # Format output
        return self._format_output(context)

    def run_stream(self, description: str, history: list[dict] = None, media_file: dict = None, feedback_data: dict = None) -> Generator[dict, None, None]:
        """Run pipeline with streaming progress events for SSE.

        Args:
            feedback_data: Optional user corrections from the feedback loop.
                Keys: confirmed_logsource, removed_indicators, added_indicators, notes
        """
        # Step 0: Intent classification
        yield {"event": "stage", "data": {"stage": "classification", "status": "running", "detail": "Classifying intent..."}}
        intent_result = self.classify_intent(description, history)
        intent = intent_result.get("intent", "generate_rule")
        yield {"event": "stage", "data": {"stage": "classification", "status": "complete", "detail": f"Intent: {intent}"}}

        if intent in ("chat", "question"):
            response_text = self.handle_conversational(description, history)
            yield {
                "event": "result",
                "data": {
                    "rule": response_text,
                    "context": {"sigma": [], "mitre": [], "sysmon": []},
                    "pipeline_metadata": None,
                },
            }
            return

        context = {
            "original_query": description,
            "history": history or [],
            "media_file": media_file,
        }

        # Stage 1: Preprocessing
        yield {"event": "stage", "data": {"stage": "preprocessing", "status": "running", "detail": "Parsing input and fetching URLs..."}}
        context = self.preprocess.run(context)
        pp = context["preprocessed"]
        yield {"event": "stage", "data": {"stage": "preprocessing", "status": "complete", "detail": f"{len(pp['segments'])} segments, {len(pp['url_content'])} URLs"}}

        # Stage 1b: Web Search Enrichment
        yield {"event": "stage", "data": {"stage": "web_enrichment", "status": "running", "detail": "Searching for additional threat intelligence..."}}
        context = self.web_enrich.run(context)
        enrich = context.get("enrichment", {})
        n_sources = len(enrich.get("sources", []))
        n_queries = len(enrich.get("search_queries", []))
        yield {"event": "stage", "data": {"stage": "web_enrichment", "status": "complete", "detail": f"{n_sources} sources from {n_queries} queries"}}

        # Stage 1c: PoC Code Analysis
        yield {"event": "stage", "data": {"stage": "poc_analysis", "status": "running", "detail": "Scanning for code snippets and PoC artifacts..."}}
        context = self.poc_analysis.run(context)
        poc = context.get("poc_analysis", {})
        n_snippets = poc.get("snippets_found", 0)
        n_behaviors = len(poc.get("behavioral_indicators", []))
        if n_snippets > 0:
            yield {"event": "stage", "data": {"stage": "poc_analysis", "status": "complete", "detail": f"{n_snippets} snippets, {n_behaviors} behavioral indicators"}}
        else:
            yield {"event": "stage", "data": {"stage": "poc_analysis", "status": "complete", "detail": "No code snippets found"}}

        # Stage 2: Entity Extraction
        yield {"event": "stage", "data": {"stage": "extraction", "status": "running", "detail": "Identifying threat indicators..."}}
        context = self.extract.run(context)
        ext = context["extraction"]
        yield {"event": "stage", "data": {"stage": "extraction", "status": "complete", "detail": f"Found {len(ext['indicators'])} indicators"}}

        # Stage 3: TTP Mapping
        yield {"event": "stage", "data": {"stage": "ttp_mapping", "status": "running", "detail": "Mapping to MITRE ATT&CK..."}}
        context = self.ttp_map.run(context)
        ttps = context["ttp_mapping"]
        yield {"event": "stage", "data": {"stage": "ttp_mapping", "status": "complete", "detail": f"Mapped {len(ttps['mappings'])} techniques"}}

        # Stage 3b: Log Source Suggestion
        yield {"event": "stage", "data": {"stage": "logsource", "status": "running", "detail": "Analyzing optimal log sources..."}}
        context = self.logsource.run(context)
        ls = context.get("logsource_suggestion", {})
        primary = ls.get("primary_source", "unknown")
        yield {"event": "stage", "data": {"stage": "logsource", "status": "complete", "detail": f"Primary: {primary}"}}

        # Stage 3c: User Feedback (send preview for confirmation)
        yield {"event": "feedback_request", "data": {
            "stage": "feedback",
            "indicators": ext.get("indicators", []),
            "ttp_mappings": ttps.get("mappings", []),
            "logsource_suggestions": ls.get("suggestions", []),
            "primary_logsource": ls.get("primary_source", ""),
            "attack_summary": ext.get("attack_summary", ""),
        }}

        # Check for user feedback from the feedback_data parameter
        if feedback_data:
            context = self._apply_user_feedback(context, feedback_data)
            yield {"event": "stage", "data": {"stage": "feedback", "status": "complete", "detail": "User feedback applied"}}
        else:
            yield {"event": "stage", "data": {"stage": "feedback", "status": "complete", "detail": "No corrections needed"}}

        # Stage 4: Rule Generation
        yield {"event": "stage", "data": {"stage": "generation", "status": "running", "detail": "Generating Sigma rules..."}}
        context = self.generate.run(context)
        gen = context["generation"]
        yield {"event": "stage", "data": {"stage": "generation", "status": "complete", "detail": f"Generated {len(gen['rules'])} rule(s)"}}

        # Stage 5: Validation
        yield {"event": "stage", "data": {"stage": "validation", "status": "running", "detail": "Validating rule syntax and logic..."}}
        context = self.validate.run(context)

        if not context["validation"]["is_valid"]:
            issues = context["validation"]["issues"]
            error_msgs = [i["message"] for i in issues if i["severity"] == "error"]
            if error_msgs:
                yield {"event": "stage", "data": {"stage": "validation", "status": "running", "detail": "Issues found, regenerating..."}}
                context["validation_feedback"] = "\n".join(error_msgs)
                context = self.generate.run(context)
                context.pop("validation_feedback", None)
                context = self.validate.run(context)

        val = context["validation"]
        yield {"event": "stage", "data": {"stage": "validation", "status": "complete", "detail": f"Valid: {val['is_valid']}"}}

        # Stage 6: Optimization
        yield {"event": "stage", "data": {"stage": "optimization", "status": "running", "detail": "Optimizing rules and enriching with IoCs..."}}
        context = self.optimize.run(context)
        opt = context["optimization"]
        yield {"event": "stage", "data": {"stage": "optimization", "status": "complete", "detail": opt.get("summary", "Done")}}

        # Final result
        yield {"event": "result", "data": self._format_output(context)}

    def _apply_user_feedback(self, context: dict, feedback: dict) -> dict:
        """Apply user corrections from the feedback loop to the pipeline context."""
        # Apply log source override
        confirmed_logsource = feedback.get("confirmed_logsource")
        if confirmed_logsource:
            ls = context.get("logsource_suggestion", {})
            ls["primary_source"] = confirmed_logsource
            ls["user_confirmed"] = True
            context["logsource_suggestion"] = ls
            print(f"[orchestrator] User confirmed logsource: {confirmed_logsource}")

        # Remove indicators the user flagged as incorrect
        removed = feedback.get("removed_indicators", [])
        if removed:
            extraction = context.get("extraction", {})
            indicators = extraction.get("indicators", [])
            extraction["indicators"] = [
                ind for ind in indicators
                if ind.get("value") not in removed
            ]
            context["extraction"] = extraction
            print(f"[orchestrator] User removed {len(removed)} indicators: {removed}")

        # Add indicators the user wants included
        added = feedback.get("added_indicators", [])
        if added:
            extraction = context.get("extraction", {})
            indicators = extraction.get("indicators", [])
            for item in added:
                indicators.append({
                    "value": item.get("value", ""),
                    "type": item.get("type", "other"),
                    "context": "Added by user",
                    "confidence": "high",
                })
            extraction["indicators"] = indicators
            context["extraction"] = extraction
            print(f"[orchestrator] User added {len(added)} indicators")

        # Append user notes to context for generation
        notes = feedback.get("notes", "")
        if notes:
            context["user_feedback_notes"] = notes
            print(f"[orchestrator] User notes: {notes}")

        return context

    def _format_output(self, context: dict) -> dict:
        """Format pipeline context into the response structure."""
        optimization = context.get("optimization", {})
        optimized_rules = optimization.get("rules", [])

        # Build the markdown + YAML response text
        parts = []
        for i, rule in enumerate(optimized_rules):
            yaml_content = rule.get("yaml_content", "")
            changes = rule.get("changes_made", [])

            # Find the matching generation explanation
            gen_rules = context.get("generation", {}).get("rules", [])
            explanation = ""
            if i < len(gen_rules):
                explanation = gen_rules[i].get("explanation", "")

            if explanation:
                parts.append(explanation)
            if yaml_content:
                parts.append(f"```yaml\n{yaml_content}\n```")
            if changes:
                parts.append("**Optimizations applied:**\n" + "\n".join(f"- {c}" for c in changes))

        notes = context.get("generation", {}).get("notes", "")
        if notes:
            parts.append(f"\n{notes}")

        response_text = "\n\n".join(parts) if parts else "I was unable to generate a rule. Please provide more details about the attack technique."

        # Build pipeline metadata for enhanced context panel
        extraction = context.get("extraction", {})
        ttp_mapping = context.get("ttp_mapping", {})
        validation = context.get("validation", {})
        enrichment = context.get("enrichment", {})
        poc_analysis = context.get("poc_analysis", {})
        logsource_suggestion = context.get("logsource_suggestion", {})

        pipeline_metadata = {
            "indicators": extraction.get("indicators", []),
            "attack_summary": extraction.get("attack_summary", ""),
            "ttp_mappings": ttp_mapping.get("mappings", []),
            "validation_issues": validation.get("issues", []),
            "optimization_changes": optimization.get("all_changes", []),
            "suggested_log_sources": extraction.get("suggested_log_sources", []),
            "enrichment_sources": enrichment.get("sources", []),
            "enrichment_queries": enrichment.get("search_queries", []),
            "poc_snippets_found": poc_analysis.get("snippets_found", 0),
            "poc_behavioral_indicators": poc_analysis.get("behavioral_indicators", []),
            "poc_attack_flow": poc_analysis.get("attack_flow", ""),
            "logsource_suggestions": logsource_suggestion.get("suggestions", []),
            "logsource_primary": logsource_suggestion.get("primary_source", ""),
        }

        # Build context for sidebar (backward compatible)
        return {
            "rule": response_text,
            "context": {
                "sigma": context.get("rag_sigma", []),
                "mitre": context.get("rag_mitre", []),
                "sysmon": context.get("rag_sysmon", []),
            },
            "pipeline_metadata": pipeline_metadata,
        }
