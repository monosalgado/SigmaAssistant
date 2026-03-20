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
from backend.pipeline.stage_extract import ExtractStage
from backend.pipeline.stage_ttp_map import TTPMapStage
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
        self.extract = ExtractStage(client, model_name)
        self.ttp_map = TTPMapStage(client, model_name, vector_store)
        self.generate = GenerateStage(client, model_name, vector_store)
        self.validate = ValidateStage(client, model_name)
        self.optimize = OptimizeStage(client, model_name)

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

        # Stage 2: Extract
        context = self.extract.run(context)

        # Stage 3: TTP Map
        context = self.ttp_map.run(context)

        # Stage 4: Generate
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

    def run_stream(self, description: str, history: list[dict] = None, media_file: dict = None) -> Generator[dict, None, None]:
        """Run pipeline with streaming progress events for SSE."""
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

        # Stage 1
        yield {"event": "stage", "data": {"stage": "preprocessing", "status": "running", "detail": "Parsing input and fetching URLs..."}}
        context = self.preprocess.run(context)
        pp = context["preprocessed"]
        yield {"event": "stage", "data": {"stage": "preprocessing", "status": "complete", "detail": f"{len(pp['segments'])} segments, {len(pp['url_content'])} URLs"}}

        # Stage 2
        yield {"event": "stage", "data": {"stage": "extraction", "status": "running", "detail": "Identifying threat indicators..."}}
        context = self.extract.run(context)
        ext = context["extraction"]
        yield {"event": "stage", "data": {"stage": "extraction", "status": "complete", "detail": f"Found {len(ext['indicators'])} indicators"}}

        # Stage 3
        yield {"event": "stage", "data": {"stage": "ttp_mapping", "status": "running", "detail": "Mapping to MITRE ATT&CK..."}}
        context = self.ttp_map.run(context)
        ttps = context["ttp_mapping"]
        yield {"event": "stage", "data": {"stage": "ttp_mapping", "status": "complete", "detail": f"Mapped {len(ttps['mappings'])} techniques"}}

        # Stage 4
        yield {"event": "stage", "data": {"stage": "generation", "status": "running", "detail": "Generating Sigma rules..."}}
        context = self.generate.run(context)
        gen = context["generation"]
        yield {"event": "stage", "data": {"stage": "generation", "status": "complete", "detail": f"Generated {len(gen['rules'])} rule(s)"}}

        # Stage 5
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

        # Stage 6
        yield {"event": "stage", "data": {"stage": "optimization", "status": "running", "detail": "Optimizing rules and enriching with IoCs..."}}
        context = self.optimize.run(context)
        opt = context["optimization"]
        yield {"event": "stage", "data": {"stage": "optimization", "status": "complete", "detail": opt.get("summary", "Done")}}

        # Final result
        yield {"event": "result", "data": self._format_output(context)}

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

        pipeline_metadata = {
            "indicators": extraction.get("indicators", []),
            "attack_summary": extraction.get("attack_summary", ""),
            "ttp_mappings": ttp_mapping.get("mappings", []),
            "validation_issues": validation.get("issues", []),
            "optimization_changes": optimization.get("all_changes", []),
            "suggested_log_sources": extraction.get("suggested_log_sources", []),
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
