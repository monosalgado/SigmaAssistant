"""
Pipeline Orchestrator - Runs stages in sequence, handles intent classification,
validation retries, and formats output for the frontend.

Optimized for Gemini free tier:
  - 5-6 total LLM calls (down from 9-10)
  - Dual-model: primary (gemini-2.5-flash) for critical stages,
    fast (gemini-2.0-flash) for lightweight stages
  - 2 calls to primary model, 3-4 calls to fast model
"""

from __future__ import annotations
import json
import datetime
from typing import Generator

from backend.pipeline.base_stage import PipelineStage
from backend.pipeline.stage_preprocess import PreprocessStage
from backend.pipeline.stage_web_enrich import WebEnrichStage
from backend.pipeline.stage_poc_analysis import PoCAnalysisStage
from backend.pipeline.stage_attack_vector import AttackVectorStage
from backend.pipeline.stage_analysis import AnalysisStage
from backend.pipeline.stage_generate import GenerateStage
from backend.pipeline.stage_review import ReviewStage
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
        self.attack_vector = AttackVectorStage(client, model_name)
        self.analysis = AnalysisStage(client, model_name, vector_store)
        self.generate = GenerateStage(client, model_name, vector_store)
        self.review = ReviewStage(client, model_name, vector_store)

        # Track whether user feedback is pending (for feedback loop)
        self._pending_feedback = None

    def classify_intent(self, message: str, history: list[dict] = None) -> dict:
        """Classify user intent to decide whether to run the full pipeline.
        Uses FAST model - simple classification task.
        """
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
            response_text = self.client.generate(
                prompt, temperature=0.0, json_mode=True, economy=True
            )
            result = json.loads(response_text)
            return result
        except Exception as e:
            print(f"[orchestrator] Intent classification failed: {e}")
            # Default to generate_rule to avoid blocking
            return {"intent": "generate_rule", "reasoning": "Classification failed, defaulting to rule generation"}

    def handle_conversational(self, message: str, history: list[dict] = None) -> str:
        """Handle chat/question intents with a simple conversational response.
        Uses FAST model - lightweight conversational task.
        """
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
            return self.client.generate(
                prompt, temperature=0.7, json_mode=False, economy=True
            )
        except Exception as e:
            return f"I apologize, I encountered an error: {e}"

    def run_sync(self, description: str, history: list[dict] = None, media_file: dict = None) -> dict:
        """Run the full pipeline synchronously. Returns same format as old analyze_attack."""
        # Step 0: Intent classification (FAST)
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

        # Stage 1: Preprocess (no LLM unless image)
        context = self.preprocess.run(context)

        # Stage 2: Web Search Enrichment (FAST)
        context = self.web_enrich.run(context)

        # Stage 3: PoC Code Analysis (FAST, only if code found)
        context = self.poc_analysis.run(context)

        # Stage 3b: Attack Vector Extraction (PRIMARY) - anchors downstream stages
        context = self.attack_vector.run(context)

        # Stage 4: Combined Analysis - extraction + TTP + logsource (PRIMARY)
        context = self.analysis.run(context)

        # Stage 5: Rule Generation (PRIMARY)
        context = self.generate.run(context)

        # Stage 6: Combined Review - validation + optimization (FAST)
        context = self.review.run(context)

        # Retry generation once if review found errors.
        # Sets `generation_retried` so the coverage-retry below can't fire
        # too — total regenerations per request are capped at 1.
        if not context["validation"]["is_valid"] and not context.get("generation_retried"):
            issues = context["validation"]["issues"]
            error_msgs = [i["message"] for i in issues if i["severity"] == "error"]
            if error_msgs:
                print(f"[orchestrator] Review found errors, retrying generation")
                context["validation_feedback"] = "\n".join(error_msgs)
                context["generation_retried"] = True
                context = self.generate.run(context)
                context.pop("validation_feedback", None)
                context = self.review.run(context)

        # Coverage-gap check (deterministic, no LLM call)
        self._run_coverage_check(context)

        # Coverage-directed regeneration: only runs if we haven't already
        # regenerated for validation errors. Bounded by `generation_retried`
        # to cap total regenerations at 1 per request (quota-safe).
        if (
            not context.get("generation_retried")
            and self._should_regenerate_for_coverage(context)
        ):
            print("[orchestrator] Coverage gaps detected, regenerating rules with feedback")
            context["coverage_feedback_for_retry"] = context.get("coverage_check", {})
            context["generation_retried"] = True
            context = self.generate.run(context)
            context.pop("coverage_feedback_for_retry", None)
            context = self.review.run(context)
            self._run_coverage_check(context)

        # Format output
        return self._format_output(context)

    def run_stream(self, description: str, history: list[dict] = None, media_file: dict = None, feedback_data: dict = None) -> Generator[dict, None, None]:
        """Run pipeline with streaming progress events for SSE.

        Args:
            feedback_data: Optional user corrections from the feedback loop.
                Keys: confirmed_logsource, removed_indicators, added_indicators, notes
        """
        # Step 0: Intent classification (FAST)
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

        # Stage 1: Preprocessing (no LLM unless image)
        yield {"event": "stage", "data": {"stage": "preprocessing", "status": "running", "detail": "Parsing input and fetching URLs..."}}
        context = self.preprocess.run(context)
        pp = context["preprocessed"]
        yield {"event": "stage", "data": {"stage": "preprocessing", "status": "complete", "detail": f"{len(pp['segments'])} segments, {len(pp['url_content'])} URLs"}}

        # Stage 2: Web Search Enrichment (FAST)
        yield {"event": "stage", "data": {"stage": "web_enrichment", "status": "running", "detail": "Searching for additional threat intelligence..."}}
        context = self.web_enrich.run(context)
        enrich = context.get("enrichment", {})
        n_sources = len(enrich.get("sources", []))
        n_queries = len(enrich.get("search_queries", []))
        yield {"event": "stage", "data": {"stage": "web_enrichment", "status": "complete", "detail": f"{n_sources} sources from {n_queries} queries"}}

        # Stage 3: PoC Code Analysis (FAST, only if code found)
        yield {"event": "stage", "data": {"stage": "poc_analysis", "status": "running", "detail": "Scanning for code snippets and PoC artifacts..."}}
        context = self.poc_analysis.run(context)
        poc = context.get("poc_analysis", {})
        n_snippets = poc.get("snippets_found", 0)
        n_behaviors = len(poc.get("behavioral_indicators", []))
        if n_snippets > 0:
            yield {"event": "stage", "data": {"stage": "poc_analysis", "status": "complete", "detail": f"{n_snippets} snippets, {n_behaviors} behavioral indicators"}}
        else:
            yield {"event": "stage", "data": {"stage": "poc_analysis", "status": "complete", "detail": "No code snippets found"}}

        # Stage 3b: Attack Vector Extraction (PRIMARY model) - anchors the rest of the pipeline
        yield {"event": "stage", "data": {"stage": "attack_vector", "status": "running", "detail": "Identifying the primary attack vector..."}}
        context = self.attack_vector.run(context)
        av = context.get("attack_vector", {})
        vuln_class = av.get("vuln_class", "unknown")
        proto = av.get("protocol", "unknown")
        n_sigs = len(av.get("payload_signatures", []))
        n_incidental = len(av.get("incidental_artifacts", []))
        conf = av.get("confidence", 0.0)
        if av.get("initial_access_vector"):
            detail = (
                f"{vuln_class} via {proto} · "
                f"{n_sigs} payload signatures · "
                f"{n_incidental} incidental strings blacklisted · "
                f"confidence {conf:.0%}"
            )
        else:
            detail = "No clear attack vector identified"
        yield {"event": "stage", "data": {"stage": "attack_vector", "status": "complete", "detail": detail}}

        # Stage 4: Combined Analysis (PRIMARY model)
        yield {"event": "stage", "data": {"stage": "analysis", "status": "running", "detail": "Extracting indicators, mapping TTPs, analyzing log sources..."}}
        context = self.analysis.run(context)
        ext = context["extraction"]
        ttps = context["ttp_mapping"]
        ls = context.get("logsource_suggestion", {})
        yield {"event": "stage", "data": {
            "stage": "analysis", "status": "complete",
            "detail": f"{len(ext['indicators'])} indicators, {len(ttps['mappings'])} TTPs, logsource: {ls.get('primary_source', 'unknown')}"
        }}

        # Stage 4b: User Feedback (send preview for confirmation)
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

        # Stage 5: Rule Generation (PRIMARY model)
        yield {"event": "stage", "data": {"stage": "generation", "status": "running", "detail": "Generating Sigma rules..."}}
        context = self.generate.run(context)
        gen = context["generation"]
        yield {"event": "stage", "data": {"stage": "generation", "status": "complete", "detail": f"Generated {len(gen['rules'])} rule(s)"}}

        # Stage 6: Combined Review (FAST model)
        yield {"event": "stage", "data": {"stage": "review", "status": "running", "detail": "Validating and optimizing rules..."}}
        context = self.review.run(context)

        if not context["validation"]["is_valid"] and not context.get("generation_retried"):
            issues = context["validation"]["issues"]
            error_msgs = [i["message"] for i in issues if i["severity"] == "error"]
            if error_msgs:
                yield {"event": "stage", "data": {"stage": "review", "status": "running", "detail": "Issues found, regenerating..."}}
                context["validation_feedback"] = "\n".join(error_msgs)
                context["generation_retried"] = True
                context = self.generate.run(context)
                context.pop("validation_feedback", None)
                context = self.review.run(context)

        val = context["validation"]
        opt = context["optimization"]
        yield {"event": "stage", "data": {
            "stage": "review", "status": "complete",
            "detail": f"Valid: {val['is_valid']}, {len(opt.get('all_changes', []))} optimizations"
        }}

        # Coverage-gap check (deterministic, no LLM call)
        self._run_coverage_check(context)
        coverage = context.get("coverage_check", {})
        n_warnings = len(coverage.get("warnings", []))
        yield {"event": "stage", "data": {
            "stage": "coverage_check", "status": "complete",
            "detail": (
                "No gaps detected" if n_warnings == 0
                else f"{n_warnings} coverage gap(s) — regenerating with feedback..."
                if self._should_regenerate_for_coverage(context)
                else f"{n_warnings} coverage gap(s) — see notes below"
            ),
        }}

        # Coverage-directed regeneration pass.
        # Skipped if a validation-driven regeneration already ran — at most
        # 1 regeneration per request total (quota-safe).
        if (
            not context.get("generation_retried")
            and self._should_regenerate_for_coverage(context)
        ):
            yield {"event": "stage", "data": {
                "stage": "generation", "status": "running",
                "detail": "Regenerating to close coverage gaps...",
            }}
            context["coverage_feedback_for_retry"] = context.get("coverage_check", {})
            context["generation_retried"] = True
            context = self.generate.run(context)
            context.pop("coverage_feedback_for_retry", None)
            context = self.review.run(context)
            self._run_coverage_check(context)
            coverage2 = context.get("coverage_check", {})
            n_w2 = len(coverage2.get("warnings", []))
            yield {"event": "stage", "data": {
                "stage": "coverage_check", "status": "complete",
                "detail": (
                    "Gaps resolved" if n_w2 == 0
                    else f"{n_w2} gap(s) remain after retry — see notes below"
                ),
            }}

        # Final result
        yield {"event": "result", "data": self._format_output(context)}

    def _should_regenerate_for_coverage(self, context: dict) -> bool:
        """Decide whether to run a single coverage-directed regeneration pass.

        Trigger conditions (any one is enough):
          - No rule detects the primary attack vector (initial_access_covered = False).
          - >= 50% of payload signatures went unreferenced.
          - Any blacklist violation (researcher/patch-workflow artifact used as detection).

        Guards:
          - Only retry once per request (`coverage_retried` sentinel in context).
          - Skip if the attack-vector extractor itself had low confidence (<0.4) —
            in that case the "gaps" are likely analyst noise, not a real miss.
          - Skip if there are no rules to improve (nothing to regenerate from).
        """
        if context.get("coverage_retried"):
            return False
        av = context.get("attack_vector") or {}
        if float(av.get("confidence") or 0.0) < 0.4:
            return False
        gen = (context.get("generation") or {}).get("rules") or []
        if not gen:
            return False
        coverage = context.get("coverage_check") or {}
        if not coverage.get("warnings"):
            return False

        should_retry = False
        if not coverage.get("initial_access_covered", True):
            should_retry = True
        sigs = av.get("payload_signatures") or []
        missed = coverage.get("payload_signatures_missed") or []
        if sigs and len(missed) / max(len(sigs), 1) >= 0.5:
            should_retry = True
        if coverage.get("blacklist_violations"):
            should_retry = True

        if should_retry:
            context["coverage_retried"] = True
        return should_retry

    def _run_coverage_check(self, context: dict) -> None:
        """Run the deterministic coverage-gap check and stash results in context.
        This compares the generated rules against the primary attack vector to
        detect when the pipeline has drifted into post-exploitation-only rules
        or picked up researcher-workflow artifacts as detection criteria."""
        attack_vector = context.get("attack_vector", {})
        # Use the final (post-review) rules if available, else the raw generation
        optimized = context.get("optimization", {}).get("rules", [])
        generated = context.get("generation", {}).get("rules", [])
        rules_to_check = optimized if optimized else generated

        try:
            coverage = AttackVectorStage.coverage_gap_check(attack_vector, rules_to_check)
        except Exception as e:
            print(f"[orchestrator] Coverage check failed: {e}")
            coverage = {
                "initial_access_covered": True,  # don't scare users on errors
                "payload_signatures_covered": [],
                "payload_signatures_missed": [],
                "blacklist_violations": [],
                "warnings": [],
            }
        context["coverage_check"] = coverage
        if coverage.get("warnings"):
            print(f"[orchestrator] Coverage warnings: {coverage['warnings']}")

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

        # Surface coverage warnings (deterministic post-generation check)
        coverage = context.get("coverage_check", {})
        warnings = coverage.get("warnings", []) if coverage else []
        if warnings:
            warning_block = ["\n---", "**⚠️ Coverage gaps detected:**"]
            for w in warnings:
                warning_block.append(f"- {w}")
            warning_block.append(
                "_These are heuristic warnings from the post-generation coverage check. "
                "Review the rules against the primary attack vector and consider refining._"
            )
            parts.append("\n".join(warning_block))

        response_text = "\n\n".join(parts) if parts else "I was unable to generate a rule. Please provide more details about the attack technique."

        # Build pipeline metadata for enhanced context panel
        extraction = context.get("extraction", {})
        ttp_mapping = context.get("ttp_mapping", {})
        validation = context.get("validation", {})
        enrichment = context.get("enrichment", {})
        poc_analysis = context.get("poc_analysis", {})
        logsource_suggestion = context.get("logsource_suggestion", {})
        attack_vector = context.get("attack_vector", {})

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
            "attack_vector": attack_vector,
            "coverage_check": coverage,
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
