"""
LLM-based Sigma rule translator.
Inherits PipelineStage to reuse llm_call() and parse_json().
"""

from __future__ import annotations
from backend.pipeline.base_stage import PipelineStage
from backend.translation.prompts import SIGMA_TO_LEQL
from backend.translation.field_mappings import SIGMA_TO_LEQL_FIELDS, SIGMA_TO_LEQL_LOGSOURCE


class LLMTranslator(PipelineStage):
    name = "translation"
    description = "Translating Sigma rule to query language"

    # run() is not used directly for translation — use translate() instead
    def run(self, context: dict) -> dict:
        return context

    def translate(self, sigma_yaml: str, target: str = "leql") -> dict:
        """
        Translate a Sigma YAML rule to the target query language using LLM.

        Returns a dict with keys:
            query, log_set, explanation, warnings, confidence
        """
        if target.lower() != "leql":
            raise ValueError(f"Target '{target}' is not yet supported. Only 'leql' is available.")

        # Attempt pySigma library translation as an optional hint
        library_hint = self._try_library_translation(sigma_yaml)

        # Render mapping tables as markdown for the prompt
        field_map_table = self._render_field_map()
        logsource_map_table = self._render_logsource_map()

        # Build the hint section (empty string if pySigma failed)
        if library_hint:
            hint_section = (
                "## Library Translation Hint (may be incomplete or wrong — use as reference only)\n"
                f"```\n{library_hint}\n```\n"
            )
        else:
            hint_section = ""

        prompt = SIGMA_TO_LEQL.format(
            field_map_table=field_map_table,
            logsource_map_table=logsource_map_table,
            library_hint=hint_section,
            sigma_rule=sigma_yaml,
        )

        try:
            # economy=True → Spark/Ollama (qwen-coder is trained for syntax translation)
            response_text = self.llm_call(prompt, temperature=0.1, json_mode=True, economy=True)
            result = self.parse_json(response_text)
        except Exception as e:
            print(f"[{self.name}] LLM translation failed: {e}")
            raise RuntimeError(f"LLM translation failed: {e}") from e

        # Ensure all expected keys are present with defaults
        return {
            "query": result.get("query", ""),
            "log_set": result.get("log_set", ""),
            "explanation": result.get("explanation", ""),
            "warnings": result.get("warnings", []),
            "confidence": result.get("confidence", "medium"),
        }

    def _try_library_translation(self, sigma_yaml: str) -> str | None:
        """
        Attempt pySigma library translation. Returns result or None on any failure.
        Failures are expected (e.g., bad tags, unsupported condition syntax) and silently ignored.
        """
        try:
            from sigma.collection import SigmaCollection
            from sigma.backends.insight_idr import InsightIDRBackend
            collection = SigmaCollection.from_yaml(sigma_yaml)
            backend = InsightIDRBackend()
            queries = backend.convert(collection)
            if queries:
                print(f"[{self.name}] pySigma hint available: {queries[0][:80]}...")
                return queries[0]
        except Exception as e:
            print(f"[{self.name}] pySigma hint failed (expected for imperfect rules): {e}")
        return None

    def _render_field_map(self) -> str:
        """Render SIGMA_TO_LEQL_FIELDS as a markdown table for the prompt."""
        lines = ["| Sigma Field | LEQL Field |", "|---|---|"]
        for sigma_field, leql_field in SIGMA_TO_LEQL_FIELDS.items():
            lines.append(f"| `{sigma_field}` | `{leql_field}` |")
        return "\n".join(lines)

    def _render_logsource_map(self) -> str:
        """Render SIGMA_TO_LEQL_LOGSOURCE as a markdown table for the prompt."""
        lines = ["| Category | Product | Service | LEQL Log Set |", "|---|---|---|---|"]
        for key, log_set in SIGMA_TO_LEQL_LOGSOURCE.items():
            category = key[0] or "*"
            product = key[1] or "*"
            service = key[2] if len(key) > 2 else "*"
            lines.append(f"| `{category}` | `{product}` | `{service}` | `{log_set}` |")
        return "\n".join(lines)
