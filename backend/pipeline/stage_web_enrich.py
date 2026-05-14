"""
Stage 2: Web Search Enrichment - search for additional CTI context.

Uses Gemini's built-in Google Search grounding (when available) to find
real-time threat intelligence. Falls back gracefully for non-Gemini backends.

This stage does NOT count as an extra LLM call for the pipeline's primary/fast
model since it uses the fast model with search tool - a single call that
searches AND summarizes.
"""

from __future__ import annotations
from backend.pipeline.base_stage import PipelineStage


class WebEnrichStage(PipelineStage):
    name = "web_enrichment"
    description = "Searching for additional threat intelligence"

    def run(self, context: dict) -> dict:
        preprocessed = context["preprocessed"]
        combined_text = preprocessed["combined_text"]

        # Build a focused search query from the user's input
        search_query = self._build_search_query(preprocessed)

        if not search_query:
            context["enrichment"] = {
                "search_queries": [],
                "sources": [],
                "additional_context": "",
            }
            print(f"[{self.name}] No search query could be built, skipping")
            return context

        # Use the LLM client's web search (Gemini Google Search grounding)
        print(f"[{self.name}] Searching: {search_query[:100]}...")
        result = self.client.web_search(search_query)

        enriched_text = result.get("text", "")
        sources = result.get("sources", [])

        # Append enriched content to combined_text for downstream stages
        if enriched_text:
            enrichment_block = f"\n\n--- Web Search Enrichment ---\n{enriched_text[:5000]}"
            preprocessed["combined_text"] += enrichment_block
            preprocessed["segments"].append(enrichment_block[:1000])

        context["enrichment"] = {
            "search_queries": [search_query],
            "sources": sources,
            "additional_context": enriched_text[:3000],
        }

        print(f"[{self.name}] Enriched with {len(sources)} sources, "
              f"{len(enriched_text)} chars of context")
        return context

    def _build_search_query(self, preprocessed: dict) -> str:
        """Build a search query from the user's input without an LLM call.

        Only uses the user's original query and URL titles (not the full page
        content) to avoid picking up irrelevant CVE IDs from the article body.
        """
        import re

        original = preprocessed.get("original_query", "")
        parts = []

        # Extract CVE IDs from the USER'S query only (not from fetched pages)
        cves = list(set(re.findall(r'CVE-\d{4}-\d{4,7}', original, re.IGNORECASE)))
        parts.extend(cves[:3])

        # Extract product/tool name from URL titles
        for uc in preprocessed.get("url_content", []):
            title = uc.get("title", "")
            if title and title != uc.get("url", ""):
                # Strip site names like "| AttackerKB", "- Rapid7"
                clean_title = re.split(r'\s*[|\-–]\s*(?:AttackerKB|Rapid7|NVD|GitHub)', title)[0].strip()
                if clean_title and clean_title not in " ".join(parts):
                    parts.append(clean_title[:80])

        # If no CVE or title found, use the user's description
        if not parts:
            clean_query = re.sub(r'http\S+', '', original).strip()
            # Remove common filler words
            clean_query = re.sub(r'(?i)^(help me |please |create |make )*(a )?(sigma )?(rule )?(for )?(this:?\s*)?', '', clean_query).strip()
            if len(clean_query) > 10:
                parts.append(clean_query[:150])

        if not parts:
            return ""

        query = " ".join(parts) + " exploit detection indicators of compromise"
        return query
