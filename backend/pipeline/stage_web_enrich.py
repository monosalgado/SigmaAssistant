"""Stage 2: Web Search Enrichment - search for additional CTI context."""

from __future__ import annotations
import re
import requests
from bs4 import BeautifulSoup
from backend.pipeline.base_stage import PipelineStage
from backend.pipeline import prompts


class WebEnrichStage(PipelineStage):
    name = "web_enrichment"
    description = "Searching for additional threat intelligence"

    def run(self, context: dict) -> dict:
        preprocessed = context["preprocessed"]
        combined_text = preprocessed["combined_text"]

        # 1. Ask LLM to generate search queries
        prompt = prompts.WEB_SEARCH_QUERIES.format(text=combined_text[:3000])

        search_queries = []
        try:
            response_text = self.llm_call(prompt, temperature=0.0, json_mode=True)
            result = self.parse_json(response_text)
            search_queries = result.get("queries", [])[:3]
        except Exception as e:
            print(f"[{self.name}] Query generation failed: {e}")

        if not search_queries:
            context["enrichment"] = {
                "search_queries": [],
                "sources": [],
                "additional_context": "",
            }
            print(f"[{self.name}] No search queries generated, skipping enrichment")
            return context

        # 2. Perform web searches using googlesearch-python
        all_urls = []
        try:
            from googlesearch import search as gsearch
            for query in search_queries:
                try:
                    results = list(gsearch(query, num_results=3, lang="en"))
                    all_urls.extend(results)
                except Exception as e:
                    print(f"[{self.name}] Search failed for '{query}': {e}")
        except ImportError:
            print(f"[{self.name}] googlesearch-python not installed, skipping web search")
            context["enrichment"] = {
                "search_queries": search_queries,
                "sources": [],
                "additional_context": "",
            }
            return context

        # Deduplicate URLs and skip already-fetched URLs
        existing_urls = {uc["url"] for uc in preprocessed.get("url_content", [])}
        seen = set()
        unique_urls = []
        for url in all_urls:
            if url not in seen and url not in existing_urls:
                seen.add(url)
                unique_urls.append(url)
        unique_urls = unique_urls[:5]  # Limit to 5 new URLs

        # 3. Fetch and extract content from search results
        sources = []
        additional_text_parts = []

        for url in unique_urls:
            try:
                resp = requests.get(url, timeout=8, headers={
                    "User-Agent": "Mozilla/5.0 SigmaAssistant/1.0"
                })
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.content, "html.parser")
                    # Remove non-content elements
                    for tag in soup.find_all(["nav", "footer", "aside", "script", "style"]):
                        tag.decompose()

                    text_parts = []
                    for elem in soup.find_all(["h1", "h2", "h3", "h4", "p", "pre", "code", "li"]):
                        text = elem.get_text(strip=True)
                        if text:
                            text_parts.append(text)

                    page_text = "\n".join(text_parts)[:2000]
                    title = soup.title.string if soup.title else url
                    snippet = page_text[:200]

                    sources.append({
                        "url": url,
                        "title": str(title).strip(),
                        "snippet": snippet,
                    })
                    additional_text_parts.append(
                        f"--- Enrichment from {url} ---\n{page_text}"
                    )
                    print(f"[{self.name}] Fetched: {url} ({len(page_text)} chars)")
            except Exception as e:
                print(f"[{self.name}] Failed to fetch {url}: {e}")

        # 4. Append enriched content to combined_text for downstream stages
        additional_context = "\n\n".join(additional_text_parts)
        if additional_context:
            preprocessed["combined_text"] += f"\n\n{additional_context}"
            # Also add as segments
            for part in additional_text_parts:
                preprocessed["segments"].append(part[:1000])

        context["enrichment"] = {
            "search_queries": search_queries,
            "sources": sources,
            "additional_context": additional_context[:3000],
        }

        print(f"[{self.name}] Enriched with {len(sources)} sources from {len(search_queries)} queries")
        return context
