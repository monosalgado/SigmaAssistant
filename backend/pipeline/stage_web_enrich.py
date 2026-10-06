"""
Stage 2: Web Search Enrichment - search for additional CTI context.

With a Gemini client: Google Search grounding, one call that searches and summarizes (the old path, kept).
All-local (Change 45): Ollama's web search returns whole pages; code drops the case's own page (and, in the
evaluation, rule pages), one model call (`WEB_DIGEST`) lists what the kept pages add about this attack, and code keeps
only the strings it finds in their page. The kept items are appended to the text the attack-vector and analysis stages
read, marked as coming from the web. Runs after the PoC stage, so the PoC stage reads only the report's own links.
"""

from __future__ import annotations

import json
import re
from typing import Optional
from urllib.parse import urlparse

from backend.llm_client import OutputLimitReached
from backend.pipeline import prompts
from backend.pipeline.base_stage import PipelineStage

# Detection-rule publishers (host, path prefix): the probe's list (2026-10-06) plus the mirror it found.
RULE_SITES = (("github.com", "/sigmahq/"), ("sigma.nasbench.dev", ""), ("detection.fyi", ""), ("socprime.com", ""),
              ("uncoder.io", ""), ("research.splunk.com", ""), ("github.com", "/splunk/security_content"),
              ("github.com", "/elastic/detection-rules"), ("sigma.controlassurance.com", ""))
MIN_STRING_CHARS = 4
WEB_HEADER = ("--- Web search: what other pages add about this attack (from the web, not from the report; "
              "each string was found in its page) ---")


def _host_path(url: str) -> tuple:
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = (parsed.hostname or "").lower()
    return (host[4:] if host.startswith("www.") else host), parsed.path.lower()


def norm_url(url: str) -> str:
    host, path = _host_path(str(url or "").strip())
    return host + path.rstrip("/")


def _is_rule_page(result: dict) -> bool:
    host, path = _host_path(result.get("url") or "")
    if any((host == h or host.endswith("." + h)) and path.startswith(p) for h, p in RULE_SITES):
        return True
    text = (result.get("content") or "").lower()
    return all(f"{key}:" in text for key in ("logsource", "detection", "condition"))


def classify_result(result: dict, own_urls: list) -> Optional[str]:
    """"own page" (one of the case's input pages), "rule page" (a detection-rule publisher, or Sigma rule text), or
    None."""
    if norm_url(result.get("url")) in {norm_url(u) for u in own_urls}:
        return "own page"
    return "rule page" if _is_rule_page(result) else None


def _squash(text: str) -> str:
    """For checking a string against a page: lower case, whitespace ignored (PDF text splits words and paths), a run
    of backslashes read as one (a YARA or JSON page writes `\\\\.\\x` for `\\.\\x`)."""
    return re.sub(r"\\+", r"\\", "".join(str(text or "").split())).lower()


def _cited_pages(source, pages: list) -> list:
    """The kept pages an item cites: by number (1, "2", "[3]", [1, 2] - the model wrote all of these) or by URL."""
    by_url = {norm_url(p["url"]): p for p in pages}
    refs = source if isinstance(source, list) else re.findall(r"\d+", str(source)) if re.fullmatch(
        r"\s*\[?\s*\d+(\s*,\s*\d+)*\s*\]?\s*", str(source or "")) else [source]
    cited = []
    for ref in refs:
        ref = str(ref).strip()
        page = pages[int(ref) - 1] if ref.isdigit() and 1 <= int(ref) <= len(pages) else by_url.get(norm_url(ref))
        if page is not None and page not in cited:
            cited.append(page)
    return cited


def check_digest(items: list, pages: list) -> tuple:
    """Keep what the pages back up. An item must cite a kept page; each string must appear in one of the pages it
    cites (case-insensitive, whitespace ignored, a backslash run read as one, >= MIN_STRING_CHARS) or it is dropped; an item whose strings all fail
    is dropped; an item with no strings is kept. Returns (kept items, dropped records)."""
    kept, dropped = [], []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        finding, source = str(item.get("finding") or "").strip(), item.get("source")
        strings = [str(s) for s in item.get("strings") or [] if str(s).strip()]
        cited = _cited_pages(source, pages)
        if not cited:
            dropped.append({"finding": finding, "source": source, "strings": strings,
                            "reason": "source is not a kept page"})
            continue
        texts, urls = [_squash(p.get("content")) for p in cited], [p["url"] for p in cited]
        good, bad = [], []
        for s in strings:
            if len(s.strip()) < MIN_STRING_CHARS:
                bad.append((s, "string too short"))
            elif any(_squash(s) in t for t in texts):
                good.append(s)
            else:
                bad.append((s, "string not in the page"))
        if strings and not good:
            dropped.append({"finding": finding, "sources": urls, "strings": strings,
                            "reason": "no string found in the page"})
            continue
        dropped.extend({"finding": finding, "sources": urls, "string": s, "reason": r} for s, r in bad)
        kept.append({"finding": finding, "strings": good, "source": urls[0], "sources": urls})
    return kept, dropped


def complete_items(text: str) -> list:
    """The items an answer cut at the output limit had finished: each complete JSON object of its "items" list, in
    order, until the first one cut off."""
    start = (text or "").find('"items"')
    start = text.find("[", start) if start >= 0 else -1
    if start < 0:
        return []
    decoder, i, items = json.JSONDecoder(), start + 1, []
    while True:
        while i < len(text) and text[i] in " \t\r\n,":
            i += 1
        if i >= len(text) or text[i] != "{":
            return items
        try:
            item, i = decoder.raw_decode(text, i)
        except ValueError:
            return items
        items.append(item)


def digest_block(items: list) -> str:
    lines = [WEB_HEADER]
    for item in items:
        strings = f" Strings: {', '.join('`' + s + '`' for s in item['strings'])}." if item["strings"] else ""
        lines.append(f"- {item['finding']}{strings} (source: {', '.join(item.get('sources') or [item['source']])})")
    return "\n".join(lines)


def web_detail(enrichment: dict) -> str:
    """The progress line the user sees for the web stage."""
    if not enrichment or not enrichment.get("search_queries"):
        return "No web search"
    if enrichment.get("limited"):
        return "Web search limit reached; continuing without web results"
    if "results" not in enrichment:
        return f"{len(enrichment.get('sources', []))} sources from {len(enrichment['search_queries'])} queries"
    parts = [f"{len(enrichment.get('sources', []))} pages read of {len(enrichment['results'])} results",
             f"{len((enrichment.get('digest') or {}).get('kept') or [])} findings kept"]
    if enrichment.get("rule_pages"):
        n = len(enrichment["rule_pages"])
        parts.append(f"{n} published rule{'s' if n != 1 else ''} found")
    if enrichment.get("error"):
        parts.append(f"error: {enrichment['error'][:80]}")
    return "; ".join(parts)


class WebEnrichStage(PipelineStage):
    name = "web_enrichment"
    description = "Searching for additional threat intelligence"
    # Set by the evaluation harness: a found human rule would make the score measure copying.
    exclude_rule_pages = False

    def run(self, context: dict) -> dict:
        preprocessed = context["preprocessed"]

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

        print(f"[{self.name}] Searching: {search_query[:100]}...")
        result = self.client.web_search(search_query)
        if "results" in result:
            return self._digest_pages(context, search_query, result)

        # The old path (Gemini Google Search grounding): a summary to append as it is
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

    def _own_urls(self, preprocessed: dict) -> list:
        urls = re.findall(r"https?://\S+", preprocessed.get("original_query", "") or "")
        return urls + [uc.get("url", "") for uc in preprocessed.get("url_content", []) if uc.get("url")]

    def _digest_pages(self, context: dict, query: str, result: dict) -> dict:
        preprocessed = context["preprocessed"]
        own = self._own_urls(preprocessed)
        records, kept_pages, rule_pages = [], [], []
        for r in result.get("results") or []:
            reason = classify_result(r, own)
            if reason == "rule page":
                rule_pages.append(r.get("url", ""))
                if not self.exclude_rule_pages:
                    reason = None
            records.append({"url": r.get("url", ""), "title": r.get("title", ""),
                            "chars": len(r.get("content") or ""), "reason": reason})
            if reason is None:
                kept_pages.append(r)
        enrichment = {"search_queries": [query], "sources": [{"url": p["url"], "title": p.get("title", "")}
                                                              for p in kept_pages],
                      "results": records, "rule_pages": rule_pages, "error": result.get("error"),
                      "limited": bool(result.get("limited")), "cached": bool(result.get("cached")),
                      "digest": None, "additional_context": ""}
        context["enrichment"] = enrichment
        if not kept_pages:
            print(f"[{self.name}] No page to read ({len(records)} results; error: {result.get('error')})")
            return context

        pages = "\n\n".join(f"[{i}] {p.get('title', '')}\nURL: {p['url']}\n{p.get('content') or ''}"
                            for i, p in enumerate(kept_pages, 1))
        prompt = prompts.WEB_DIGEST.format(report=self.source_text(preprocessed["combined_text"]), pages=pages)
        error, cut = None, False
        try:
            answer = self.parse_json(self.llm_call(prompt, temperature=0.0, json_mode=True, economy=True))
            items = answer.get("items", []) if isinstance(answer, dict) else []
        except Exception as e:  # cut: keep its complete items; unreadable: no digest. The pipeline goes on.
            error, cut = f"{type(e).__name__}: {e}"[:300], isinstance(e, OutputLimitReached)
            items = complete_items(getattr(e, "partial", "")) if cut else []
            print(f"[{self.name}] Digest {'cut' if cut else 'failed'}: {e}; {len(items)} complete items kept to check")
        kept, dropped = check_digest(items, kept_pages)
        enrichment["digest"] = {"error": error, "cut": cut, "proposed": len(items) if isinstance(items, list) else 0,
                                "kept": kept, "dropped": dropped}
        if kept:
            block = digest_block(kept)
            preprocessed["combined_text"] += "\n\n" + block
            preprocessed["segments"].append(block[:1000])
            enrichment["additional_context"] = block
        print(f"[{self.name}] {len(kept_pages)} pages read; digest kept {len(kept)} of "
              f"{enrichment['digest']['proposed']} items, {len(dropped)} dropped")
        return context

    def _build_search_query(self, preprocessed: dict) -> str:
        """Build a search query from the user's input without an LLM call.

        Only uses the user's original query and URL titles (not the full page
        content) to avoid picking up irrelevant CVE IDs from the article body.
        """
        original = preprocessed.get("original_query", "")
        parts = []

        # Extract CVE IDs from the USER'S query only (not from fetched pages); each once (Change 45)
        cves = list(dict.fromkeys(c.upper() for c in re.findall(r'CVE-\d{4}-\d{4,7}', original, re.IGNORECASE)))
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
