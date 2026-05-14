"""Stage 1: Input Preprocessing - URL fetching, text segmentation, image transcription."""

from __future__ import annotations
import re
import requests
from bs4 import BeautifulSoup
from backend.pipeline.base_stage import PipelineStage
from backend.pipeline import prompts


class PreprocessStage(PipelineStage):
    name = "preprocessing"
    description = "Parsing input, fetching URLs, and processing images"

    # Generous limit for technical articles (CVE writeups, blog posts).
    # Downstream consumers (poc_analysis, attack_vector, analysis, review) run on
    # Spark/Ollama — no API cost. The only Gemini-primary consumer is stage_generate.
    # 40k chars x up to 3 URLs = ~120k chars (~30k tokens), trivial vs. 1M context.
    MAX_PAGE_TEXT = 40000

    def run(self, context: dict) -> dict:
        query = context["original_query"]
        media_file = context.get("media_file")

        # 1. Extract and fetch URLs
        urls = re.findall(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            query
        )

        url_content = []
        for url in urls[:3]:  # Limit to 3 URLs
            try:
                resp = requests.get(url, timeout=10, headers={
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                                  "Chrome/120.0.0.0 Safari/537.36"
                })
                if resp.status_code == 200:
                    page_text, title = self._extract_page_content(resp.content, url)
                    url_content.append({
                        "url": url,
                        "text": page_text,
                        "title": title,
                    })
                    print(f"[{self.name}] Fetched URL: {url} ({len(page_text)} chars)")
                else:
                    print(f"[{self.name}] URL returned {resp.status_code}: {url}")
            except Exception as e:
                print(f"[{self.name}] Failed to fetch {url}: {e}")

        # 2. Text segmentation - combine user query with fetched content
        combined_parts = [query]
        for uc in url_content:
            combined_parts.append(f"\n--- Content from {uc['url']} ---\n{uc['text']}")

        combined_text = "\n".join(combined_parts)

        # Split into segments by double newlines or headers
        segments = [s.strip() for s in re.split(r'\n{2,}|(?=^#{1,3}\s)', combined_text) if s.strip()]
        if not segments:
            segments = [combined_text]

        # 3. Image transcription (if media attached)
        image_transcription = None
        if media_file:
            image_transcription = self._transcribe_image(media_file, query)

        if image_transcription:
            combined_text += f"\n\n--- Image Content ---\n{image_transcription}"
            segments.append(f"Image Content: {image_transcription}")

        # Update context
        context["preprocessed"] = {
            "original_query": query,
            "segments": segments,
            "url_content": url_content,
            "image_transcription": image_transcription,
            "combined_text": combined_text,
        }
        print(f"[{self.name}] Preprocessed: {len(segments)} segments, "
              f"{len(url_content)} URLs, "
              f"combined_text={len(combined_text)} chars, "
              f"image={'yes' if image_transcription else 'no'}")
        return context

    def _extract_page_content(self, html_bytes: bytes, url: str) -> tuple:
        """Extract text from HTML, preserving code blocks as markdown fences.

        Returns (page_text, title) where code blocks are placed FIRST in page_text
        so they survive truncation.
        """
        soup = BeautifulSoup(html_bytes, "html.parser")

        title = soup.title.string if soup.title else url
        title = str(title).strip()

        # Remove non-content elements
        for tag in soup.find_all(["nav", "footer", "aside", "script", "style",
                                   "header", "form", "iframe", "noscript"]):
            tag.decompose()

        # First pass: extract code blocks SEPARATELY before converting to text
        code_blocks = []
        for pre_tag in soup.find_all("pre"):
            code_text = pre_tag.get_text()
            if len(code_text.strip()) < 20:
                continue
            lang = self._guess_code_language(code_text)
            code_blocks.append(f"```{lang}\n{code_text.strip()}\n```")
            pre_tag.decompose()  # Remove from soup so it's not double-counted

        # Also grab substantial standalone <code> blocks
        for code_tag in soup.find_all("code"):
            code_text = code_tag.get_text()
            if len(code_text.strip()) > 50 and "\n" in code_text:
                lang = self._guess_code_language(code_text)
                code_blocks.append(f"```{lang}\n{code_text.strip()}\n```")
                code_tag.decompose()

        # Second pass: extract prose text from content elements
        text_parts = []
        for elem in soup.find_all(["h1", "h2", "h3", "h4", "p", "li",
                                     "td", "th", "blockquote", "figcaption"]):
            text = elem.get_text(strip=True)
            if text and len(text) > 5:
                text_parts.append(text)

        prose_text = "\n".join(text_parts)

        # Build final output: code blocks FIRST (so they survive truncation),
        # then prose text
        parts = []
        if code_blocks:
            parts.append("--- Code/Config Snippets ---")
            parts.extend(code_blocks)
            parts.append("--- Article Content ---")
        parts.append(prose_text)

        page_text = "\n\n".join(parts)[:self.MAX_PAGE_TEXT]
        return page_text, title

    def _guess_code_language(self, code: str) -> str:
        """Simple heuristic to guess code language for fence annotation."""
        code_lower = code.lower()
        if "import " in code_lower and ("def " in code_lower or "print(" in code_lower):
            return "python"
        if "function " in code_lower or "const " in code_lower or "=>" in code_lower:
            return "javascript"
        if "$" in code and ("Get-" in code or "Set-" in code or "Invoke-" in code):
            return "powershell"
        if "#!/bin/" in code:
            return "bash"
        if "#include" in code:
            return "c"
        if "using System" in code or "namespace " in code:
            return "csharp"
        if code.strip().startswith(("id:", "info:", "title:")):
            return "yaml"
        if "SELECT " in code.upper() or "INSERT " in code.upper():
            return "sql"
        if "<html" in code_lower or "<!doctype" in code_lower:
            return "html"
        return ""

    def _transcribe_image(self, media_file: dict, context_text: str) -> str | None:
        """Transcribe technical content from an image using the active LLM backend."""
        try:
            part = self.client.make_image_part(media_file["path"], media_file["mime"])
            if part is None:
                print(f"[{self.name}] Image transcription not supported by current LLM backend - skipping")
                return None

            prompt = prompts.IMAGE_TRANSCRIPTION.format(context=context_text[:500])
            response_text = self.llm_call(
                prompt, temperature=0.0, json_mode=True, media_parts=[part]
            )
            result = self.parse_json(response_text)
            if result.get("is_technical"):
                transcription = result.get("transcription", "")
                print(f"[{self.name}] Image transcribed: {len(transcription)} chars")
                return transcription
            else:
                print(f"[{self.name}] Image classified as non-technical, skipping")
                return None
        except Exception as e:
            print(f"[{self.name}] Image transcription failed: {e}")
            return None
