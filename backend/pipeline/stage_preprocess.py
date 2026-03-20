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
                    "User-Agent": "Mozilla/5.0 SigmaAssistant/1.0"
                })
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.content, "html.parser")
                    # Remove nav, footer, sidebar, ads
                    for tag in soup.find_all(["nav", "footer", "aside", "script", "style"]):
                        tag.decompose()
                    # Extract main text from paragraphs and headers
                    text_parts = []
                    for elem in soup.find_all(["h1", "h2", "h3", "h4", "p", "pre", "code", "li"]):
                        text = elem.get_text(strip=True)
                        if text:
                            text_parts.append(text)
                    page_text = "\n".join(text_parts)[:3000]
                    title = soup.title.string if soup.title else url
                    url_content.append({
                        "url": url,
                        "text": page_text,
                        "title": str(title).strip(),
                    })
                    print(f"[{self.name}] Fetched URL: {url} ({len(page_text)} chars)")
            except Exception as e:
                print(f"[{self.name}] Failed to fetch {url}: {e}")

        # 2. Text segmentation - split into logical paragraphs
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
        print(f"[{self.name}] Preprocessed: {len(segments)} segments, {len(url_content)} URLs, image={'yes' if image_transcription else 'no'}")
        return context

    def _transcribe_image(self, media_file: dict, context_text: str) -> str | None:
        """Use Gemini multimodal to transcribe technical content from image."""
        try:
            from google.genai import types

            with open(media_file["path"], "rb") as f:
                file_data = f.read()

            part = types.Part.from_bytes(data=file_data, mime_type=media_file["mime"])
            prompt = prompts.IMAGE_TRANSCRIPTION.format(context=context_text[:500])

            response = self.client.models.generate_content(
                model=self.model_name,
                contents=[prompt, part],
                config=types.GenerateContentConfig(
                    temperature=0.0,
                    response_mime_type="application/json",
                ),
            )

            result = self.parse_json(response.text)
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
