"""Stage 1.5: PoC Code Analysis - extract behavioral indicators from code snippets."""

from __future__ import annotations
import re
import requests
from backend.pipeline.base_stage import PipelineStage
from backend.pipeline import prompts

_GITHUB_FILE_RE = r'https?://github\.com/([\w\-]+)/([\w\-]+)/blob/([\w\-]+)/([\w\./\-]+)'
_GIST_RE = r'https?://gist\.github\.com/([\w\-]+)/([\w]+)'
_MAX_GITHUB_FILES = 3
_MAX_GISTS = 2


def github_fetch_targets(text: str) -> tuple[list[dict], list[dict]]:
    """The GitHub files and gists this stage fetches for `text`, in fetch order.

    Shared with the evaluation's snapshot builder, so that what gets stored is
    exactly what the stage will ask for.
    """
    files = [
        {
            "fetch_url": f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}",
            "source_url": f"https://github.com/{owner}/{repo}/blob/{branch}/{path}",
            "path": path,
        }
        for owner, repo, branch, path in re.findall(_GITHUB_FILE_RE, text)[:_MAX_GITHUB_FILES]
    ]
    gists = [
        {
            "fetch_url": f"https://api.github.com/gists/{gist_id}",
            "source_url": f"https://gist.github.com/{user}/{gist_id}",
        }
        for user, gist_id in re.findall(_GIST_RE, text)[:_MAX_GISTS]
    ]
    return files, gists


class PoCAnalysisStage(PipelineStage):
    name = "poc_analysis"
    description = "Analyzing code snippets for behavioral indicators"

    def run(self, context: dict) -> dict:
        preprocessed = context["preprocessed"]
        combined_text = preprocessed["combined_text"]

        # 1. Extract code blocks from the text
        code_snippets = self._extract_code_blocks(combined_text)

        # 2. Check for GitHub URLs and fetch code
        github_snippets = self._fetch_github_code(combined_text)
        code_snippets.extend(github_snippets)

        if not code_snippets:
            context["poc_analysis"] = {
                "snippets_found": 0,
                "behavioral_indicators": [],
                "attack_flow": "",
            }
            print(f"[{self.name}] No code snippets found")
            return context

        # 3. Analyze code snippets with LLM
        snippets_text = ""
        for i, snippet in enumerate(code_snippets[:5]):  # Limit to 5 snippets
            lang = snippet.get("language", "unknown")
            source = snippet.get("source", "inline")
            source_url = snippet.get("source_url", "")
            content = snippet.get("content", "")[:2000]  # Limit per snippet

            header = f"Snippet {i + 1} ({lang}, from {source}"
            if source_url:
                header += f": {source_url}"
            header += ")"

            snippets_text += f"\n### {header}\n```{lang}\n{content}\n```\n"

        prompt = prompts.POC_CODE_ANALYSIS.format(code_snippets=snippets_text)

        try:
            response_text = self.llm_call(prompt, temperature=0.0, json_mode=True, economy=True)
            result = self.parse_json(response_text)
        except Exception as e:
            print(f"[{self.name}] PoC analysis failed: {e}")
            result = {"behavioral_indicators": [], "attack_flow": ""}

        behavioral_indicators = result.get("behavioral_indicators", [])
        attack_flow = result.get("attack_flow", "")

        # 4. Merge behavioral indicators into combined text for downstream extraction
        if attack_flow:
            preprocessed["combined_text"] += f"\n\n--- PoC Code Analysis ---\n{attack_flow}"
            preprocessed["segments"].append(f"PoC Analysis: {attack_flow}")

        context["poc_analysis"] = {
            "snippets_found": len(code_snippets),
            "behavioral_indicators": behavioral_indicators,
            "attack_flow": attack_flow,
        }

        print(f"[{self.name}] Analyzed {len(code_snippets)} snippets, "
              f"found {len(behavioral_indicators)} behavioral indicators")
        return context

    def _extract_code_blocks(self, text: str) -> list[dict]:
        """Extract fenced code blocks from text."""
        snippets = []

        # Match ```language\ncode\n``` blocks
        pattern = r'```(\w*)\n([\s\S]*?)```'
        matches = re.findall(pattern, text)

        for lang, code in matches:
            code = code.strip()
            if len(code) < 20:  # Skip trivially short snippets
                continue
            if not lang:
                lang = self._guess_language(code)
            snippets.append({
                "language": lang or "unknown",
                "source": "inline",
                "source_url": None,
                "content": code,
            })

        # Also look for <code> or <pre> blocks that might have been extracted from HTML
        pre_pattern = r'<pre[^>]*>([\s\S]*?)</pre>'
        pre_matches = re.findall(pre_pattern, text)
        for code in pre_matches:
            code = re.sub(r'<[^>]+>', '', code).strip()  # Strip inner HTML tags
            if len(code) < 20:
                continue
            snippets.append({
                "language": self._guess_language(code),
                "source": "inline",
                "source_url": None,
                "content": code,
            })

        return snippets

    def _fetch_github_code(self, text: str) -> list[dict]:
        """Find GitHub URLs and fetch raw code content."""
        snippets = []
        file_targets, gist_targets = github_fetch_targets(text)

        for target in file_targets:
            path = target["path"]
            try:
                resp = requests.get(target["fetch_url"], timeout=8, headers={
                    "User-Agent": "Mozilla/5.0 SigmaAssistant/1.0"
                })
                if resp.status_code == 200:
                    content = resp.text[:3000]
                    extension = path.rsplit(".", 1)[-1] if "." in path else ""
                    lang = self._extension_to_language(extension)

                    snippets.append({
                        "language": lang,
                        "source": "github",
                        "source_url": target["source_url"],
                        "content": content,
                    })
                    print(f"[{self.name}] Fetched GitHub code: {path}")
            except Exception as e:
                print(f"[{self.name}] Failed to fetch GitHub code {path}: {e}")

        for target in gist_targets:
            try:
                resp = requests.get(target["fetch_url"], timeout=8, headers={
                    "User-Agent": "Mozilla/5.0 SigmaAssistant/1.0"
                })
                if resp.status_code == 200:
                    gist_data = resp.json()
                    for filename, file_info in gist_data.get("files", {}).items():
                        content = file_info.get("content", "")[:3000]
                        lang = file_info.get("language", "unknown") or "unknown"
                        snippets.append({
                            "language": lang.lower(),
                            "source": "github",
                            "source_url": target["source_url"],
                            "content": content,
                        })
                        break  # Only take first file from gist
            except Exception as e:
                print(f"[{self.name}] Failed to fetch gist {target['source_url']}: {e}")

        return snippets

    def _guess_language(self, code: str) -> str:
        """Simple heuristic to guess code language."""
        code_lower = code.lower()
        if "import " in code_lower and ("def " in code_lower or "print(" in code_lower):
            return "python"
        if "function " in code_lower or "var " in code_lower or "const " in code_lower:
            return "javascript"
        if "$" in code and ("-" in code or "|" in code) and ("Get-" in code or "Set-" in code or "Invoke-" in code):
            return "powershell"
        if "#!/bin/" in code:
            return "bash"
        if "#include" in code:
            return "c"
        if "using System" in code or "namespace " in code:
            return "csharp"
        return "unknown"

    def _extension_to_language(self, ext: str) -> str:
        """Map file extension to language name."""
        mapping = {
            "py": "python", "js": "javascript", "ts": "typescript",
            "ps1": "powershell", "psm1": "powershell",
            "sh": "bash", "bash": "bash",
            "c": "c", "h": "c", "cpp": "cpp",
            "cs": "csharp", "java": "java",
            "go": "go", "rs": "rust", "rb": "ruby",
            "pl": "perl", "php": "php",
            "yml": "yaml", "yaml": "yaml",
            "xml": "xml", "json": "json",
        }
        return mapping.get(ext.lower(), "unknown")
