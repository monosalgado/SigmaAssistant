"""How much of the extracted source the attack-vector and analysis stages see.

These stages used to read only the first 8000 / 4000 characters. On pages that
open with site navigation that window held no article at all, and the
attack-vector stage filled the gap with its own prompt examples (defect 15,
ENGINEERING_LOG 2026-09-23). Offline: a fake client captures the prompt.
"""

from __future__ import annotations

from backend.pipeline.base_stage import SOURCE_TEXT_MAX_CHARS
from backend.pipeline.stage_analysis import AnalysisStage
from backend.pipeline.stage_attack_vector import AttackVectorStage

MARKER = "ARTICLE-BODY-MARKER-7f3a"


class CapturingClient:
    model_name = "fake"

    def __init__(self):
        self.prompts = []

    def generate(self, prompt, **kwargs):
        self.prompts.append(prompt)
        return "{}"


class NoRagStore:
    def search(self, *args, **kwargs):
        return {}


def source_with_marker_at(offset: int) -> str:
    """Navigation-like filler with the article marker placed at `offset`."""
    filler = "Products Solutions Support Careers Contact "
    head = (filler * (offset // len(filler) + 1))[:offset]
    return head + MARKER + " the actual write-up continues here."


def context_for(text: str) -> dict:
    return {"preprocessed": {"combined_text": text, "segments": [], "url_content": []}}


def run_attack_vector(text: str) -> str:
    client = CapturingClient()
    AttackVectorStage(client, "fake").run(context_for(text))
    return client.prompts[0]


def run_analysis(text: str) -> str:
    client = CapturingClient()
    AnalysisStage(client, "fake", NoRagStore()).run(context_for(text))
    return client.prompts[0]


def test_attack_vector_sees_text_beyond_the_old_8000_char_cut():
    assert MARKER in run_attack_vector(source_with_marker_at(30_000))


def test_analysis_sees_text_beyond_the_old_4000_char_cut():
    assert MARKER in run_analysis(source_with_marker_at(30_000))


def test_longest_corpus_case_fits_inside_the_window():
    """79,800 characters is the longest extracted text in the 303-case corpus."""
    assert SOURCE_TEXT_MAX_CHARS >= 79_800


def test_text_beyond_the_window_is_cut_and_the_cut_is_logged(capsys):
    prompt = run_analysis(source_with_marker_at(SOURCE_TEXT_MAX_CHARS + 10))
    assert MARKER not in prompt
    assert "Source text cut from" in capsys.readouterr().out


def test_text_inside_the_window_is_not_reported_as_cut(capsys):
    run_attack_vector(source_with_marker_at(1_000))
    assert "Source text cut" not in capsys.readouterr().out
