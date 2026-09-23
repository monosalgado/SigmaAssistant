"""What the pipeline exposes for diagnosing a case (plan 1.1c).

Offline: fake client and vector store; no LLM, no network. The harness needs the
intermediate results (attack vector, logsource suggestions, generation counts) to
explain a score, not just the final rules.
"""

from __future__ import annotations

import json

from backend.pipeline.orchestrator import PipelineOrchestrator
from backend.pipeline.stage_generate import GenerateStage

BAD_ID_RULE = """title: X
id: 5a3b4c5d-6e7f-8g9h-1i2j-3k4l5m6n7o8p
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'x.exe'
    condition: selection
"""


class _Client:
    model_name = "fake"

    def generate(self, prompt, **kwargs):
        return json.dumps({"rules": [{"yaml_content": BAD_ID_RULE, "explanation": ""}],
                           "notes": ""})


class _NoRag:
    def search(self, *args, **kwargs):
        return {}


def _generation_context() -> dict:
    return {
        "original_query": "https://example.com/a",
        "history": [],
        "preprocessed": {"url_content": [], "combined_text": "text"},
        "extraction": {"attack_summary": "summary", "indicators": []},
        "ttp_mapping": {"mappings": []},
    }


def test_each_generation_call_is_logged():
    """A regeneration overwrites context["generation"]; the log must keep both calls,
    or the invalid-id rate (Change 9) loses a generation's worth of data."""
    stage = GenerateStage(_Client(), "fake", _NoRag())
    context = stage.run(_generation_context())
    context = stage.run(context)
    assert context["generation_log"] == [
        {"rules": 1, "ids_replaced": 1},
        {"rules": 1, "ids_replaced": 1},
    ]


def test_output_exposes_generation_log_and_retry_flag():
    orchestrator = PipelineOrchestrator(None, "fake", vector_store=None)
    context = {"generation_log": [{"rules": 2, "ids_replaced": 1}],
               "generation_retried": True}
    meta = orchestrator._format_output(context)["pipeline_metadata"]
    assert meta["generations"] == [{"rules": 2, "ids_replaced": 1}]
    assert meta["generation_retried"] is True


def test_output_defaults_when_nothing_was_generated():
    meta = PipelineOrchestrator(None, "fake", vector_store=None)._format_output({})["pipeline_metadata"]
    assert meta["generations"] == [] and meta["generation_retried"] is False
