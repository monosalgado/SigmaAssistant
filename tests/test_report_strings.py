"""Tests for Change 40 (user 2026-10-03: "Prompt + record"): the analysis's indicators reach the rule writer
as the strings the report gives, right after the payload signatures, and the pipeline records which of them
the rules use.

Why (tuning set, four runs; log 2026-10-03, detection steps 1-2): where the log source is right, the rules
use the right fields with the wrong values (S5v 0.14-0.22); of the human's values that occur in the report,
the first rule uses about a quarter; the ones the rule writer had and did not use were mostly offered as
indicators (a JSON dump below the attack summary), while the payload signatures - presented as what rules
should match - are used. Only 6% of the indicators reach the first rule (`c36_yaml60`, 35 of 609).

The model still decides which strings fit; the wording names kinds of evidence, no value. Code only records.
Offline: stand-in client; no LLM.
"""

from __future__ import annotations

import json

from backend.pipeline import prompts
from backend.pipeline.stage_generate import GenerateStage, format_indicators

T = prompts.RULE_GENERATION
RULE = ("title: t\nlogsource: {category: process_creation, product: windows}\ndetection:\n"
        "  selection:\n    Image|endswith: '\\\\schtasks.exe'\n  condition: selection\n")


def test_indicators_are_listed_one_per_line_with_their_type_and_context():
    text = format_indicators([{"value": "schtasks.exe", "type": "process", "context": "creates the task"},
                              "not an indicator", {"value": "evil.dll", "type": "file_path"}])
    assert text.splitlines() == ["- `schtasks.exe` (process) — creates the task", "- `evil.dll` (file_path)"]
    assert format_indicators([]) == "None found."


def test_the_reports_strings_come_right_after_the_payload_signatures():
    payload, strings = T.index("### Payload Signatures"), T.index("### Strings the Report Gives")
    avoid = T.index("### Strings that must NOT drive detection")
    assert payload < strings < avoid
    header = T[strings:T.index("\n", strings)]
    assert "specific to this attack" in header
    assert "Extracted Threat Indicators" not in T


def test_instruction_12_builds_the_detection_from_the_strings_the_report_gives():
    line = next(l for l in T.splitlines() if l.startswith("12. "))
    assert "strings the report gives" in line.lower() and "payload signatures" in line.lower()


def test_the_new_wording_names_kinds_of_evidence_but_no_value():
    header = T[T.index("### Strings the Report Gives"):].split("\n", 1)[0]
    line = next(l for l in T.splitlines() if l.startswith("12. "))
    for text in (header, line):
        assert "`" not in text and '"' not in text


class _CapturingClient:
    model_name = "fake"

    def __init__(self):
        self.prompts = []

    def generate(self, prompt, **kwargs):
        self.prompts.append(prompt)
        return json.dumps({"rules": [{"yaml_content": RULE, "explanation": ""}], "notes": ""})


class _NoRag:
    def search(self, *args, **kwargs):
        return {}


def test_the_rule_writer_is_given_the_list():
    client = _CapturingClient()
    GenerateStage(client, "fake", _NoRag()).run({
        "original_query": "https://example.com/a", "history": [],
        "preprocessed": {"url_content": [], "combined_text": "text"},
        "extraction": {"attack_summary": "summary", "indicators": [
            {"value": "schtasks.exe", "type": "process", "context": "creates the task"}]},
        "ttp_mapping": {"mappings": []},
        "logsource_suggestion": {"primary_source": "x", "suggestions": []},
    })
    section = client.prompts[0].split("### Strings the Report Gives")[1].split("### Strings that must NOT")[0]
    assert "- `schtasks.exe` (process) — creates the task" in section


def test_the_pipeline_records_which_indicators_the_rules_use():
    from backend.pipeline.orchestrator import PipelineOrchestrator
    from eval.run_eval import DIAGNOSIS_FIELDS
    context = {"attack_vector": {}, "generation": {"rules": [{"yaml_content": RULE}]},
               "extraction": {"indicators": [{"value": "schtasks.exe"}, {"value": "CVE-2024-1"}]}}
    PipelineOrchestrator._run_coverage_check(None, context)
    assert context["indicator_use"] == {"given": 2, "used": ["schtasks.exe"], "unused": ["CVE-2024-1"]}
    assert PipelineOrchestrator._pipeline_metadata(context)["indicator_use"] == context["indicator_use"]
    assert "indicator_use" in DIAGNOSIS_FIELDS
