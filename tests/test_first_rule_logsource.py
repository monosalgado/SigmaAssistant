"""Offline tests for Change 26 (plan 2.2, step c): the generation prompt recommends the
analysis stage's log source for the FIRST rule, with the analysis's confidence and
reasoning; the model may choose otherwise if the evidence shows that log source cannot
observe the behaviour, and must then say why. Nothing is enforced in code (user,
2026-09-25: "I want them to think").

Why: the rule writer overrode a correct suggestion in 6 of 58 cases after Change 25 —
generation rule 2 made an initial-access rule "MANDATORY" with the attack vector's
telemetry, while the suggestion sat inside the Sysmon reference block.
"""

from __future__ import annotations

import json

from backend.pipeline import prompts
from backend.pipeline.sigma_logsource import first_rule_logsource_block
from backend.pipeline.stage_generate import GenerateStage

RULE = """title: X
id: 11111111-2222-3333-4444-555555555555
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'x.exe'
    condition: selection
"""


# --- the block ------------------------------------------------------------

def test_the_block_gives_the_log_source_as_yaml_with_the_analysis_reasoning():
    block = first_rule_logsource_block({"logsource_primary": "x", "user_confirmed": False,
        "suggestions": [{"category": "process_creation", "product": "windows",
                         "service": None, "confidence": 0.95,
                         "reasoning": "the loader spawns rundll32"}]})
    assert "logsource:\n    category: process_creation\n    product: windows" in block
    assert "service" not in block.split("Confidence")[0]
    assert "0.95" in block and "the loader spawns rundll32" in block


def test_a_log_source_without_a_category_keeps_its_service():
    block = first_rule_logsource_block({"suggestions": [
        {"category": None, "product": "windows", "service": "security", "confidence": 0.8}]})
    assert "logsource:\n    product: windows\n    service: security" in block


def test_internal_flags_are_not_shown():
    block = first_rule_logsource_block({"suggestions": [
        {"category": "process_creation", "product": "windows", "service": None,
         "service_dropped": "sysmon", "confidence": 0.9}]})
    assert "sysmon" not in block and "service_dropped" not in block


def test_the_analysts_confirmation_takes_precedence():
    block = first_rule_logsource_block({"user_confirmed": True,
        "primary_source": "process_creation (Sysmon Event ID 1)",
        "suggestions": [{"category": "webserver", "confidence": 0.9}]})
    assert "confirmed by the analyst" in block.lower()
    assert "process_creation (Sysmon Event ID 1)" in block
    assert "webserver" not in block


def test_no_recommendation_says_so():
    block = first_rule_logsource_block({"suggestions": []})
    assert "no log source was recommended" in block.lower()


# --- the prompt -----------------------------------------------------------

def test_the_block_sits_right_after_the_attack_vector_in_the_prompt():
    t = prompts.RULE_GENERATION
    assert t.index("{attack_vector_summary}") < t.index("{first_rule_logsource}") < t.index("{payload_signatures}")


def test_the_instructions_let_the_model_decide_and_explain():
    t = prompts.RULE_GENERATION
    assert "The FIRST rule" in t
    assert "unless the evidence" in t
    assert "description" in t.split("The FIRST rule")[1][:600]


def test_rule_2_keeps_the_attack_vector_rule_but_not_necessarily_first():
    rule2 = next(l for l in prompts.RULE_GENERATION.splitlines() if l.startswith("2. "))
    assert "PRIMARY ATTACK VECTOR" in rule2
    assert "does not have to be the first rule" in rule2


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


def test_the_generation_stage_puts_the_recommendation_in_its_prompt():
    client = _CapturingClient()
    GenerateStage(client, "fake", _NoRag()).run({
        "original_query": "https://example.com/a", "history": [],
        "preprocessed": {"url_content": [], "combined_text": "text"},
        "extraction": {"attack_summary": "summary", "indicators": []},
        "ttp_mapping": {"mappings": []},
        "logsource_suggestion": {"primary_source": "x", "suggestions": [
            {"category": "image_load", "product": "windows", "service": None,
             "confidence": 0.9, "reasoning": "a DLL is side-loaded"}]},
    })
    prompt = client.prompts[0]
    head = prompt.split("### Payload Signatures")[0]
    assert "category: image_load" in head and "a DLL is side-loaded" in head
