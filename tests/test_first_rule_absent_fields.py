"""Offline tests for Change 29 (plan 2.6b): the rule writer is told what SigmaHQ's rules
leave out of the recommended log source, and what Sigma's `product` means.

Why (Change 28 run): the analysis stage's suggestion was right for 9 of 12 web gold cases
("webserver", no product), and in 6 of them the first rule added a product anyway —
`fortigate`, `iis`, `sitecore`, `webserver` — reading `product` as the attacked application.
SigmaHQ's web rules carry no product. The note is generated from the committed table, never
written per case; the model still decides (user, 2026-09-25: "I want them to think").
"""

from __future__ import annotations

import json

import pytest

from backend.pipeline import prompts
from backend.pipeline.sigma_logsource import absent_fields_note, first_rule_logsource_block
from backend.pipeline.stage_generate import GenerateStage
from eval.diagnose_logsource import first_rule_adds_to_top

TABLE = {
    "with_category": [
        {"category": "process_creation", "products": ["linux", "macos", "windows"], "fields": []},
        {"category": "webserver", "products": [None], "fields": []},
    ],
    "without_category": [{"product": "windows", "service": "security", "fields": []}],
}


# --- the note ---------------------------------------------------------------

def test_a_log_source_whose_rules_have_no_product_says_so():
    note = absent_fields_note({"category": "webserver", "product": None}, TABLE)
    assert "no `product` and no `service`" in note and "leave them out" in note


def test_a_category_with_a_product_is_told_only_about_the_service():
    note = absent_fields_note({"category": "process_creation", "product": "windows"}, TABLE)
    assert "no `service`" in note and "leave it out" in note
    assert "`product`" not in note


def test_a_missing_product_the_rules_do_use_is_named_not_forbidden():
    note = absent_fields_note({"category": "process_creation"}, TABLE)
    assert "linux, macos or windows" in note
    assert "no `product`" not in note


def test_the_service_form_is_told_it_has_no_category():
    note = absent_fields_note({"product": "windows", "service": "security"}, TABLE)
    assert "no `category`" in note


@pytest.mark.parametrize("sug", [{"category": "email"}, {}, {"category": "-", "product": "-"}])
def test_nothing_is_said_about_a_log_source_the_table_does_not_know(sug):
    assert absent_fields_note(sug, TABLE) == ""


# --- the block ---------------------------------------------------------------

def _info(**top):
    return {"suggestions": [{"confidence": 0.9, "reasoning": "why", **top}]}


def test_the_block_carries_the_note_after_the_confidence_line():
    block = first_rule_logsource_block(_info(category="webserver", product=None, service=None), TABLE)
    assert block.startswith("logsource:\n    category: webserver\nConfidence: 0.9.")
    assert block.index("Confidence") < block.index("no `product`")


def test_without_a_table_the_block_is_as_before():
    block = first_rule_logsource_block(_info(category="webserver"))
    assert "leave" not in block


def test_the_analysts_confirmation_gets_no_note():
    block = first_rule_logsource_block({"user_confirmed": True, "primary_source": "webserver",
                                        "suggestions": [{"category": "webserver"}]}, TABLE)
    assert "leave" not in block


# --- the prompt --------------------------------------------------------------

def test_the_generation_prompt_says_what_product_means():
    t = prompts.RULE_GENERATION
    assert "what produces the log" in t
    assert "not necessarily the software the attack targets" in t


class _CapturingClient:
    model_name = "fake"

    def __init__(self):
        self.prompts = []

    def generate(self, prompt, **kwargs):
        self.prompts.append(prompt)
        return json.dumps({"rules": [], "notes": ""})


class _NoRag:
    def search(self, *args, **kwargs):
        return {}


def test_the_generation_stage_uses_the_committed_table():
    client = _CapturingClient()
    GenerateStage(client, "fake", _NoRag()).run({
        "original_query": "https://example.com/a", "history": [],
        "preprocessed": {"url_content": [], "combined_text": "text"},
        "extraction": {"attack_summary": "summary", "indicators": []},
        "ttp_mapping": {"mappings": []},
        "logsource_suggestion": {"primary_source": "x", "suggestions": [
            {"category": "webserver", "product": None, "service": None,
             "confidence": 0.9, "reasoning": "the exploit is an HTTP request"}]},
    })
    head = client.prompts[0].split("### Payload Signatures")[0]
    assert "no `product` and no `service`" in head


# --- the measure (fixed before the run) ----------------------------------------

def _row(rule, top):
    return {"scores": {"logsource": {"per_field": {
                f: {"predicted": rule.get(f), "gold": None} for f in ("category", "product", "service")}}},
            "pipeline": {"logsource_suggestions": [top] if top else []}}


@pytest.mark.parametrize("rule, top, expected", [
    ({"category": "webserver", "product": "fortigate"}, {"category": "webserver"}, {"product"}),
    ({"category": "webserver", "product": "iis", "service": "owa"}, {"category": "webserver"},
     {"product", "service"}),
    ({"category": "webserver"}, {"category": "webserver", "product": "-"}, set()),
    ({"category": "process_creation", "product": "windows"},
     {"category": "process_creation", "product": "windows"}, set()),
    ({"category": "process_creation", "product": "windows"}, {"category": "webserver"}, None),
    ({"category": "webserver"}, None, None),
])
def test_first_rule_adds_to_top(rule, top, expected):
    assert first_rule_adds_to_top(_row(rule, top)) == expected


def test_an_unscored_row_is_not_counted():
    assert first_rule_adds_to_top({"scores": {"logsource": None},
                                   "pipeline": {"logsource_suggestions": [{"category": "x"}]}}) is None
