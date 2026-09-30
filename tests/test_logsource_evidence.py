"""Tests for Change 38 (better log-source picks, step 2, user 2026-09-29): the analysis prompt asks the
model to look at the evidence the text gives, rank the log sources by how specific the evidence each
would record is, and name that evidence for every suggestion (`evidence`).

Why (the tuning set only): about 25 of 60 top picks match no human-written SigmaHQ rule for the report;
reports whose distinctive evidence is a dropped file, a registry key, a network destination or a script
were picked as a process start or a web request, and a log a specific product writes (the Windows
Security log, an appliance's own log) was never picked (0 of 60 in three runs). The old instruction was
only "Determine the best Sigma log sources for detecting this attack".

No mapping is hard-coded: the model reasons, the code validates against SigmaHQ's table as before.
The example stays a placeholder (Change 27: examples get copied).
"""

from __future__ import annotations

import json

from backend.pipeline import prompts


def _part3():
    """Part 3 with its line breaks collapsed, so a phrase wrapped across two lines still matches."""
    t = prompts.COMBINED_ANALYSIS
    return " ".join(t[t.index("## PART 3: Log Source Recommendation"):t.index("### Output Format")].split())


def test_the_model_looks_at_the_evidence_the_text_gives_before_choosing():
    part = _part3().lower()
    for kind in ("command", "file", "registry", "network", "script", "event id"):
        assert kind in part, kind
    assert "own log" in part            # a log a specific product or appliance writes


def test_log_sources_are_ranked_by_how_specific_their_evidence_is():
    part = _part3().lower()
    assert "most specific" in part and "false positives" in part
    assert "whichever form" in part       # a category, or a product's own log


def test_no_log_source_is_named_as_the_default():
    # The instruction ranks by evidence; it does not steer towards or away from a category.
    instruction = _part3().split("### Log sources with a category")[0]
    for name in ("process_creation", "webserver", "file_event", "registry_set", "security"):
        assert name not in instruction, name


def test_every_suggestion_names_its_evidence():
    part = _part3()
    assert "evidence" in part.split("Each suggestion needs:")[1]


def test_the_example_carries_evidence_as_placeholders_only():
    t = prompts.COMBINED_ANALYSIS
    example = t[t.index("### Output Format"):]
    body = json.loads(example[example.index("{{"):].replace("{{", "{").replace("}}", "}"))
    evidence = body["logsource_suggestions"][0]["evidence"]
    assert evidence and all(e.startswith("<") and e.endswith(">") for e in evidence)


def test_the_prompt_still_fills_its_inputs():
    filled = prompts.COMBINED_ANALYSIS.format(text="T", attack_vector_summary="A", incidental_blacklist="B",
                                              mitre_context="M", logsource_categories="C",
                                              logsource_services="S")
    assert "### Log sources with a category (no service)\nC" in filled


def test_the_evidence_reaches_the_saved_suggestions():
    from backend.pipeline.sigma_logsource import normalise_suggestion
    s = normalise_suggestion({"category": "file_event", "product": "windows", "service": None,
                              "evidence": ["C:\\Windows\\Temp\\x.dll"]}, set())
    assert s["evidence"] == ["C:\\Windows\\Temp\\x.dll"]


# --- v2 (2026-09-30): the evidence first, then the ranking ------------------------------------
# v1's development check (tuning set): every suggestion listed evidence, but the top pick stayed the
# habitual one even when a lower suggestion held far more specific evidence (12 cases). The answer now
# lists the evidence before any suggestion, each item with the log source that records it and whether it
# is specific to the attack; the suggestions are then ranked from that list.

def _output_format():
    t = prompts.COMBINED_ANALYSIS
    return t[t.index("### Output Format"):]


def test_the_evidence_inventory_is_written_before_the_suggestions():
    out = _output_format()
    assert out.index('"evidence_inventory"') < out.index('"logsource_suggestions"')


def test_each_inventory_item_says_its_log_source_and_whether_it_is_specific():
    body = json.loads(_output_format()[_output_format().index("{{"):].replace("{{", "{").replace("}}", "}"))
    item = body["evidence_inventory"][0]
    assert set(item) == {"evidence", "log_source", "specific"}
    assert item["evidence"].startswith("<") and item["log_source"].startswith("<")


def test_specific_is_defined_by_whether_normal_activity_also_produces_it():
    part = _part3().lower()
    assert "evidence_inventory" in part
    assert "normal activity" in part and "search for this exact value" in part
    assert "ranked from the inventory" in part


def test_the_inventory_reaches_the_saved_results():
    from backend.pipeline.stage_analysis import AnalysisStage
    from eval.run_eval import DIAGNOSIS_FIELDS
    assert "evidence_inventory" in DIAGNOSIS_FIELDS

    class _Client:
        model_name = "fake"

        def generate(self, prompt, **kwargs):
            return json.dumps({"indicators": [], "attack_summary": "s", "ttp_mappings": [],
                               "evidence_inventory": [{"evidence": "evil.dll", "log_source": "file_event / windows",
                                                       "specific": True}],
                               "logsource_suggestions": [{"category": "file_event", "product": "windows",
                                                          "service": None, "evidence": ["evil.dll"]}],
                               "logsource_primary": "file_event / windows"})

    class _Store:
        def search(self, *a, **k):
            return {}

        def __getattr__(self, name):
            return lambda *a, **k: {}

    context = AnalysisStage(_Client(), "fake", _Store()).run(
        {"preprocessed": {"combined_text": "text"}, "attack_vector": {}})
    assert context["logsource_suggestion"]["evidence_inventory"][0]["evidence"] == "evil.dll"


# --- v2 refined (2026-09-30, smoke on 2 tuning cases): the inventory followed the prompt's own list
# --- order (processes first) and marked standard system programs "specific" (all 15 items).

def test_the_inventory_follows_the_texts_order_not_the_prompts():
    assert "in the order it appears in the text" in _part3().lower()


def test_specific_means_a_value_normal_activity_does_not_produce_even_if_the_attacker_used_it():
    part = _part3().lower()
    assert "expect no hits from normal activity" in part
    assert "even if the attacker used it" in part
    assert "most items marked specific" in part
