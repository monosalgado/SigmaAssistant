"""Tests for Change 50 (user 2026-10-12: test both parked options): the attack-vector step's log-source guess stops
steering the log source.

The analysis step's top pick follows the guess (`primary_telemetry`) in 42 of 47 cases (`diagnose_logsource.py`,
`c42B_tuning60`), and the guess reaches three log-source decisions: the analysis prompt and the rule writer's prompt
(the summary line "Primary telemetry: ...") and the rule writer's field-taxonomy query. With Change 50 none of them
gets it, so the analysis step - which has SigmaHQ's full menu - is the only place the log source is chosen.
Unchanged on purpose: the attack-vector prompt and answer (the guess is still made, recorded and shown to the
analyst), the analysis's ATT&CK search query (not a log-source decision; byte-identical), every other summary line.
Offline: stand-in client and store.
"""

from __future__ import annotations

import json

from backend.pipeline import prompts
from backend.pipeline.stage_analysis import AnalysisStage
from backend.pipeline.stage_attack_vector import AttackVectorStage
from backend.pipeline.stage_generate import GenerateStage

AV = {"initial_access_vector": "a phishing email with an LNK attachment", "vuln_class": "other",
      "protocol": "email", "primary_telemetry": "webserver_access_log", "kill_chain_stages": ["execution"],
      "confidence": 0.8}
TEXT = "The actor sent LNK files that ran rundll32.exe."


class _Store:
    def __init__(self):
        self.queries = []

    def search(self, query, collections=None, n_results=5):
        self.queries.append((query, collections))
        return {}


class _Client:
    model_name = "fake"

    def __init__(self, answer):
        self.answer, self.prompts = answer, []

    def generate(self, prompt, **kwargs):
        self.prompts.append(prompt)
        return json.dumps(self.answer)


def test_the_summary_can_leave_out_the_guess_and_keeps_everything_else():
    full = AttackVectorStage.format_vector_summary(AV)
    without = AttackVectorStage.format_vector_summary(AV, telemetry=False)
    assert "Primary telemetry" in full and "Primary telemetry" not in without
    assert [l for l in full.splitlines() if not l.startswith("- Primary telemetry")] == without.splitlines()


def _analysis(store=None):
    client = _Client({"indicators": [], "attack_summary": "s", "ttp_mappings": [], "logsource_suggestions": [],
                      "logsource_primary": ""})
    store = store or _Store()
    AnalysisStage(client, "fake", store).run({"preprocessed": {"combined_text": TEXT}, "attack_vector": AV})
    return client.prompts[0], store


def test_the_analysis_prompt_does_not_get_the_guess():
    prompt, _ = _analysis()
    assert "Primary telemetry" not in prompt
    assert "a phishing email with an LNK attachment" in prompt          # the rest of the summary is there


def test_the_attack_search_query_is_unchanged():
    _, store = _analysis()
    query = next(q for q, cols in store.queries if cols == ["mitre"])
    assert query == AttackVectorStage.format_vector_summary(AV) + "\n" + TEXT[:500]


RULE = ("title: t\nid: 11111111-1111-1111-1111-111111111111\nstatus: experimental\nlogsource:\n"
        "    category: process_creation\n    product: windows\ndetection:\n    sel:\n        Image|endswith: x.exe\n"
        "    condition: sel\nlevel: medium\n")


def _generation():
    client = _Client({"rules": [{"yaml_content": RULE, "explanation": ""}], "notes": ""})
    store = _Store()
    GenerateStage(client, "fake", store).run({
        "original_query": "https://example.com/a", "history": [],
        "preprocessed": {"url_content": [], "combined_text": TEXT},
        "attack_vector": AV,
        "extraction": {"attack_summary": "summary", "indicators": []},
        "ttp_mapping": {"mappings": []},
        "logsource_suggestion": {"primary_source": "process_creation / windows", "suggestions": [
            {"category": "process_creation", "product": "windows", "service": None, "confidence": 0.9,
             "reasoning": "rundll32 starts"}]},
    })
    return client.prompts[0], store


def test_the_rule_writer_does_not_get_the_guess():
    prompt, _ = _generation()
    assert "Primary telemetry" not in prompt
    assert "a phishing email with an LNK attachment" in prompt


def test_the_field_lookup_does_not_use_the_guess():
    _, store = _generation()
    query = next(q for q, cols in store.queries if cols == ["taxonomy"])
    assert "webserver_access_log" not in query and "process_creation" in query


def test_the_attack_vector_step_still_makes_the_guess():
    assert "`primary_telemetry`" in prompts.ATTACK_VECTOR_EXTRACTION
