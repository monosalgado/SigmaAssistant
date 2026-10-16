"""Tests for Change 51 (user 2026-10-12: test both parked options): the attack-vector step writes its log-source guess
from SigmaHQ's menu instead of 13 labels of the pipeline's own.

The 13 labels (added 2026-05-14, "where the initial exploit would be visible") are not Sigma's: 7 map to a Sigma
category, 6 have none; the analysis step's top pick follows the guess in 42 of 47 cases (`diagnose_logsource.py`,
`c42B_tuning60`). With Change 51 the guess (`primary_telemetry`, `secondary_telemetry`) is a SigmaHQ log source from
the same two tables the analysis step gets - a category, or `product/service`. Only section 4 and the worked
examples' two telemetry fields change; everything downstream is as today. The model decides; code records whether
the guess is on the menu, without enforcing it. Offline: stand-in client.
"""

from __future__ import annotations

import hashlib
import json
import re

from backend.pipeline import prompts
from backend.pipeline.sigma_logsource import format_category_table, format_service_table, load_logsource_table
from backend.pipeline.stage_attack_vector import AttackVectorStage, describe_telemetry, telemetry_on_table

TABLE = load_logsource_table()
P = prompts.ATTACK_VECTOR_EXTRACTION
OLD_ONLY = ("webserver_access_log", "web_proxy", "`waf`", "network_ids", "cloud_audit", "email_gateway", "auth_log")


def _h(text):
    return hashlib.sha256(text.encode()).hexdigest()


def test_section_4_asks_for_a_log_source_from_sigmahqs_tables():
    sec4 = P.split("### 4. Telemetry surfaces")[1].split("### 5.")[0]
    assert "{logsource_categories}" in sec4 and "{logsource_services}" in sec4
    assert "product/service" in sec4
    assert not any(label in P for label in OLD_ONLY)


def test_the_rest_of_the_prompt_is_unchanged():
    # Fingerprints of `main`'s prompt (70b010e): everything before section 4, and from section 5 on without the
    # examples' two telemetry fields.
    assert _h(P.split("### 4. Telemetry surfaces")[0]) == \
        "7107348cb6d55d2b8b793c19f742d1fa4138dca37599cc835d6a08973b829eea"
    after = "### 5. Kill-chain coverage" + P.split("### 5. Kill-chain coverage")[1]
    after = "\n".join(l for l in after.splitlines()
                      if not l.lstrip().startswith(('"primary_telemetry"', '"secondary_telemetry"')))
    assert _h(after) == "604d688cd136b319c971f8a37f1e93ce4881c02224fa76603f5649ec453d986f"


def test_the_examples_use_only_menu_values():
    values = re.findall(r'"primary_telemetry": "([^"]+)"', P)
    for listed in re.findall(r'"secondary_telemetry": \[([^\]]*)\]', P):
        values += re.findall(r'"([^"]+)"', listed)
    assert len(values) == 9 and all(telemetry_on_table(v, TABLE) for v in values)


def test_a_guess_is_shown_in_sigmas_terms():
    assert describe_telemetry("webserver") == "Sigma logsource category `webserver`"
    assert describe_telemetry("registry_set") == "Sigma logsource category `registry_set`"
    assert describe_telemetry("windows/security") == "Sigma logsource product `windows`, service `security`"
    assert "not a SigmaHQ log source" in describe_telemetry("made_up_source")


def test_on_the_menu_or_not():
    assert telemetry_on_table("process_creation", TABLE) and telemetry_on_table("zeek/http", TABLE)
    assert not telemetry_on_table("webserver_access_log", TABLE) and not telemetry_on_table("", TABLE)


class _Client:
    model_name = "fake"

    def __init__(self, telemetry):
        self.telemetry, self.prompts = telemetry, []

    def generate(self, prompt, **kwargs):
        self.prompts.append(prompt)
        return json.dumps({"initial_access_vector": "v", "primary_telemetry": self.telemetry, "confidence": 0.7})


def _run(telemetry):
    client = _Client(telemetry)
    context = AttackVectorStage(client, "fake").run({"preprocessed": {"combined_text": "a report"}})
    return client.prompts[0], context["attack_vector"]


def test_the_stage_sends_the_tables_and_records_whether_the_guess_is_on_them():
    prompt, av = _run("registry_set")
    assert format_category_table(TABLE) in prompt and format_service_table(TABLE) in prompt
    assert av["primary_telemetry"] == "registry_set" and av["primary_telemetry_on_table"] is True
    assert _run("webserver_access_log")[1]["primary_telemetry_on_table"] is False
