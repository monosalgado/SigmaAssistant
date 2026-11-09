"""Offline tests for Change 54 (plan approved by the user 2026-11-08; log "Change 54 planned"): host footprint first.

Diagnosis D1: the pipeline understood the ActiveMQ attack's host behaviour (the server's java.exe starting a shell),
but the rules anchored on the exploit's delivery and copied strings; `ParentImage` was in 0 of the 15 rules. Now the
attack-vector step lists where the attack shows in the logs of the machine it runs on (steps with an actor, an
action, a target and their SigmaHQ log source), code keeps the well-formed steps and records whether each log source
is on SigmaHQ's table, the rule writer must detect one step, and the coverage check records whether a rule did.
Nothing names an attack. Offline: stand-in clients, no model.
"""

from __future__ import annotations

import json
import re

from backend.pipeline import prompts
from backend.pipeline.sigma_logsource import load_logsource_table
from backend.pipeline.stage_attack_vector import (
    FOOTPRINT_ACTIONS,
    AttackVectorStage,
    normalize_footprint,
    telemetry_on_table,
)
from backend.pipeline.stage_generate import GenerateStage

AV = prompts.ATTACK_VECTOR_EXTRACTION
GEN = prompts.RULE_GENERATION
TABLE = load_logsource_table()
STEP_KEYS = {"log_source", "actor", "action", "target", "derived_from"}


def _examples() -> list:
    section = AV.split("### Few-shot Examples", 1)[1]
    blocks = re.findall(r"Output \(abbreviated\):\n(\{\{.*?\n\}\})", section, re.S)
    return [json.loads(b.replace("{{", "{").replace("}}", "}")) for b in blocks]


def _step(log_source="process_creation", actor="svc.exe", action="starts", target="sh", derived_from="q"):
    return {"log_source": log_source, "actor": actor, "action": action, "target": target,
            "derived_from": derived_from}


# --- the attack-vector prompt ---------------------------------------------------------------------------

def test_a_host_footprint_section_sits_between_the_telemetry_and_the_kill_chain():
    assert AV.index("### 4. Telemetry surfaces") < AV.index("### 4b. Host footprint") \
        < AV.index("### 5. Kill-chain coverage")
    section = AV.split("### 4b. Host footprint")[1].split("### 5.")[0]
    for field in ("`log_source`", "`actor`", "`action`", "`target`", "`derived_from`"):
        assert field in section, field
    assert all(f"`{a}`" in section for a in FOOTPRINT_ACTIONS)
    assert "inferred_from_class" in section and "not necessarily where" in section
    assert "an empty list" in section.lower()


def test_every_example_shows_a_footprint_on_sigmahqs_table():
    examples = _examples()
    assert len(examples) == 3
    for example in examples:
        steps = example["host_footprint"]
        assert steps and all(set(s) == STEP_KEYS for s in steps)
        assert all(telemetry_on_table(s["log_source"], TABLE) for s in steps)
        assert all(s["action"] in FOOTPRINT_ACTIONS for s in steps)


def test_each_examples_footprint_is_one_line():
    # One line each, so the fingerprint of Change 51 (everything else unchanged) can leave it out.
    lines = [line for line in AV.splitlines() if line.lstrip().startswith('"host_footprint"')]
    assert len(lines) == 3 and all(line.rstrip().endswith("],") for line in lines)


# --- the stage --------------------------------------------------------------------------------------------

def test_well_formed_steps_are_kept_with_whether_their_log_source_is_on_the_table():
    steps = normalize_footprint([
        _step(log_source=" process_creation ", action="Starts"),
        _step(log_source="made_up_logs", action="writes", target="x.txt", derived_from="inferred_from_class"),
        _step(log_source="file_event", actor="", target=""),          # nothing acts and nothing is acted on
        {"actor": "svc.exe", "action": "starts", "target": "sh"},      # no log source
        "not a step",
        _step(log_source="registry_set", actor="a", action="teleports", target="k", derived_from=7)])
    assert steps == [
        {**_step(), "on_table": True},
        {**_step(log_source="made_up_logs", action="writes", target="x.txt", derived_from="inferred_from_class"),
         "on_table": False},
        {**_step(log_source="registry_set", actor="a", action="other", target="k", derived_from="7"), "on_table": True}]


def test_at_most_four_steps_and_anything_but_a_list_gives_none():
    assert len(normalize_footprint([_step()] * 6)) == 4
    assert normalize_footprint("process_creation") == [] and normalize_footprint(None) == []


class _Client:
    model_name = "fake"

    def __init__(self, answer):
        self.answer, self.prompts = answer, []

    def generate(self, prompt, **kwargs):
        self.prompts.append(prompt)
        return json.dumps(self.answer)


def _vector(answer):
    return AttackVectorStage(_Client(answer), "fake").run({"preprocessed": {"combined_text": "a report"}})["attack_vector"]


def test_the_stage_keeps_the_footprint_and_gives_an_empty_one_by_default():
    av = _vector({"initial_access_vector": "v", "primary_telemetry": "network_connection", "host_footprint": [_step()]})
    assert av["host_footprint"] == [{**_step(), "on_table": True}]
    assert _vector({"initial_access_vector": "v"})["host_footprint"] == []
    assert AttackVectorStage.EMPTY_RESULT["host_footprint"] == []


def test_the_rule_writer_gets_each_step_in_sigmas_terms_with_its_evidence():
    text = AttackVectorStage.format_host_footprint({"host_footprint": normalize_footprint([
        _step(derived_from="the service runs sh"),
        _step(log_source="made_up_logs", action="writes", target="x.txt", derived_from="inferred_from_class")])})
    first, second = text.splitlines()
    assert first == '1. In Sigma logsource category `process_creation`: svc.exe starts sh - "the service runs sh"'
    assert "(not a SigmaHQ log source)" in second and "inferred from the kind of attack" in second


def test_no_footprint_says_so():
    assert AttackVectorStage.format_host_footprint({}) == "No host footprint identified."
    assert AttackVectorStage.format_host_footprint({"host_footprint": []}) == "No host footprint identified."


# --- the rule writer ---------------------------------------------------------------------------------------

def test_the_rule_writer_gets_the_footprint_right_after_the_candidate_patterns():
    assert GEN.index("{payload_signatures}") < GEN.index("### Host footprint") < GEN.index("{host_footprint}") \
        < GEN.index("### Strings that must NOT drive detection")


def test_instruction_2b_asks_for_a_rule_on_a_footprint_step_with_parent_and_child_fields():
    line = next(l for l in GEN.splitlines() if l.startswith("2b. "))
    for s in ("HOST FOOTPRINT", "`ParentImage`", "`Image`", "log source", "does not have to be the first rule"):
        assert s in line, s
    instructions = GEN.split("### Instructions")[1].split("### Output Format")[0]
    numbers = [m.group(1) for m in re.finditer(r"^(\d+b?)\. ", instructions, re.M)]
    assert numbers == ["1", "2", "2b"] + [str(n) for n in range(3, 13)]


class _CapturingClient:
    model_name = "fake"

    def __init__(self):
        self.prompts = []

    def generate(self, prompt, **kwargs):
        self.prompts.append(prompt)
        return "no rules"


class _NoRag:
    def search(self, *args, **kwargs):
        return {}


def test_the_generation_stage_puts_the_footprint_in_its_prompt():
    client = _CapturingClient()
    GenerateStage(client, "fake", _NoRag()).run({
        "original_query": "https://example.com/a", "history": [],
        "preprocessed": {"url_content": [], "combined_text": "text"},
        "extraction": {"attack_summary": "summary", "indicators": []},
        "ttp_mapping": {"mappings": []}, "logsource_suggestion": {},
        "attack_vector": {"initial_access_vector": "v", "host_footprint": normalize_footprint([_step()])}})
    section = client.prompts[0].split("### Host footprint")[1].split("### Strings that must NOT drive detection")[0]
    assert "svc.exe starts sh" in section


# --- the coverage check (recorded only) -------------------------------------------------------------------

def _rule(category=None, product="windows", service=None):
    lines = ["title: t", "logsource:"]
    if category:
        lines.append(f"    category: {category}")
    if product:
        lines.append(f"    product: {product}")
    if service:
        lines.append(f"    service: {service}")
    lines += ["detection:", "    sel:", "        Image: 'x.exe'", "    condition: sel"]
    return {"yaml_content": "\n".join(lines) + "\n"}


def _covered(steps, rules):
    return AttackVectorStage.coverage_gap_check({"host_footprint": normalize_footprint(steps)}, rules)


def test_coverage_records_whether_a_rule_uses_a_footprint_steps_log_source():
    assert _covered([_step()], [_rule("network_connection"), _rule("process_creation")])["host_footprint_covered"] is True
    assert _covered([_step()], [_rule("network_connection")])["host_footprint_covered"] is False


def test_a_product_service_step_is_matched_on_product_and_service():
    step = _step(log_source="windows/security")
    assert _covered([step], [_rule(service="security")])["host_footprint_covered"] is True
    assert _covered([step], [_rule(service="system")])["host_footprint_covered"] is False


def test_without_a_step_on_the_table_coverage_is_not_measured():
    assert _covered([_step(log_source="made_up_logs")], [_rule("process_creation")])["host_footprint_covered"] is None
    assert AttackVectorStage.coverage_gap_check({}, [_rule("process_creation")])["host_footprint_covered"] is None


def test_footprint_coverage_never_adds_a_warning_so_it_never_triggers_the_retry():
    coverage = _covered([_step()], [_rule("network_connection")])
    assert coverage["host_footprint_covered"] is False
    assert not any("footprint" in w.lower() for w in coverage["warnings"])


def test_a_rule_that_does_not_parse_does_not_count_as_covering():
    assert _covered([_step()], [{"yaml_content": "logsource: [unclosed"}])["host_footprint_covered"] is False


# --- the wording clarified before the run (user, 2026-11-09; log the same day) ------------------------------
# The live check wrote a kernel-driver exploit and a DLL as `starts` steps, and the prompt's own Example A read
# "explorer.exe starts rundll32.exe loading <loader>.dll": a start and a load in one step.

def test_each_action_is_defined_and_a_module_is_loaded_not_started():
    section = AV.split("### 4b. Host footprint")[1].split("### 5.")[0]
    line = next(l for l in section.splitlines() if l.strip().startswith("- `action`"))
    assert "`starts`" in line and "its own process" in line
    assert "`loads`" in line and "DLL" in line and "driver" in line
    assert "`image_load`" in line and "`driver_load`" in line


def test_a_step_is_written_only_when_the_attack_has_it():
    section = AV.split("### 4b. Host footprint")[1].split("### 5.")[0]
    assert "starts no new program" in section and "no `starts` step" in section


def test_example_a_writes_the_start_and_the_load_as_two_steps():
    steps = _examples()[0]["host_footprint"]
    assert [(s["action"], s["log_source"]) for s in steps] == [
        ("starts", "process_creation"), ("loads", "image_load"), ("changes", "registry_set")]
    assert steps[0]["target"] == "rundll32.exe" and "<loader>.dll" in steps[1]["target"]
    assert not any(s["action"] == "starts" and ".dll" in s["target"] for e in _examples() for s in e["host_footprint"])


def test_instruction_2b_says_a_started_program_is_a_process_and_how_to_write_a_load():
    line = next(l for l in GEN.splitlines() if l.startswith("2b. "))
    assert "not a DLL or driver" in line and "`ImageLoaded`" in line
