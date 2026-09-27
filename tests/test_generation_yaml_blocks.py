"""Tests for Change 36 (defect 5): the rule writer answers in YAML blocks, not JSON strings.

Fully offline: the parser is a pure function; the stage runs with a capturing fake client.

Generation used to return each rule inside a JSON string, so every backslash was escaped twice
and one bad escape (`Invalid \\escape`, a Windows path) lost every rule of the answer - 3 of the
7 lost first rules in the shared run (log 2026-09-26), and a live review rewrite (2026-09-27).
Now each rule is a ```yaml block under a "### Rule N: <why>" heading, written as in a Sigma file.
"""

from __future__ import annotations

import yaml

from backend.pipeline import prompts
from backend.pipeline.stage_generate import GenerateStage, parse_rule_blocks

ANSWER = r"""Here are the rules.

### Rule 1: Detects Mimikatz reading LSASS memory
```yaml
title: Mimikatz LSASS Access
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
    condition: selection
```

### Rule 2 — Detects the sekurlsa command line
```yml
title: Sekurlsa Command
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'sekurlsa::logonpasswords'
    condition: selection
```

### Notes
The first rule needs Sysmon event 10.
"""


# --- the parser ---------------------------------------------------------------------

def test_each_rule_block_is_a_rule_with_its_heading_as_the_explanation():
    out = parse_rule_blocks(ANSWER)
    assert [r["explanation"] for r in out["rules"]] == [
        "Detects Mimikatz reading LSASS memory", "Detects the sekurlsa command line"]
    assert out["rules"][1]["yaml_content"].startswith("title: Sekurlsa Command")
    assert out["notes"] == "The first rule needs Sysmon event 10."
    assert out["parse_error"] is None


def test_a_backslash_is_kept_exactly_as_written():
    rule = yaml.safe_load(parse_rule_blocks(ANSWER)["rules"][0]["yaml_content"])
    assert rule["detection"]["selection"]["TargetImage|endswith"] == "\\lsass.exe"


def test_blocks_without_headings_are_still_rules():
    out = parse_rule_blocks("```yaml\ntitle: A\n```\n\ntext\n\n```yaml\ntitle: B\n```")
    assert [r["yaml_content"] for r in out["rules"]] == ["title: A", "title: B"]
    assert [r["explanation"] for r in out["rules"]] == ["", ""]


def test_an_answer_without_a_yaml_block_is_a_parse_error_not_a_crash():
    out = parse_rule_blocks('{"rules": [{"yaml_content": "title: A\\\\x"}]}')
    assert out["rules"] == []
    assert "no ```yaml block" in out["parse_error"]


def test_an_empty_block_is_not_a_rule():
    out = parse_rule_blocks("### Rule 1: nothing\n```yaml\n\n```\n")
    assert out["rules"] == [] and out["parse_error"]


# --- the prompt ------------------------------------------------------------------------

def test_the_prompt_asks_for_yaml_blocks_not_json():
    t = prompts.RULE_GENERATION
    assert "Respond with JSON only" not in t
    assert "### Rule 1:" in t and "```yaml" in t
    assert '"yaml_content"' not in t


def test_the_worked_example_is_a_valid_rule_in_the_same_format():
    example = prompts.RULE_GENERATION.split("### Few-shot Example")[1]
    example = example.replace("{{", "{").replace("}}", "}").replace("{current_date}", "2026-09-27")
    out = parse_rule_blocks(example)
    assert len(out["rules"]) == 1
    rule = yaml.safe_load(out["rules"][0]["yaml_content"])
    assert rule["detection"]["selection"]["TargetImage|endswith"] == "\\lsass.exe"
    assert rule["tags"] == ["attack.credential-access", "attack.t1003.001"]     # Change 33 kept
    assert rule["id"] == "<new UUID>"                                           # Change 30 kept


# --- the stage -----------------------------------------------------------------------

class _CapturingClient:
    model_name = "fake"

    def __init__(self, answer):
        self.answer, self.kwargs = answer, []

    def generate(self, prompt, **kwargs):
        self.kwargs.append(kwargs)
        return self.answer


class _NoRag:
    def search(self, *args, **kwargs):
        return {}


def _run(answer):
    client = _CapturingClient(answer)
    context = GenerateStage(client, "fake", _NoRag()).run({
        "original_query": "https://example.com/a", "history": [],
        "preprocessed": {"url_content": [], "combined_text": "text"},
        "extraction": {"attack_summary": "summary", "indicators": []},
        "ttp_mapping": {"mappings": []},
        "logsource_suggestion": {"suggestions": []},
    })
    return client, context


def test_the_stage_does_not_ask_the_model_for_json():
    client, _ = _run(ANSWER)
    assert client.kwargs[0].get("json_mode") is False


def test_the_stage_reads_the_rules_from_the_blocks():
    _, context = _run(ANSWER)
    gen = context["generation"]
    assert len(gen["rules"]) == 2
    assert gen["rules"][0]["explanation"] == "Detects Mimikatz reading LSASS memory"
    assert gen["notes"] == "The first rule needs Sysmon event 10."
    assert context["generation_log"][-1]["parse_error"] is None


def test_an_unreadable_answer_is_recorded_in_the_generation_log():
    _, context = _run("I cannot help with that.")
    assert context["generation"]["rules"] == []
    assert "Generation error" in context["generation"]["notes"]
    assert context["generation_log"][-1]["parse_error"]
