"""Tests for comparing the pipeline's prompts between two versions of the code (professor's
question, 2026-09-28: how was the prompt in May, and how different is it now?).

Offline: the prompts are read from source text, never imported or run, so an old version's
code does not execute. Which file uses a prompt comes from `git grep` lines; archived
stages do not count, because the pipeline no longer calls them.
"""

from __future__ import annotations

from eval.prompt_history import compare, prompt_templates, prompt_users, template_inputs

SOURCE = '''
"""Module docstring is not a prompt."""
X = 3
RULE_GENERATION = """Write rules for {attack_summary} on {current_date}. JSON: {{"rules": []}}"""
COMBINED_ANALYSIS = "Analyse {text}"
NAME = f"not a {X} constant"
'''


def test_prompts_are_the_module_level_string_constants():
    assert set(prompt_templates(SOURCE)) == {"RULE_GENERATION", "COMBINED_ANALYSIS"}


def test_a_templates_inputs_are_its_placeholders_not_its_literal_braces():
    text = prompt_templates(SOURCE)["RULE_GENERATION"]
    assert template_inputs(text) == ["attack_summary", "current_date"]


def test_the_files_that_use_each_prompt_leave_out_archived_stages():
    lines = [
        "2ec05f6:backend/pipeline/stage_generate.py:12:    prompt = prompts.RULE_GENERATION.format(",
        "2ec05f6:backend/pipeline/archive/stage_extract.py:18:    prompts.ENTITY_EXTRACTION.format(",
        "2ec05f6:backend/pipeline/orchestrator.py:60:    p = prompts.INTENT_CLASSIFICATION + prompts.CONVERSATIONAL",
    ]
    assert prompt_users(lines) == {"RULE_GENERATION": {"stage_generate.py"},
                                   "INTENT_CLASSIFICATION": {"orchestrator.py"},
                                   "CONVERSATIONAL": {"orchestrator.py"}}


def test_comparing_two_versions_says_what_changed_in_each_prompt():
    old = {"A": "same {x}", "B": "old {x}", "GONE": "bye"}
    new = {"A": "same {x}", "B": "new text {x} {y}", "NEW": "hi {z}"}
    rows = {r["name"]: r for r in compare(old, new)}
    assert rows["A"]["status"] == "same"
    assert rows["B"]["status"] == "changed"
    assert (rows["B"]["chars_old"], rows["B"]["chars_new"]) == (len("old {x}"), len("new text {x} {y}"))
    assert rows["B"]["inputs_added"] == ["y"] and rows["B"]["inputs_removed"] == []
    assert rows["GONE"]["status"] == "removed" and rows["GONE"]["chars_new"] is None
    assert rows["NEW"]["status"] == "added" and rows["NEW"]["inputs_added"] == ["z"]


def test_the_comparison_marks_which_prompts_the_pipeline_uses_in_each_version():
    rows = {r["name"]: r for r in compare({"A": "a", "B": "b"}, {"A": "a", "B": "b"},
                                          users_old={"A": {"x.py"}, "B": {"y.py"}},
                                          users_new={"A": {"x.py"}})}
    assert rows["A"]["used_old"] == ["x.py"] and rows["A"]["used_new"] == ["x.py"]
    assert rows["B"]["used_old"] == ["y.py"] and rows["B"]["used_new"] == []
