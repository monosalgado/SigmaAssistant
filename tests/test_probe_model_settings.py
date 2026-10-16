"""Tests for the qwen3.6 settings probe (`eval/probe_model_settings.py`, log 2026-10-16): reading a thinking model's
answer, and the presence-penalty verdict. Offline; made-up responses."""

from __future__ import annotations

from eval.probe_model_settings import answer_of, override_verdict, reasoning_of


def test_reasoning_from_a_field_or_from_think_tags():
    assert reasoning_of({"content": '{"ok": true}', "reasoning": "Let me think."}) == "Let me think."
    assert reasoning_of({"content": '{"ok": true}', "reasoning_content": "Hmm."}) == "Hmm."
    assert reasoning_of({"content": '<think>\nplan it\n</think>\n{"ok": true}'}) == "plan it"
    assert reasoning_of({"content": '{"ok": true}'}) == ""


def test_the_answer_without_its_thinking():
    assert answer_of({"content": '<think>\nplan it\n</think>\n{"ok": true}'}) == '{"ok": true}'
    assert answer_of({"content": '{"ok": true}', "reasoning": "x"}) == '{"ok": true}'
    assert answer_of({"content": None}) == ""


def test_the_presence_penalty_verdict():
    assert override_verdict("a", "a", "b") == "the request's value overrides the Modelfile's"
    assert override_verdict("a", "a", "a") == "no effect seen"
    assert override_verdict("a", "b", "a").startswith("inconclusive")
