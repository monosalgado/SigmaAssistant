"""Tests for measuring Change 37: every JSON answer of the PoC, attack-vector and analysis stages is
captured and read twice - with the reader before Change 37 and with today's - so the comparison is on
identical answers, free of run-to-run variation. Offline: stand-in stages; no LLM.
"""

from __future__ import annotations

from eval.probe_json_repair import capture_answers, old_parse, readability


def test_the_old_reader_is_the_one_before_change_37():
    assert old_parse('```json\n{"a": 1}\n```') == {"a": 1}
    try:
        old_parse('{"p": "C:\\Windows"}')
    except ValueError as exc:
        assert "escape" in str(exc)
    else:
        raise AssertionError("the old reader must fail on a stray backslash")


class _Stage:
    name = "analysis"

    def __init__(self, answer):
        self.answer = answer

    def llm_call(self, prompt, **kwargs):
        return self.answer

    def parse_json(self, text):
        from backend.pipeline.base_stage import PipelineStage
        return PipelineStage.parse_json(self, text)

    def run(self, context):
        context["result"] = self.parse_json(self.llm_call("prompt"))
        return context


def test_each_answer_is_read_both_ways():
    good = readability('{"logsource_suggestions": [{"category": "file_event"}]}', _Stage(""))
    assert good == {"old": True, "new": True, "error": None}
    bad = readability('{"p": "C:\\Windows"}', _Stage(""))
    assert bad["old"] is False and bad["new"] is True and "escape" in bad["error"]
    broken = readability('{"a": 1,,}', _Stage(""))
    assert broken["old"] is False and broken["new"] is False


def test_the_stages_answers_are_captured_as_it_runs():
    stage = _Stage('{"p": "C:\\Windows"}')
    with capture_answers(stage) as answers:
        context = stage.run({})
    assert answers == ['{"p": "C:\\Windows"}']
    assert context["result"] == {"p": "C:\\Windows"}
    assert "llm_call" not in vars(stage)        # restored
