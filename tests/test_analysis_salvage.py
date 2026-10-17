"""Tests for Change 52's salvage (user 2026-10-17: "raise the limit and add the salvage"): when every attempt of the
analysis answer is cut at the limit, code keeps what the last attempt finished - every complete top-level field and
the complete items of a list cut midway - instead of discarding the whole answer. Missing fields stay empty. Recorded
in the row. Offline: stand-in client; made-up answers.
"""

from __future__ import annotations

import json

from backend.llm_client import OutputLimitReached
from backend.pipeline.base_stage import salvage_json
from backend.pipeline.stage_analysis import AnalysisStage

IND = '{"value": "cmd.exe", "type": "process", "context": "ran it", "confidence": "high"}'


def test_a_list_cut_midway_keeps_its_complete_items():
    text = '{"indicators": [' + IND + ', ' + IND.replace("cmd.exe", "x.dll") + ', {"value": "evil.ex'
    assert salvage_json(text) == {"indicators": [json.loads(IND), json.loads(IND.replace("cmd.exe", "x.dll"))]}


def test_complete_fields_before_the_cut_are_kept():
    text = ('{"indicators": [' + IND + '], "attack_summary": "a loader", "ttp_mappings": [{"technique_id": "T1059"}, '
            '{"technique_id": "T10')
    assert salvage_json(text) == {"indicators": [json.loads(IND)], "attack_summary": "a loader",
                                  "ttp_mappings": [{"technique_id": "T1059"}]}


def test_braces_inside_strings_do_not_confuse_it():
    text = '{"indicators": [{"value": "a{b}[c],", "type": "other"}, {"value": "d'
    assert salvage_json(text) == {"indicators": [{"value": "a{b}[c],", "type": "other"}]}


def test_nothing_complete_gives_none():
    assert salvage_json('{"indicators": [{"value": "cm') is None
    assert salvage_json("not json at all") is None


class _CutClient:
    model_name = "fake"

    def __init__(self, partial):
        self.partial = partial

    def generate(self, prompt, **kwargs):
        raise OutputLimitReached("answer stopped at the 32768-token output limit on 3 attempts", partial=self.partial)


class _Store:
    def search(self, *args, **kwargs):
        return {}


def test_a_cut_analysis_keeps_what_it_finished_and_says_so():
    partial = '{"indicators": [' + IND + ', ' + IND.replace("cmd.exe", "x.dll") + ', {"value": "evil'
    context = AnalysisStage(_CutClient(partial), "fake", _Store()).run(
        {"preprocessed": {"combined_text": "a report"}, "attack_vector": {}})
    assert [i["value"] for i in context["extraction"]["indicators"]] == ["cmd.exe", "x.dll"]
    assert context["logsource_suggestion"]["suggestions"] == [] and context["ttp_mapping"]["mappings"] == []
    assert context["extraction"]["salvaged"] == {"fields": ["indicators"], "indicators": 2}


def test_an_answer_with_nothing_complete_is_an_empty_analysis_as_before():
    context = AnalysisStage(_CutClient('{"indicators": [{"val'), "fake", _Store()).run(
        {"preprocessed": {"combined_text": "a report"}, "attack_vector": {}})
    assert context["extraction"]["indicators"] == [] and context["extraction"].get("salvaged") is None


def test_the_row_records_the_salvage():
    from backend.pipeline.orchestrator import PipelineOrchestrator
    from eval.run_eval import DIAGNOSIS_FIELDS
    assert "analysis_salvaged" in DIAGNOSIS_FIELDS
    import inspect
    assert "analysis_salvaged" in inspect.getsource(PipelineOrchestrator)


def test_windows_paths_and_escaped_quotes_inside_strings():
    text = ('{"indicators": [{"value": "C:\\\\Windows\\\\System32\\\\dxdiag.exe", "type": "file_path"}, '
            '{"value": "say \\"hi, there\\"", "type": "other"}, {"value": "C:\\\\Win')
    kept = salvage_json(text)["indicators"]
    assert [i["value"] for i in kept] == ["C:\\Windows\\System32\\dxdiag.exe", 'say "hi, there"']
