"""Offline tests for Change 31 (plan 2.7): technique IDs that do not exist in ATT&CK are
dropped from the analysis stage's list, and recorded.

Why: the analysis stage writes IDs ATT&CK does not have — in a loop, T1562.001 → T1562.339
(defect 19). Like the rule-id check (Change 9), code validates against a specification
(the local ATT&CK collection: 216 techniques, 475 sub-techniques) and records what it
removed; it never invents or repairs an ID (an invalid sub-technique is not truncated to
its parent). The valid IDs are a committed list built from that collection, so the check
and its measure (`eval/count_techniques.py`) read the same file.
"""

from __future__ import annotations

import json

from backend.pipeline.attack_ids import (
    ATTACK_IDS_PATH,
    ids_from_metadatas,
    load_attack_ids,
    split_known,
)
from backend.pipeline.orchestrator import PipelineOrchestrator
from backend.pipeline.stage_analysis import AnalysisStage
from eval.count_techniques import VALID_IDS_PATH
from eval.run_eval import DIAGNOSIS_FIELDS

VALID = {"T1059", "T1059.001", "T1562.001", "T1190"}


def _m(tid):
    return {"technique_id": tid, "technique_name": "n", "tactic": "t"}


def test_valid_ids_are_kept_in_order_and_invalid_ones_recorded():
    kept, dropped = split_known([_m("T1190"), _m("T1562.339"), _m("t1059.001")], VALID)
    assert [m["technique_id"] for m in kept] == ["T1190", "t1059.001"]
    assert dropped == ["T1562.339"]


def test_an_invalid_sub_technique_is_dropped_not_repaired():
    kept, dropped = split_known([_m("T1059.999")], VALID)
    assert kept == [] and dropped == ["T1059.999"]


def test_entries_without_a_usable_id_are_dropped_and_recorded():
    kept, dropped = split_known([{"technique_name": "x"}, "T1190", _m("  ")], VALID)
    assert kept == [] and dropped == ["", "T1190", ""]


def test_kept_entries_are_the_models_own_unchanged():
    m = _m("T1190")
    kept, _ = split_known([m], VALID)
    assert kept[0] is m


def test_ids_come_from_the_collections_metadata():
    mds = [{"external_id": "T1190"}, {"external_id": "t1059.001"}, {"external_id": "TA0001"},
           {"external_id": ""}, {}, None]
    assert ids_from_metadatas(mds) == ["T1059.001", "T1190"]


def test_the_committed_list():
    ids = load_attack_ids()
    assert len(ids) == 691
    assert {"T1562.001", "T1059.001", "T1190"} <= ids
    assert "T1562.339" not in ids


def test_the_check_and_its_measure_read_the_same_file():
    assert ATTACK_IDS_PATH == VALID_IDS_PATH


# --- where it applies ------------------------------------------------------

class _Client:
    model_name = "fake"

    def generate(self, prompt, **kwargs):
        return json.dumps({"indicators": [], "logsource_suggestions": [],
                           "ttp_mappings": [_m("T1190"), _m("T1562.339")]})


class _NoRag:
    def search(self, *args, **kwargs):
        return {}


def test_the_analysis_stage_drops_and_records():
    ctx = {"preprocessed": {"combined_text": "text", "segments": [], "url_content": []}}
    out = AnalysisStage(_Client(), "fake", _NoRag()).run(ctx)
    assert [m["technique_id"] for m in out["ttp_mapping"]["mappings"]] == ["T1190"]
    assert out["ttp_mapping"]["dropped_ids"] == ["T1562.339"]


def test_the_dropped_ids_reach_the_result_rows():
    meta = PipelineOrchestrator(None, "fake", vector_store=None)._format_output(
        {"ttp_mapping": {"mappings": [], "dropped_ids": ["T1562.339"]}})["pipeline_metadata"]
    assert meta["ttp_dropped_ids"] == ["T1562.339"]
    assert "ttp_dropped_ids" in DIAGNOSIS_FIELDS
