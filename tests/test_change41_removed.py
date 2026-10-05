"""Change 41 removed (user 2026-10-04: "remove change 41").

The evidence step passed its tuning gate (S5vu +0.026 [-0.013, +0.069]) but was not confirmed on confirmation set 2
(60 fresh cases, 3 runs per arm: S5vu -0.005 [-0.039, +0.025]); it cost ~31 s and ~11,000 tokens per case and more
retries. The pipeline goes back to `cde43ed`: no evidence step, payload signatures shown up to 10. Kept: Change 39,
the record of indicator use, and the diagnosis tool's reading of the evidence record in saved runs. Offline.
"""

from __future__ import annotations

import importlib.util
import inspect
from pathlib import Path

from backend.pipeline import prompts
from backend.pipeline.stage_attack_vector import AttackVectorStage


def test_there_is_no_evidence_step():
    assert importlib.util.find_spec("backend.pipeline.stage_evidence") is None
    assert not hasattr(prompts, "EVIDENCE_EXTRACTION")
    from backend.pipeline.orchestrator import PipelineOrchestrator
    for method in (PipelineOrchestrator.run_sync, PipelineOrchestrator._analysis_events):
        assert "self.evidence" not in inspect.getsource(method)


def test_the_rule_writer_sees_up_to_ten_payload_signatures_again():
    av = {"payload_signatures": [{"pattern": f"p{i}", "where": "w", "derived_from": "d"} for i in range(20)]}
    assert len(AttackVectorStage.format_payload_signatures(av).splitlines()) == 10


def test_the_harness_and_the_app_no_longer_list_the_step():
    from eval.run_eval import DIAGNOSIS_FIELDS
    assert "evidence" not in DIAGNOSIS_FIELDS and "indicator_use" in DIAGNOSIS_FIELDS
    script = (Path(__file__).resolve().parent.parent / "frontend" / "script.js").read_text(encoding="utf-8")
    assert "id: 'evidence'" not in script


def test_change_39_stays():
    from eval.count_example_copies import INLINE_EXAMPLES
    assert not any(e in prompts.ATTACK_VECTOR_EXTRACTION.lower() for e in INLINE_EXAMPLES)
