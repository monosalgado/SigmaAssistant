"""Change 38 removed (user 2026-10-03: "remove Change 38, keep Change 37").

Three iterations on the tuning set did not move the analysis stage's top log-source pick towards the human
rules; v3's ranking step moved it away more often than towards (log 2026-10-03). The analysis goes back to its
pre-Change-38 form: one model call, the earlier log-source instruction, no evidence inventory, no ranking step.
Change 37 (the JSON escape repair) stays. Offline: stand-in client; no LLM.
"""

from __future__ import annotations

import importlib.util
import json

from backend.pipeline import prompts


def _part3() -> str:
    t = prompts.COMBINED_ANALYSIS
    return " ".join(t[t.index("## PART 3: Log Source Recommendation"):t.index("### Output Format")].split())


def test_the_analysis_prompt_has_its_earlier_log_source_instruction():
    assert "Determine the best Sigma log sources for detecting this attack" in _part3()
    assert "evidence_inventory" not in prompts.COMBINED_ANALYSIS
    assert "most specific evidence" not in _part3()


def test_there_is_no_ranking_step():
    assert not hasattr(prompts, "LOGSOURCE_RANKING")
    assert importlib.util.find_spec("backend.pipeline.stage_logsource_ranking") is None


def test_the_analysis_makes_one_model_call_and_saves_no_ranking():
    from backend.pipeline.stage_analysis import AnalysisStage
    from eval.run_eval import DIAGNOSIS_FIELDS

    class _Client:
        model_name = "fake"

        def __init__(self):
            self.calls = 0

        def generate(self, prompt, **kwargs):
            self.calls += 1
            return json.dumps({"indicators": [], "attack_summary": "s", "ttp_mappings": [],
                               "logsource_suggestions": [{"category": "process_creation", "product": "windows",
                                                          "service": None}],
                               "logsource_primary": "process_creation / windows"})

    class _Store:
        def __getattr__(self, name):
            return lambda *a, **k: {}

    client = _Client()
    context = AnalysisStage(client, "fake", _Store()).run({"preprocessed": {"combined_text": "t"},
                                                           "attack_vector": {}})
    assert client.calls == 1
    assert set(context["logsource_suggestion"]) == {"suggestions", "primary_source"}
    assert "logsource_ranking" not in DIAGNOSIS_FIELDS and "evidence_inventory" not in DIAGNOSIS_FIELDS


def test_change_37_stays():
    from backend.pipeline.base_stage import repair_json_escapes
    assert json.loads(repair_json_escapes('{"p": "C:\\Users\\bob"}')) == {"p": "C:\\Users\\bob"}
