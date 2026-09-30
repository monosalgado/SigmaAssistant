"""Tests for Change 38 v3 (user 2026-09-30: "Separate AI step"): after the analysis answer, a short
second model call ranks the candidate log sources by the evidence each would record.

Why (tuning set): the analysis finds the evidence and, with a strict definition, judges which items are
specific to the attack - but within its one long answer it does not rank by its own judgements
(Operation Triangulation: 15 specific domains for the network log, 1 for the process log; the process log
stayed first). A small, separate comparison is the model's only task here.

The model decides the order; code only checks: an added log source must be one SigmaHQ's rules use
(`on_table`, Sigma's service convention first), every earlier suggestion is kept, and if the call fails
the analysis's order stands. Offline: stand-in clients; no LLM.
"""

from __future__ import annotations

import json

from backend.pipeline import prompts
from backend.pipeline.stage_logsource_ranking import LogSourceRankingStage

TABLE = {"with_category": [{"category": "process_creation", "products": ["windows"], "fields": []},
                           {"category": "network_connection", "products": ["windows"], "fields": []},
                           {"category": "file_event", "products": ["windows"], "fields": []}],
         "without_category": [{"product": "windows", "service": "security", "fields": []}]}

SUGGESTIONS = [
    {"category": "process_creation", "product": "windows", "service": None, "evidence": ["BackupAgent"],
     "reasoning": "processes", "confidence": 0.95},
    {"category": "network_connection", "product": "windows", "service": None,
     "evidence": ["evil-c2.net", "bad-cdn.com"], "reasoning": "C2", "confidence": 0.9},
]
INVENTORY = [{"evidence": "BackupAgent", "log_source": "process_creation / windows", "specific": False},
             {"evidence": "evil-c2.net", "log_source": "network_connection / windows", "specific": True},
             {"evidence": "4698", "log_source": "windows / security", "specific": True}]


class _Client:
    model_name = "fake"

    def __init__(self, answer=None, fail=False):
        self.answer, self.fail, self.prompts = answer, fail, []

    def generate(self, prompt, **kwargs):
        self.prompts.append(prompt)
        if self.fail:
            raise RuntimeError("timed out")
        return json.dumps(self.answer)


def _rank(answer=None, fail=False, suggestions=SUGGESTIONS, inventory=INVENTORY):
    client = _Client(answer, fail)
    stage = LogSourceRankingStage(client, "fake")
    ranked, record = stage.rank(suggestions, inventory, TABLE, known_services={("windows", "security")})
    return ranked, record, client


def _names(suggestions):
    return [(s.get("category"), s.get("product"), s.get("service")) for s in suggestions]


# --- the prompt ----------------------------------------------------------------------------

def test_the_prompt_asks_only_for_an_order_by_false_positives():
    t = " ".join(prompts.LOGSOURCE_RANKING.lower().split())     # a phrase may wrap across lines
    assert "fewest false positives" in t
    assert "specific" in t and "normal activity" in t
    for name in ("process_creation", "webserver", "file_event", "security"):
        assert name not in t, name          # no log source named as the default


def test_the_prompt_shows_each_candidate_with_its_evidence_and_the_inventory():
    _, _, client = _rank({"ranking": [], "reason": ""})
    sent = client.prompts[0]
    assert "network_connection" in sent and "evil-c2.net" in sent
    assert "4698" in sent and "specific: true" in sent.lower()


# --- the order -----------------------------------------------------------------------------

def test_the_suggestions_follow_the_models_order_and_keep_their_details():
    ranked, record, _ = _rank({"ranking": [{"category": "network_connection", "product": "windows"},
                                           {"category": "process_creation", "product": "windows"}],
                               "reason": "15 specific domains"})
    assert _names(ranked) == [("network_connection", "windows", None), ("process_creation", "windows", None)]
    assert ranked[0]["reasoning"] == "C2" and ranked[0]["evidence"] == ["evil-c2.net", "bad-cdn.com"]
    assert record["changed_top"] is True and record["reason"] == "15 specific domains"


def test_a_suggestion_the_model_leaves_out_is_kept_at_the_end():
    ranked, _, _ = _rank({"ranking": [{"category": "network_connection", "product": "windows"}], "reason": ""})
    assert _names(ranked) == [("network_connection", "windows", None), ("process_creation", "windows", None)]


def test_a_log_source_the_evidence_points_to_can_be_added_if_sigmahq_uses_it():
    ranked, record, _ = _rank({"ranking": [{"product": "windows", "service": "security", "evidence": ["4698"]},
                                           {"category": "network_connection", "product": "windows"}],
                               "reason": "event 4698 is the task creation itself"})
    assert _names(ranked)[0] == (None, "windows", "security")
    assert ranked[0]["evidence"] == ["4698"] and ranked[0]["added_by"] == "logsource_ranking"
    assert record["added"] == ["windows/security"]


def test_a_log_source_sigmahq_does_not_use_is_not_added():
    ranked, record, _ = _rank({"ranking": [{"category": "made_up", "product": "ios"},
                                           {"category": "network_connection", "product": "windows"}],
                               "reason": ""})
    assert _names(ranked) == [("network_connection", "windows", None), ("process_creation", "windows", None)]
    assert record["dropped"] == ["made_up/ios"]


def test_if_the_call_fails_the_analysis_order_stands():
    ranked, record, _ = _rank(fail=True)
    assert _names(ranked) == _names(SUGGESTIONS)
    assert record["changed_top"] is False and "timed out" in record["error"]


def test_no_suggestions_means_no_call():
    ranked, record, client = _rank({"ranking": []}, suggestions=[], inventory=[])
    assert ranked == [] and record["ran"] is False and client.prompts == []


# --- inside the pipeline -------------------------------------------------------------------

def test_the_analysis_stage_ranks_its_suggestions_and_records_it():
    from backend.pipeline.stage_analysis import AnalysisStage
    from backend.telemetry import TELEMETRY
    from eval.run_eval import DIAGNOSIS_FIELDS

    class _Seq:
        model_name = "fake"

        def __init__(self):
            self.calls = 0

        def generate(self, prompt, **kwargs):
            from backend.telemetry import TELEMETRY as T
            self.calls += 1
            T.record(backend="fake", tier="economy", model="m", operation="generate", latency_s=0.1,
                     prompt_chars=len(prompt))
            if self.calls == 1:
                return json.dumps({"indicators": [], "attack_summary": "s", "ttp_mappings": [],
                                   "evidence_inventory": INVENTORY, "logsource_suggestions": SUGGESTIONS,
                                   "logsource_primary": "process_creation / windows"})
            return json.dumps({"ranking": [{"category": "network_connection", "product": "windows"}],
                               "reason": "domains"})

    class _Store:
        def __getattr__(self, name):
            return lambda *a, **k: {}

    TELEMETRY.reset()
    context = AnalysisStage(_Seq(), "fake", _Store()).run({"preprocessed": {"combined_text": "t"},
                                                           "attack_vector": {}})
    assert context["logsource_suggestion"]["suggestions"][0]["category"] == "network_connection"
    assert context["logsource_suggestion"]["ranking"]["changed_top"] is True
    assert [c["stage"] for c in TELEMETRY.as_dicts()] == ["analysis", "logsource_ranking"]
    assert "logsource_ranking" in DIAGNOSIS_FIELDS
