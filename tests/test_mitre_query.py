"""Tests for #1 (pipeline quality, user 2026-10-05): the analysis stage searches ATT&CK with the attack-vector summary
followed by the start of the text, not the start of the text alone.

Why (tuning set, `probe_mitre_query.py` on `c41A_tuning60`): the first 500 characters are mostly the input URLs and a
site menu; a gold technique is among the 5 results in 3 of 42 cases, against 14 of 42 for the summary followed by
the text (12 for the summary alone). The summary first keeps the search useful when the page opens with a menu; the
text after it keeps it useful when the attack-vector stage found nothing. Offline: stand-in store and client.
"""

from __future__ import annotations

import json

from backend.pipeline.stage_analysis import AnalysisStage
from backend.pipeline.stage_attack_vector import AttackVectorStage


class _Store:
    def __init__(self):
        self.queries = []

    def search(self, query, collections=None, n_results=5):
        self.queries.append((query, collections))
        return {}


class _Client:
    model_name = "fake"

    def generate(self, prompt, **kwargs):
        return json.dumps({"indicators": [], "attack_summary": "s", "ttp_mappings": [], "logsource_suggestions": [],
                           "logsource_primary": ""})


AV = {"initial_access_vector": "a phishing email with an LNK attachment", "vuln_class": "other", "protocol": "smtp"}
TEXT = "https://x.example/report\nHome | News | Menu\nThe actor sent LNK files..."


def _mitre_query(attack_vector):
    store = _Store()
    AnalysisStage(_Client(), "fake", store).run({"preprocessed": {"combined_text": TEXT}, "attack_vector": attack_vector})
    return next(q for q, cols in store.queries if cols == ["mitre"])


def test_the_attack_vector_summary_comes_first_then_the_start_of_the_text():
    query = _mitre_query(AV)
    summary = AttackVectorStage.format_vector_summary(AV)
    assert query.startswith(summary) and query.endswith(TEXT[:500])


def test_without_an_attack_vector_the_text_still_reaches_the_search():
    assert TEXT[:500] in _mitre_query({})
