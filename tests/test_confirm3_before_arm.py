"""Confirmation set 3, arm A (branch `confirm3-before`, never merged): `main` at `2ece908` with Change 42 taken out -
the analysis stage searches ATT&CK with the first 500 characters of the text, as before Change 42. Everything else is
`main` (Change 43 removed, Change 44 in, cut answers' tails recorded), so the two arms differ only by the query.
Change 42's own test (`test_mitre_query.py`) is deleted on this branch. Offline: stand-in store and client.
"""

from __future__ import annotations

import json

from backend.pipeline.stage_analysis import AnalysisStage


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


def test_the_attack_search_is_the_start_of_the_text_only():
    text = "https://x.example/report\nHome | News | Menu\nThe actor sent LNK files..." * 20
    store = _Store()
    av = {"initial_access_vector": "a phishing email with an LNK attachment", "vuln_class": "other"}
    AnalysisStage(_Client(), "fake", store).run({"preprocessed": {"combined_text": text}, "attack_vector": av})
    assert next(q for q, cols in store.queries if cols == ["mitre"]) == text[:500]
