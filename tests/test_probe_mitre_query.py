"""Tests for diagnosing the analysis stage's ATT&CK retrieval (#1, user 2026-10-05: "go in that order").

The analysis searches the ATT&CK collection with `combined_text[:500]` - often the input URLs and a site menu
(Inbox, retrieval check b). The probe runs that search and the candidates fixed before looking (the attack-vector
summary the stage already has; the summary followed by the current text) and asks, per case, whether the gold rule's
techniques are among the 5 results - exact, and with sub-techniques collapsed onto their parent (as S4). Offline:
a stand-in store; no LLM.
"""

from __future__ import annotations

from eval.probe_mitre_query import QUERIES, gold_techniques, recall, retrieved_ids, run_queries


def test_gold_techniques_come_from_the_rules_tags():
    rule = {"tags": ["attack.execution", "attack.t1059.001", "attack.t1218", "cve.2024-1"]}
    assert gold_techniques(rule) == {"t1059.001", "t1218"}


def test_recall_exact_and_by_parent():
    gold, got = {"t1059.001", "t1218"}, {"t1059", "t1218", "t1105"}
    assert recall(gold, got) == 0.5
    assert recall(gold, got, parent=True) == 1.0
    assert recall(set(), got) is None


def test_retrieved_ids_are_read_from_the_metadata():
    result = {"mitre": {"metadatas": [[{"external_id": "T1059.001"}, {"external_id": "T1218"}, {}]]}}
    assert retrieved_ids(result) == ["t1059.001", "t1218"]


def test_the_candidate_queries_are_fixed():
    assert list(QUERIES) == ["current", "vector_summary", "both"]
    ctx = {"text": "https://x.example/a\nHome | News | Menu\n" + "body " * 200,
           "attack_vector": {"initial_access_vector": "phishing LNK", "vuln_class": "other", "protocol": "smtp"}}
    assert QUERIES["current"](ctx) == ctx["text"][:500]
    assert "phishing LNK" in QUERIES["vector_summary"](ctx)
    assert QUERIES["both"](ctx).startswith(QUERIES["vector_summary"](ctx))


class _Store:
    def __init__(self):
        self.queries = []

    def search(self, query, collections=None, n_results=5):
        self.queries.append(query)
        ids = ["T1566.001", "T1204"] if "phishing" in query else ["T1595"]
        return {"mitre": {"metadatas": [[{"external_id": i} for i in ids]]}}


def test_each_query_is_run_and_scored_against_the_gold():
    ctx = {"text": "https://x.example/a menu", "attack_vector": {"initial_access_vector": "phishing LNK"}}
    out = run_queries(_Store(), ctx, {"t1566.001"})
    assert out["current"]["recall"] == 0.0 and out["vector_summary"]["recall"] == 1.0
    assert out["vector_summary"]["retrieved"] == ["t1566.001", "t1204"]
