"""Offline tests for eval/count_example_copies.py (plan 2.3, measured before Change 27's run).

Counts the attack-vector prompt's example text copied into a finished run's recorded
attack vectors — the defect-15 criterion (`probe_attack_vector.leaked_markers`) applied to
full-run rows. The input the marker must be absent from is the case's extracted text plus
the GitHub code the PoC stage fetched: a superset of what the model saw, so the count is a
lower bound, like the probe's.
"""

from __future__ import annotations

from eval.count_example_copies import (
    copies,
    corpus_hits,
    github_bodies,
    model_input,
    rules_text,
    summarise,
)


def _av(**over):
    av = {"initial_access_vector": "x", "entry_point": "", "attacker_controlled_input": "",
          "payload_signatures": [], "incidental_artifacts": [], "reasoning": ""}
    av.update(over)
    return av


def test_a_marker_in_the_vector_counts_in_the_vector_and_anywhere():
    c = copies(_av(entry_point="/saml/login"), "a Windows implant writes a Run key")
    assert c["in_vector"] == {"saml": ["/saml/login"]}
    assert c["anywhere"] == {"saml": ["/saml/login"]}


def test_a_marker_only_among_incidental_strings_counts_anywhere_only():
    c = copies(_av(incidental_artifacts=[{"value": "patch.nss", "reason": "vendor patch"}]),
               "unrelated text")
    assert c["anywhere"] == {"saml": ["patch.nss"]}
    assert c["in_vector"] == {}


def test_a_marker_that_is_in_the_input_is_not_a_copy():
    c = copies(_av(entry_point="/saml/login"), "the actor POSTs to /SAML/login repeatedly")
    assert c["anywhere"] == {} and c["in_vector"] == {}


def test_the_new_example_is_counted_too():
    c = copies(_av(payload_signatures=[{"pattern": "qx7loader.dll"}]), "a loader DLL")
    assert c["in_vector"] == {"email_iso_lnk": ["qx7loader"]}


def test_fetched_github_code_is_part_of_the_input():
    text = "PoC: https://github.com/acme/poc/blob/main/exploit.py"
    url_map = {"https://raw.githubusercontent.com/acme/poc/main/exploit.py": {"path": "/tmp/x"}}
    bodies = github_bodies(text, url_map, read=lambda path: "requests.post('/saml/login')")
    assert bodies == ["requests.post('/saml/login')"]
    c = copies(_av(entry_point="/saml/login"), model_input(text, bodies))
    assert c["in_vector"] == {}


def test_github_links_without_a_stored_body_add_nothing():
    text = "https://github.com/acme/poc/blob/main/gone.py"
    url_map = {"https://raw.githubusercontent.com/acme/poc/main/gone.py": {"status": 404}}
    assert github_bodies(text, url_map, read=lambda p: "never read") == []


def test_summary_counts_cases_not_markers():
    results = [
        {"rule_id": "a", "anywhere": {"saml": ["/saml/login", "samlrequest"]}, "in_vector": {"saml": ["/saml/login"]}},
        {"rule_id": "b", "anywhere": {"saml": ["patch.nss"]}, "in_vector": {}},
        {"rule_id": "c", "anywhere": {}, "in_vector": {}},
    ]
    s = summarise(results)
    assert (s["n"], s["anywhere"], s["in_vector"]) == (3, 2, 1)
    assert s["by_example_in_vector"] == {"saml": 1}


# --- copies that reach the generated rules (added 2026-09-26, before the defect-15 run) ---
# In the step (d) run the new example's invented names were found in two cases' rules by a
# one-off search; this makes that count committed. Retrieval cannot be the source: no
# marker occurs in any retrieval collection (`--check-retrieval`).

def test_a_marker_in_a_generated_rule_counts_in_rules():
    c = copies(_av(), "a Qakbot report", rules_text="Image|endswith: '\\\\qx7loader.dll'")
    assert c["in_rules"] == {"email_iso_lnk": ["qx7loader"]}


def test_a_marker_in_the_rules_that_is_in_the_input_is_not_a_copy():
    c = copies(_av(), "the loader is saved as qx7loader.dll", rules_text="qx7loader.dll")
    assert c["in_rules"] == {}


def test_no_rules_means_nothing_in_rules():
    assert copies(_av(entry_point="/saml/login"), "text")["in_rules"] == {}


def test_rules_text_joins_a_list_and_accepts_a_string_or_nothing():
    assert rules_text({"rules_yaml": ["title: a", "title: b"]}) == "title: a\ntitle: b"
    assert rules_text({"rules_yaml": "title: a"}) == "title: a"
    assert rules_text({"rules_yaml": None}) == "" and rules_text({}) == ""


def test_summary_counts_cases_with_copies_in_rules():
    results = [
        {"rule_id": "a", "anywhere": {}, "in_vector": {}, "in_rules": {"saml": ["samlrequest"]}},
        {"rule_id": "b", "anywhere": {}, "in_vector": {}, "in_rules": {}},
    ]
    s = summarise(results)
    assert s["in_rules"] == 1 and s["by_example_in_rules"] == {"saml": 1}


def test_corpus_hits_names_the_markers_found_in_reference_texts():
    assert corpus_hits(["a rule about SAMLRequest abuse", "nothing"]) == {"samlrequest": 1}
    assert corpus_hits(["process_creation rule"]) == {}
