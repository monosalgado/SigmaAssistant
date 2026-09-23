"""Offline tests for the defect-15 measurement's scoring functions.

The run itself needs the Spark; these pin the two definitions every reported
number depends on, so the criteria cannot drift after the results are seen.
"""

from __future__ import annotations

from eval.probe_attack_vector import leaked_markers, normalise, quote_found


def test_example_string_absent_from_input_is_a_leak():
    output = '{"initial_access_vector": "HTTP POST to /saml/login with a crafted SAMLRequest body"}'
    leaks = leaked_markers(output, "Defrag was disabled via schtasks on the host.")
    assert leaks == {"saml": ["/saml/login", "samlrequest"]}


def test_example_string_present_in_input_is_not_a_leak():
    """A write-up that really is about a SAML endpoint must not be counted."""
    output = '{"entry_point": "/saml/login"}'
    assert leaked_markers(output, "The attacker POSTs to /SAML/login repeatedly.") == {}


def test_generic_patterns_are_not_markers():
    """`$(` and `../` are legitimate inferences from a vulnerability class."""
    output = '{"payload_signatures": [{"pattern": "$("}, {"pattern": "../../etc/passwd"}]}'
    assert leaked_markers(output, "unrelated text") == {}


def test_quote_matching_ignores_case_and_whitespace():
    source = normalise("The actor ran\n  schtasks /Change /TN Defrag   /Disable")
    assert quote_found("ran schtasks /change /tn defrag /disable", source)


def test_quote_with_ellipsis_needs_every_fragment():
    source = normalise("The actor ran schtasks. Later the service was stopped.")
    assert quote_found("ran schtasks... the service was stopped", source)
    assert not quote_found("ran schtasks... the service was deleted", source)


def test_paraphrase_is_not_found():
    """A miss means "not verbatim", which is why M2 is only an upper bound."""
    source = normalise("The actor ran schtasks to disable defragmentation.")
    assert not quote_found("the attacker turned off defrag", source)
