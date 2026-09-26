"""Offline tests for Change 27 (plan 2.3, step d): the attack-vector prompt's web bias.

After Change 26 the attack-vector stage still labelled 18 of 46 non-web cases with
web telemetry; 4 of those vectors contained the prompt's own Example A text (e.g. a
Windows implant described as "HTTP POST to /saml/login"). Two of the three worked
examples were web exploits, Example A was written from one real past case (Citrix,
`NSC_TASS`), and `primary_telemetry` was defined as where "the initial exploit" is
visible — even for reports that describe no exploit. Prompt changes only: the model
still decides (user, 2026-09-25).
"""

from __future__ import annotations

import json
import re

from backend.pipeline import prompts
from eval.probe_attack_vector import EXAMPLE_MARKERS

AV = prompts.ATTACK_VECTOR_EXTRACTION
HOST = {"process_creation", "file_event", "registry_event"}
FIELDS = {"initial_access_vector", "protocol", "entry_point", "attacker_controlled_input",
          "preconditions", "vuln_class", "cwe_hint", "cvss_attack_vector", "payload_signatures",
          "primary_telemetry", "secondary_telemetry", "kill_chain_stages",
          "incidental_artifacts", "confidence", "reasoning"}


def _examples() -> list:
    """The worked examples' JSON, with the template's doubled braces undone."""
    section = AV.split("### Few-shot Examples", 1)[1]
    blocks = re.findall(r"Output \(abbreviated\):\n(\{\{.*?\n\}\})", section, re.S)
    return [json.loads(b.replace("{{", "{").replace("}}", "}")) for b in blocks]


def test_the_real_case_example_is_gone():
    for s in ("/saml/login", "SAMLRequest", "NSC_TASS", "patch.nss"):
        assert s not in AV, s


def test_the_examples_are_balanced_one_web_two_host():
    telemetry = [e["primary_telemetry"] for e in _examples()]
    assert len(telemetry) == 3
    assert telemetry.count("webserver_access_log") == 1
    assert sum(t in HOST for t in telemetry) == 2


def test_every_example_is_valid_json_with_every_field():
    for e in _examples():
        assert FIELDS <= set(e), FIELDS - set(e)


def test_an_example_has_no_network_exploit_at_all():
    """The case the stage handled worst: malware delivered to a user, seen on the host."""
    assert any(e["protocol"] == "email" and e["primary_telemetry"] in HOST for e in _examples())


def test_primary_telemetry_is_where_the_described_activity_is_seen():
    line = next(l for l in AV.splitlines() if l.startswith("- `primary_telemetry`"))
    assert "Where the initial exploit would be visible." not in line
    assert "malware" in line and "`process_creation`" in line
    assert "Decide from what the text actually describes" in line


def test_the_stage_is_told_not_to_invent_a_network_request():
    line = next(l for l in AV.splitlines() if l.startswith("- `initial_access_vector`"))
    assert "never invent a network request the text does not mention" in line


def test_the_copy_markers_cover_the_new_example():
    """Its invented names are counted as copies, like the old examples' were."""
    new = EXAMPLE_MARKERS["email_iso_lnk"]
    assert new and all(m in AV.lower() for m in new)
