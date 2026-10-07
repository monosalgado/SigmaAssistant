"""Tests for #6's measurement (pipeline quality; user 2026-10-07: "do ... the second step" - honest labels and fewer
imperatives, the prompt review's P2/P3): are the attack-vector stage's payload signatures in the report, and do the ones
that are not reach the rules anyway?

The rule writer is told the signatures are "strings/patterns a real attacker MUST produce", and the coverage retry that
each missed one "MUST literally" appear in a rule. Per signature: **in the report** (its literal text, regex escapes
undone and defanging - `[.]`, `hxxp` - ignored, appears in the report's text), **in parts** (a regex whose literal
fragments of >= 4 characters all appear), **not in the report**, and whether the stage marked it `inferred_from_class`;
then whether the final rules use it (the pipeline's own coverage record, `payload_signatures_covered`). Offline;
made-up rows.
"""

from __future__ import annotations

from eval.signature_grounding import literal, run_counts, signature_status

REPORT = "The actor sent hxxps://evil[.]example/dl.php?id=7 and ran cmd.exe /c whoami, then rundll32.exe x.dll,Start."


def test_regex_escapes_are_undone_and_defanging_ignored():
    assert literal("hxxps://evil\\.example/dl\\.php") == "https://evil.example/dl.php"
    assert literal("cmd\\.exe /c whoami") == "cmd.exe /c whoami"


def test_a_signature_is_in_the_report_in_parts_or_not():
    assert signature_status("https://evil\\.example/dl\\.php", REPORT) == "in the report"
    assert signature_status("rundll32\\.exe .*,Start", REPORT) == "in parts"
    assert signature_status("powershell -enc [A-Za-z0-9]+", REPORT) == "not in the report"
    assert signature_status("cmd\\.exe /c whoami", REPORT.upper()) == "in the report"    # case does not matter


def test_a_run_counts_statuses_and_their_use_by_the_rules():
    row = {"rule_id": "a", "pipeline": {
        "attack_vector": {"payload_signatures": [
            {"pattern": "cmd\\.exe /c whoami", "derived_from": "quote"},
            {"pattern": "powershell -enc [A-Za-z0-9]+", "derived_from": "inferred_from_class"},
            {"pattern": "/invented/path\\.aspx", "derived_from": "made up"}]},
        "coverage_check": {"payload_signatures_covered": ["powershell -enc [A-Za-z0-9]+", "/invented/path\\.aspx"]}}}
    counts = run_counts([row], {"a": REPORT})
    assert counts["signatures"] == 3 and counts["cases"] == 1
    assert counts["status"] == {"in the report": 1, "in parts": 0, "not in the report": 2}
    assert counts["used"] == {"in the report": 0, "in parts": 0, "not in the report": 2}
    assert counts["inferred_from_class"] == 1 and counts["not_in_report_not_inferred"] == 1
    assert counts["not_in_report_not_inferred_used"] == 1


def test_doubled_backslashes_are_read_as_one():
    # Found reading the first output (2026-10-07): real Windows paths written with doubled backslashes were counted
    # "not in the report" (`C:\\Users\\public\\...` against the report's `C:\Users\public\...`).
    report = "It ran C:\\Users\\public\\test\\wermgr.exe from \\\\192.168.1.215\\smb\\addCube.dll"
    assert signature_status("C:\\\\Users\\\\public\\\\test\\\\wermgr\\.exe", report) == "in the report"
    assert signature_status("\\\\\\\\192\\.168\\.1\\.215\\\\smb\\\\addCube\\.dll", report) == "in the report"
