"""Tests for `eval/evtx_inventory.py` (the recorded-log plan, step 1; user 2026-10-19): an inventory of public EVTX
recordings by identifiers only - collection, top folder, CVE IDs and ATT&CK technique IDs in the file path, plus CVE IDs
a collection's README table associates with a name that appears in the file name - and their match to our reports by
CVE (report-level candidates) and by technique (technique-level). Offline; a made-up tree."""

from __future__ import annotations

from eval.evtx_inventory import ids_in, inventory, match, readme_aliases

README = """
Tactic | Technique | Description | Event IDs | Tool or CVE
TA0004 | T1547.010 | something | 800 | Widget (CVE-2021-1111 / CVE-2021-2222)
TA0006 | T1003 | other | 4662 | SomeTool
"""


def test_ids_in_a_path():
    assert ids_in("Folder/T1003.001 thing (CVE-2020-1234).evtx") == ({"CVE-2020-1234"}, {"T1003.001"})
    assert ids_in("TA0004-Privilege Escalation/x.evtx") == (set(), set())        # a tactic id is not a technique


def test_readme_names_become_cve_aliases():
    assert readme_aliases(README) == {"widget": {"CVE-2021-1111", "CVE-2021-2222"}}


def test_inventory_and_matching(tmp_path):
    a = tmp_path / "CollA"
    (a / "Priv").mkdir(parents=True)
    (a / "README.md").write_text(README)
    for name in ("Priv/x (Widget).evtx", "Priv/y CVE-2020-1234.evtx", "Priv/z T1059.evtx", "Priv/notes.txt"):
        (a / name).write_bytes(b"")
    recs = inventory(tmp_path)
    assert len(recs) == 3
    by = {r["file"].split("/")[-1]: r for r in recs}
    assert by["x (Widget).evtx"]["cves"] == ["CVE-2021-1111", "CVE-2021-2222"]
    assert by["y CVE-2020-1234.evtx"]["cves"] == ["CVE-2020-1234"] and by["z T1059.evtx"]["techniques"] == ["T1059"]
    reports = [{"rule_id": "r1", "cves": {"CVE-2021-2222"}, "techniques": {"T1059.001"}},
               {"rule_id": "r2", "cves": set(), "techniques": {"T1003"}}]
    m = match(recs, reports)
    assert m["r1"]["same_cve"] == ["CollA/Priv/x (Widget).evtx"]
    assert m["r1"]["same_technique"] == ["CollA/Priv/z T1059.evtx"]                 # parent technique counts
    assert m["r2"] == {"same_cve": [], "same_technique": []}
