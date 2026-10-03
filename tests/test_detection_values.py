"""Tests for S5v, a value-level detection score (roadmap R8; user 2026-10-03: "do 1 and 2").

S5 compares field names only, so a rule matching the wrong process with the right field scores as well as the
right rule: on the tuning set, a Sitecore rule that looks for `cmd=` and `$(nslookup` scores S5 = 0.67 against a
human rule that matches the vulnerable page. S5v compares the values the detection looks for.

Definition (fixed before any run is scored):
- values: every string or number in the detection, lower-cased, `*` wildcards at the ends removed, a doubled
  backslash read as one; the field is the name before the first `|` (as S5); a bare keyword list has field "";
  selections named `filter...` (SigmaHQ's convention for exclusions), `condition` and `timeframe` are skipped
- a human value g is found by one of our values p when p contains g (ours is at least as specific), or g contains
  p and p is at least half as long; a value shorter than 3 characters only counts when equal
- recall (any field / same field), precision (any field), F1 (any field)
Offline; no LLM.
"""

from __future__ import annotations

from eval.scorers import extract_detection_values, normalise_value, score_detection_values, value_matches


def test_values_are_normalised():
    assert normalise_value("*\\\\Local\\\\Temp\\\\*") == "\\local\\temp\\"
    assert normalise_value("  POST ") == "post"
    assert normalise_value(4698) == "4698"
    assert normalise_value(None) is None


def test_values_come_from_every_selection_except_filters():
    detection = {
        "selection": {"CommandLine|contains|all": ["create", "ONSTART"], "Image|endswith": "\\schtasks.exe"},
        "filter_main_legit": {"Image|endswith": "\\Program Files\\AutoIt3\\AutoIt3.exe"},
        "keywords": ["evil.dll"],
        "timeframe": "5m",
        "condition": "selection and not filter_main_legit",
    }
    assert extract_detection_values(detection) == {
        ("commandline", "create"), ("commandline", "onstart"), ("image", "\\schtasks.exe"), ("", "evil.dll")}


def test_a_list_of_maps_is_read_like_a_map():
    detection = {"selection": [{"Image|endswith": "\\Autoit3.exe"}, {"OriginalFileName": "AutoIt3.exe"}],
                 "condition": "selection"}
    assert extract_detection_values(detection) == {("image", "\\autoit3.exe"), ("originalfilename", "autoit3.exe")}


def test_a_human_value_is_found_by_an_equal_or_more_specific_value():
    assert value_matches("\\local\\temp\\", "c:\\users\\x\\appdata\\local\\temp\\")
    assert value_matches(".txt", "errors.txt")
    assert value_matches("4698", "4698")


def test_a_broader_value_counts_only_when_it_is_at_least_half_as_long():
    assert value_matches("\\rundll32.exe", "rundll32.exe")
    assert not value_matches("-encodedcommand", "-enc")


def test_a_very_short_value_counts_only_when_equal():
    assert not value_matches(";", "; ls")
    assert value_matches(";", ";")


def test_the_right_fields_with_the_wrong_values_score_low():
    gold = {"selection": {"cs-method": "POST",
                          "cs-uri-query|contains": "/sitecore/shell/ClientBin/Reporting/Report.ashx",
                          "sc-status": 200}, "condition": "selection"}
    ours = {"selection_uri": {"cs-uri-query|contains": "cmd="},
            "selection_body": {"cs-method": ["POST", "PUT"],
                               "request_body|contains": [";", "$(nslookup", "<parameter>=a[$("]},
            "condition": "1 of selection_*"}
    s = score_detection_values(ours, gold)
    assert s["n_gold"] == 3 and s["n_predicted"] == 6
    assert abs(s["recall"] - 1 / 3) < 1e-9 and abs(s["recall_same_field"] - 1 / 3) < 1e-9
    assert abs(s["precision"] - 1 / 6) < 1e-9
    assert s["missing"] == ["/sitecore/shell/clientbin/reporting/report.ashx", "200"]


def test_the_same_value_in_another_field_counts_only_for_any_field():
    gold = {"selection": {"ParentImage|endswith": "\\msiexec.exe"}, "condition": "selection"}
    ours = {"selection": {"Image|endswith": "\\msiexec.exe"}, "condition": "selection"}
    s = score_detection_values(ours, gold)
    assert s["recall"] == 1.0 and s["recall_same_field"] == 0.0 and s["f1"] == 1.0


def test_no_values_on_a_side_leaves_the_score_undefined():
    s = score_detection_values({"condition": "selection"}, {"selection": {"Image": "x.exe"}, "condition": "selection"})
    assert s["recall"] == 0.0 and s["precision"] is None and s["f1"] is None
    assert score_detection_values(None, None)["recall"] is None
