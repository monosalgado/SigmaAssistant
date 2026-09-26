"""Offline tests for eval/count_techniques.py — the measures of Changes 31 (plan 2.7, the
ATT&CK ID check) and 32 (plan 2.8, at most 10 techniques), fixed before their run.

What the model WROTE is counted, not what survives the check: after Change 31 the
analysis stage keeps valid IDs in `ttp_mappings` and records the rest in
`ttp_dropped_ids`, so written = kept + dropped, and "invented" = written IDs that ATT&CK
does not have. Rule tags are counted separately (S4 scores the rule's tags).
"""

from __future__ import annotations

import json

from eval.count_techniques import (
    case_measures,
    load_valid_ids,
    rule_tag_ids,
    summarise,
    technique_ids,
    written_ids,
)

VALID = {"T1059", "T1059.001", "T1562.001", "T1190"}
RULE = "title: x\ntags:\n    - attack.execution\n    - attack.t1059.001\n    - attack.t1562.339\n"


def _row(mappings=(), dropped=None, rules=(), cut=0):
    pipeline = {"ttp_mappings": list(mappings)}
    if dropped is not None:
        pipeline["ttp_dropped_ids"] = list(dropped)
    return {"rule_id": "r", "pipeline": pipeline, "rules_yaml": list(rules),
            "telemetry": {"calls_output_limited": cut}}


def test_technique_ids_are_normalised_and_blanks_skipped():
    assert technique_ids([{"technique_id": " t1059.001 "}, {"technique_id": ""}, {"x": 1},
                          "T1190"]) == ["T1059.001"]


def test_written_ids_include_what_the_check_dropped():
    row = _row([{"technique_id": "T1190"}], dropped=["T1562.339"])
    assert written_ids(row) == ["T1190", "T1562.339"]


def test_rows_from_before_the_check_have_no_dropped_field():
    assert written_ids(_row([{"technique_id": "T1562.339"}])) == ["T1562.339"]


def test_rule_tag_ids_read_every_rule_and_skip_broken_yaml():
    row = _row(rules=[RULE, "title: [broken", "title: y\ntags: [attack.t1190]"])
    assert rule_tag_ids(row) == {"T1059.001", "T1562.339", "T1190"}


def test_case_measures():
    row = _row([{"technique_id": "T1059.001"}, {"technique_id": "T1562.339"}],
               dropped=["T9999"], rules=[RULE], cut=2)
    m = case_measures(row, VALID)
    assert m == {"written": 3, "invalid": ["T1562.339", "T9999"],
                 "rule_invalid": ["T1562.339"], "cut": 2}


def test_summary():
    ms = [{"written": 3, "invalid": ["T9"], "rule_invalid": [], "cut": 0},
          {"written": 12, "invalid": [], "rule_invalid": ["T8"], "cut": 1},
          {"written": 5, "invalid": ["T7", "T6"], "rule_invalid": [], "cut": 0}]
    s = summarise(ms)
    assert (s["n"], s["median"], s["max"], s["over_10"]) == (3, 5, 12, 1)
    assert (s["invalid_cases"], s["invalid_total"], s["rule_invalid_cases"], s["cut_cases"]) == (2, 3, 1, 1)


def test_exactly_ten_techniques_is_not_over_the_limit():
    """Change 32 asks for at most 10: ten is within it."""
    ms = [{"written": 10, "invalid": [], "rule_invalid": [], "cut": 0},
          {"written": 11, "invalid": [], "rule_invalid": [], "cut": 0}]
    assert summarise(ms)["over_10"] == 1


def test_valid_ids_load_from_a_json_list(tmp_path):
    path = tmp_path / "ids.json"
    path.write_text(json.dumps(["T1190", "t1059.001"]), encoding="utf-8")
    assert load_valid_ids(path) == {"T1190", "T1059.001"}
