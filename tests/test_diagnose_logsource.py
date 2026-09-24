"""Offline tests for the logsource diagnosis (plan task 2.1).

They pin the bucket definitions before the baseline-v2 counts are read, so the
criteria cannot drift after the results are seen.
"""

from __future__ import annotations

import pytest

from eval.diagnose_logsource import (
    bucket,
    corpus_categories,
    diagnose_case,
    gold_in_any_rule,
    is_web_category,
    is_web_telemetry,
    summarise,
    top_suggestion_exact,
)


@pytest.mark.parametrize("gold, rule, offered, expected", [
    ("process_creation", "process_creation", ["process_creation", "file_event"], "right_suggested"),
    ("process_creation", "process_creation", ["file_event", "process_creation"], "right_rescued"),
    ("process_creation", "webserver", ["process_creation", "file_event"], "overridden"),
    ("process_creation", "webserver", ["file_event", "process_creation"], "ranked_low"),
    ("process_creation", "file_event", ["file_event", "webserver"], "followed_wrong"),
    ("process_creation", "webserver", ["file_event", "registry_set"], "wrong_elsewhere"),
])
def test_every_case_lands_in_exactly_one_bucket(gold, rule, offered, expected):
    assert bucket(gold, rule, offered) == expected


def test_comparison_uses_the_scorers_normalisation():
    """Case and surrounding space do not matter, as in S3."""
    assert bucket("process_creation", " Process_Creation", ["PROCESS_CREATION"]) == "right_suggested"


def test_absent_matches_absent_as_in_the_scorer():
    """A gold rule without a category is matched only by a rule without one."""
    assert bucket(None, None, ["process_creation"]) == "right_rescued"
    assert bucket(None, "process_creation", ["process_creation"]) == "followed_wrong"


def test_only_the_first_three_suggestions_count_as_offered():
    """The generation prompt shows only three; a fourth was never offered."""
    offered = ["file_event", "registry_set", "image_load", "process_creation"]
    assert bucket("process_creation", "file_event", offered) == "followed_wrong"


def test_no_suggestions_means_nothing_offered():
    assert bucket("process_creation", "file_event", []) == "wrong_elsewhere"


def _row(rule_cat, gold_cat, suggestions, telemetry="process_creation", rules_yaml=None):
    return {
        "rule_id": "abc",
        "scores": {"logsource": {"per_field": {
            "category": {"predicted": rule_cat, "gold": gold_cat},
        }}},
        "pipeline": {
            "logsource_suggestions": [{"category": c} for c in suggestions],
            "attack_vector": {"primary_telemetry": telemetry},
        },
        "rules_yaml": rules_yaml or [],
    }


def test_rule_and_gold_come_from_the_s3_score_so_they_cannot_disagree():
    d = diagnose_case(_row("webserver", "process_creation", ["process_creation"]))
    assert (d["rule"], d["gold"], d["top"]) == ("webserver", "process_creation", "process_creation")
    assert d["bucket"] == "overridden"


def test_a_row_that_s3_does_not_score_is_left_out():
    row = _row("x", "y", [])
    row["scores"]["logsource"] = None
    assert diagnose_case(row) is None
    assert diagnose_case({"rule_id": "abc", "scores": None}) is None


def test_web_definitions():
    assert is_web_category("webserver") and is_web_category("Proxy")
    assert not is_web_category("process_creation") and not is_web_category(None)
    assert is_web_telemetry("webserver_access_log") and is_web_telemetry("waf")
    assert is_web_telemetry("web_proxy")
    assert not is_web_telemetry("network_ids") and not is_web_telemetry(None)


def test_gold_found_in_a_later_rule_of_the_response():
    rules = [
        "title: a\nlogsource:\n  category: webserver\n",
        "not: [valid yaml",
        "title: c\nlogsource:\n  category: Process_Creation\n",
    ]
    assert gold_in_any_rule("process_creation", rules)
    assert not gold_in_any_rule("file_event", rules)


def test_summary_counts_buckets_and_web_mislabels():
    rows = [
        _row("process_creation", "process_creation", ["process_creation"]),
        _row("webserver", "process_creation", ["process_creation"], telemetry="webserver_access_log"),
        _row("webserver", "webserver", ["webserver"], telemetry="webserver_access_log"),
    ]
    s = summarise([diagnose_case(r) for r in rows])
    assert s["n"] == 3
    assert s["buckets"]["right_suggested"] == 2
    assert s["buckets"]["overridden"] == 1
    # web labels where the gold rule is not web: 1 of the 2 non-web cases
    assert s["non_web_gold"] == 2
    assert s["web_telemetry_on_non_web_gold"] == 1
    assert s["web_rule_on_non_web_gold"] == 1
    assert s["web_top_on_non_web_gold"] == 0


# --------------------------------------------------------------------------
# Post-hoc measures, added after the first run (found by reading the
# confusion list); reported separately from the pre-registered buckets.
# --------------------------------------------------------------------------

def test_corpus_categories_are_the_ones_sigmahq_rules_use(tmp_path):
    (tmp_path / "a.yml").write_text("logsource:\n  category: Process_Creation\n  product: windows\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.yml").write_text("logsource:\n  product: windows\n  service: security\n")
    (tmp_path / "c.yml").write_text("not: [valid yaml")
    assert corpus_categories(tmp_path) == {"process_creation"}


def test_top_suggestion_scored_verbatim_with_the_s3_scorer():
    row = _row("webserver", "process_creation", [])
    row["scores"]["logsource"]["per_field"].update({
        "product": {"predicted": "windows", "gold": "windows"},
        "service": {"predicted": None, "gold": None},
    })
    row["pipeline"]["logsource_suggestions"] = [
        {"category": "process_creation", "product": "windows", "service": "sysmon"}]
    assert top_suggestion_exact(row) is False  # the extra service fails, as in S3
    row["pipeline"]["logsource_suggestions"][0]["service"] = None
    assert top_suggestion_exact(row) is True
    row["pipeline"]["logsource_suggestions"] = []
    assert top_suggestion_exact(row) is None


def test_rule_copying_the_attack_vector_label_is_recorded():
    d = diagnose_case(_row("webserver_access_log", "process_creation", ["process_creation"],
                           telemetry="webserver_access_log"))
    assert d["rule_is_telemetry_label"] is True


def test_post_hoc_summary_counts():
    rows = [
        _row("webserver_access_log", "process_creation", ["process_creation"],
             telemetry="webserver_access_log"),
        _row("file_event", "process_creation", ["file_event"], telemetry="file_event"),
        _row("process_creation", "process_creation", ["process_creation"]),
    ]
    s = summarise([diagnose_case(r) for r in rows],
                  known_categories={"process_creation", "file_event"})
    assert s["wrong"] == 2
    assert s["wrong_rule_is_telemetry_label"] == 2
    assert s["overridden_rule_is_telemetry_label"] == 1
    assert s["wrong_rule_category_unknown"] == 1


def _scored_row(rule, gold, top=None):
    """A row with all three logsource fields: rule/gold/top as (category, product, service)."""
    fields = ("category", "product", "service")
    row = {
        "rule_id": "abc",
        "scores": {"logsource": {"per_field": {
            f: {"predicted": p, "gold": g, "match": p == g} for f, p, g in zip(fields, rule, gold)
        }}},
        "pipeline": {"logsource_suggestions": [dict(zip(fields, top))] if top else [],
                     "attack_vector": {}},
        "rules_yaml": [],
    }
    return row


def test_per_field_counts_show_which_field_fails():
    from eval.diagnose_logsource import per_field_counts
    rows = [
        _scored_row(("process_creation", "windows", None), ("process_creation", "windows", None)),
        _scored_row(("process_creation", "windows", "sysmon"), ("process_creation", "windows", None)),
        _scored_row(("webserver", None, None), ("process_creation", "windows", None)),
        {"rule_id": "x", "scores": {"logsource": None}},
    ]
    c = per_field_counts(rows)
    assert c == {"n": 3, "category": 2, "product": 2, "service": 2, "only_service_wrong": 1}


def test_top_suggestion_category_and_product_agreement():
    from eval.diagnose_logsource import top_category_and_product_right
    gold = ("process_creation", "windows", None)
    assert top_category_and_product_right(
        _scored_row(gold, gold, top=("process_creation", "windows", "sysmon"))) is True
    assert top_category_and_product_right(
        _scored_row(gold, gold, top=("process_creation", "linux", None))) is False
    assert top_category_and_product_right(_scored_row(gold, gold)) is None
