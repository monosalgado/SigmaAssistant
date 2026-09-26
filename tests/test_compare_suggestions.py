"""Offline tests for eval/compare_suggestions.py — plan 2.6's measures (Change 28), fixed
before its run.

The analysis stage's top log-source suggestion is compared with the gold rule's log source
over ALL matched rows: the gold comes from the manifest, so a case counts whether or not
its first rule parses — the diagnosis tool's web-label counts do not, and their
denominators differ between runs (log, 2026-09-26 correction).
"""

from __future__ import annotations

from eval.compare_suggestions import compare, gold_form, suggestion_measures

TABLE = {
    "with_category": [
        {"category": "process_creation", "products": ["linux", "windows"], "fields": []},
        {"category": "webserver", "products": [None], "fields": []},
    ],
    "without_category": [{"product": "windows", "service": "security", "fields": []}],
}


def _row(rule_id, *suggestions, parsed=True):
    return {"rule_id": rule_id,
            "scores": {"logsource": {"exact_match": False} if parsed else None},
            "pipeline": {"logsource_suggestions": list(suggestions)}}


def test_exact_uses_s3s_rule_absent_matches_absent():
    m = suggestion_measures(_row("a", {"category": "webserver", "product": None, "service": None}),
                            {"category": "webserver"}, TABLE)
    assert m["exact"] is True and m["on_table"] is True


def test_placeholders_count_as_absent():
    m = suggestion_measures(_row("a", {"category": "webserver", "product": "-"}),
                            {"category": "webserver"}, TABLE)
    assert m["exact"] is True


def test_an_invented_product_is_neither_exact_nor_on_the_table():
    m = suggestion_measures(_row("a", {"category": "webserver", "product": "linux-windows/apache-iis"}),
                            {"category": "webserver"}, TABLE)
    assert m["exact"] is False and m["on_table"] is False


def test_only_the_top_suggestion_counts():
    m = suggestion_measures(_row("a", {"category": "process_creation", "product": "windows"},
                                 {"category": "webserver"}), {"category": "webserver"}, TABLE)
    assert m["exact"] is False


def test_the_service_form_is_recognised():
    m = suggestion_measures(_row("a", {"category": None, "product": "windows", "service": "security"}),
                            {"product": "windows", "service": "security"}, TABLE)
    assert m == {"has_suggestion": True, "exact": True, "on_table": True, "no_category": True}


def test_no_suggestion_counts_as_a_miss_not_as_missing():
    m = suggestion_measures(_row("a"), {"category": "webserver"}, TABLE)
    assert m == {"has_suggestion": False, "exact": False, "on_table": False, "no_category": False}


def test_a_case_whose_first_rule_did_not_parse_still_counts():
    m = suggestion_measures(_row("a", {"category": "webserver"}, parsed=False),
                            {"category": "webserver"}, TABLE)
    assert m["exact"] is True


def test_gold_forms():
    assert gold_form({"product": "windows", "service": "security"}) == "service"
    assert gold_form({"category": "proxy"}) == "web"
    assert gold_form({"category": "webserver"}) == "web"
    assert gold_form({"category": "process_creation", "product": "windows"}) == "category"


def test_compare_pairs_by_rule_id_and_tests_exact_paired():
    gold = {"a": {"category": "webserver"}, "b": {"category": "webserver"},
            "c": {"product": "windows", "service": "security"}, "d": {"category": "webserver"}}
    web, pc = {"category": "webserver"}, {"category": "process_creation", "product": "windows"}
    sec = {"product": "windows", "service": "security"}
    rows_a = [_row("a", web), _row("b", pc), _row("c", pc), _row("x", web)]
    rows_b = [_row("a", pc), _row("b", web), _row("c", sec), _row("d", web)]
    r = compare(rows_a, rows_b, gold, TABLE)
    assert r["n"] == 3  # a, b, c: in both runs and in the manifest
    assert r["exact"]["a_true"] == 1 and r["exact"]["b_true"] == 2
    assert (r["exact"]["only_a"], r["exact"]["only_b"]) == (1, 2)
    assert (r["no_category"]["a"], r["no_category"]["b"]) == (0, 1)
    assert r["by_gold_form"]["service"] == {"n": 1, "a": 0, "b": 1}
    assert r["by_gold_form"]["web"] == {"n": 2, "a": 1, "b": 1}
