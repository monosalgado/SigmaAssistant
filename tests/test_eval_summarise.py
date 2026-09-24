"""Tests for the evaluation summariser.

Constraint: fully offline — operates on in-memory result rows, no files, no
network, no LLM calls.

The failure mode this guards against is a summary that is silently wrong rather
than visibly broken. Three specific ways that could happen:

  * averaging an undefined metric as 0.0, which drags the mean down with cases
    that had nothing to measure;
  * reporting one denominator for all metrics, when content scores exist only
    for rules that parsed and S4/S5 are undefined for some of those;
  * summing missing token counts as zero, producing a cost figure that looks
    precise and is not.

See thesis/ENGINEERING_LOG.md, Change 6.
"""

from __future__ import annotations

from eval.summarise import NULL_BASELINES, check_gates, split_by_contamination, summarise


def _row(*, parses=True, issues=0, logsource=None, attack=None,
         detection=None, tokens=1000, error=None, scored=True):
    """One result row in the shape run_eval.py writes."""
    if not scored:
        return {"scores": None, "error": error, "telemetry": {}, "n_rules": 0}

    scores = {"validity": {"parses": parses, "issue_count": issues}}
    if parses:
        if logsource is not None:
            scores["logsource"] = {"exact_match": logsource}
        if attack is not None:
            scores["attack"] = {"exact": {"f1": attack}}
        if detection is not None:
            scores["detection_fields"] = {"f1": detection}

    return {
        "scores": scores,
        "error": error,
        "n_rules": 1,
        "elapsed_s": 10.0,
        "telemetry": {"total_tokens": tokens,
                      "calls_without_token_data": 0 if tokens else 1},
    }


# --------------------------------------------------------------------------
# Denominators
# --------------------------------------------------------------------------

def test_each_metric_reports_its_own_n():
    """Content scores exist only for rules that parsed, and S4 is undefined for
    rules with no ATT&CK tags. A single shared n would misreport all three."""
    rows = [
        _row(logsource=True, attack=0.8, detection=0.5),
        _row(logsource=False, attack=None, detection=0.4),   # no ATT&CK tags
        _row(parses=False),                                  # nothing to score
    ]
    s = summarise(rows)
    assert s["n_scored"] == 3
    assert s["n_parsed"] == 2
    assert s["n_logsource"] == 2
    assert s["n_attack"] == 1       # the untagged case is excluded, not zeroed
    assert s["n_detection"] == 2


def test_unparsed_rules_are_excluded_from_content_scores():
    """A rule that did not parse has no logsource to compare. Counting it as a
    miss would conflate S1 failure with S3 failure."""
    rows = [_row(logsource=True), _row(parses=False)]
    s = summarise(rows)
    assert s["validity_rate"] == 0.5
    assert s["logsource_exact"] == 1.0   # not 0.5
    assert s["n_logsource"] == 1


def test_undefined_f1_is_not_averaged_as_zero():
    """score_case returns None for an undefined F1. Treating that as 0.0 would
    understate the metric in proportion to how many cases were unmeasurable."""
    rows = [_row(attack=1.0), _row(attack=None)]
    s = summarise(rows)
    assert s["attack_f1"] == 1.0
    assert s["n_attack"] == 1


def test_metric_with_no_measurable_cases_is_none_not_zero():
    rows = [_row(attack=None, detection=None, logsource=None)]
    s = summarise(rows)
    assert s["attack_f1"] is None
    assert s["detection_f1"] is None
    assert s["logsource_exact"] is None


# --------------------------------------------------------------------------
# Errors and empty input
# --------------------------------------------------------------------------

def test_errored_cases_count_toward_total_but_not_toward_scores():
    """A case that crashed is still a case. Dropping it from the denominator
    would make a fragile arm look accurate."""
    rows = [_row(logsource=True), _row(scored=False, error="ConnectionError")]
    s = summarise(rows)
    assert s["n_cases"] == 2
    assert s["n_errors"] == 1
    assert s["n_scored"] == 1


def test_empty_run_does_not_raise():
    s = summarise([])
    assert s["n_cases"] == 0
    assert s["validity_rate"] is None
    assert s["total_tokens"] is None


# --------------------------------------------------------------------------
# Cost
# --------------------------------------------------------------------------

def test_missing_token_counts_are_flagged_not_summed_as_zero():
    rows = [_row(tokens=1000), _row(tokens=None)]
    s = summarise(rows)
    assert s["total_tokens"] == 1000
    assert s["mean_tokens"] == 1000.0      # mean over the calls that reported
    assert s["calls_without_token_data"] == 1


# --------------------------------------------------------------------------
# Null baselines
# --------------------------------------------------------------------------

def test_baselines_cover_every_agreement_metric():
    """Each agreement metric must be printable next to a chance level. A metric
    without one could be reported as a success when it is not."""
    s = summarise([_row(logsource=True, attack=0.5, detection=0.5)])
    for key in NULL_BASELINES:
        assert key in s


def test_a_result_at_chance_is_detectable():
    """Pins the comparison the report relies on: scoring at the null baseline is
    not a positive result."""
    rows = [_row(logsource=False, attack=0.09, detection=0.13)]
    s = summarise(rows)
    assert s["attack_f1"] <= NULL_BASELINES["attack_f1"]
    assert s["detection_f1"] <= NULL_BASELINES["detection_f1"]
    assert s["logsource_exact"] <= NULL_BASELINES["logsource_exact"]


def test_mean_issues_is_a_float_so_it_formats_consistently():
    """statistics.mean returns an int for all-int input, which would print as
    '0' rather than '0.00' and read as a different kind of value."""
    s = summarise([_row(issues=0), _row(issues=0)])
    assert isinstance(s["mean_issues"], float)


# --------------------------------------------------------------------------
# Clean vs flagged cases (plan 1.3b)
# --------------------------------------------------------------------------

def _tagged(rule_id, flagged):
    row = _row()
    row["rule_id"] = rule_id
    if flagged is not None:
        row["contamination"] = {"flagged": flagged, "reasons": []}
    return row


def test_rows_split_by_their_own_flag():
    rows = [_tagged("a", False), _tagged("b", True), _tagged("c", False)]
    split = split_by_contamination(rows)
    assert [r["rule_id"] for r in split["clean"]] == ["a", "c"]
    assert [r["rule_id"] for r in split["flagged"]] == ["b"]
    assert split["unknown"] == []


def test_older_rows_are_split_with_the_committed_list():
    """Files written before the flag existed carry no field; the committed list
    applies by rule_id, so baseline v1 can be split too."""
    rows = [_tagged("a", None), _tagged("b", None)]
    split = split_by_contamination(rows, flags={"a": False, "b": True})
    assert [r["rule_id"] for r in split["flagged"]] == ["b"]


def test_a_case_in_neither_place_is_unknown_not_clean():
    split = split_by_contamination([_tagged("z", None)], flags={})
    assert [r["rule_id"] for r in split["unknown"]] == ["z"] and split["clean"] == []


# --------------------------------------------------------------------------
# Gates: is a result file citable? (plan 1.4a)
# --------------------------------------------------------------------------
# Until now these were computed by hand after every run.

def _gated(rule_id="r", **overrides):
    """A row as run_eval.py writes it since Changes 14-17."""
    row = {"rule_id": rule_id, "error": None, "elapsed_s": 90.0,
           "snapshots_missed": 0, "poc_snapshots_missed": 0, "pipeline": {},
           "telemetry": {"n_errors": 0, "calls_without_token_data": 0}}
    row.update(overrides)
    return row


def _status(result, name):
    return next(c["status"] for c in result["checks"] if c["name"] == name)


def test_a_clean_file_is_citable():
    result = check_gates([_gated("a"), _gated("b")])
    assert result["verdict"] == "CITABLE"
    assert all(c["status"] == "PASS" for c in result["checks"])


def test_each_failure_is_detected():
    cases = {
        "page snapshots all served": _gated(snapshots_missed=1),
        "PoC GitHub snapshots all served": _gated(poc_snapshots_missed=2),
        "token data on every call": _gated(telemetry={"n_errors": 0, "calls_without_token_data": 1}),
        "no failed LLM calls": _gated(telemetry={"n_errors": 1, "calls_without_token_data": 0}),
        "no case-level errors": _gated(error="ValueError: x"),
        "no suspiciously fast cases (< 30 s)": _gated(elapsed_s=6.1),
    }
    for name, bad_row in cases.items():
        result = check_gates([_gated("ok"), bad_row])
        assert _status(result, name) == "FAIL", name
        assert result["verdict"] == "NOT CITABLE", name


def test_duplicate_cases_fail():
    assert _status(check_gates([_gated("a"), _gated("a")]), "no duplicate cases") == "FAIL"


def test_older_files_say_what_they_did_not_record():
    """Baseline v1 predates the PoC snapshots (Change 17) and was written when
    crashes were hidden from the harness (before Change 14)."""
    old = _gated()
    del old["poc_snapshots_missed"], old["pipeline"]
    result = check_gates([old])
    assert _status(result, "PoC GitHub snapshots all served") == "NOT RECORDED"
    assert _status(result, "no case-level errors") == "NOT RECORDED"
    assert result["verdict"] == "CITABLE WITH CAVEATS (2 not recorded)"


def test_an_empty_file_is_not_citable():
    assert check_gates([])["verdict"] == "NOT CITABLE"
