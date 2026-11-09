"""Offline tests for eval/simulate_keep_runnable.py - Change 55, step 1 (plan in the log 2026-11-09): the change's own
rule applied to saved rows of runs that kept the rules before review. A simulation: exact for the revert itself, both
sides scored with today's scorer."""

from __future__ import annotations

from eval.simulate_keep_runnable import simulate_rules, simulate_run

GOLD = """title: Gold
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\\\\node.exe'
        Image|endswith: '\\\\cmd.exe'
    condition: selection
"""
GOOD = """title: Ours
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\\\\node.exe'
    selection_child:
        Image|endswith: '\\\\cmd.exe'
    condition: all of selection_*
"""
BROKEN = GOOD.replace("all of selection_*", "all of selection_ *")
OTHER = GOOD.replace("process_creation", "file_event")


def _row(tmp_path, final, before, rid="c1"):
    gold = tmp_path / f"{rid}.yml"
    gold.write_text(GOLD, encoding="utf-8")
    return {"rule_id": rid, "rule_path": str(gold), "product": "windows", "rules_yaml": final,
            "pipeline": {"pre_review_rules": before}}


def test_the_changes_own_rule_puts_back_what_review_broke(tmp_path):
    rules, reverted = simulate_rules(_row(tmp_path, [BROKEN, OTHER], [GOOD, OTHER]))
    assert rules == [GOOD, OTHER] and [r["rule"] for r in reverted] == [1]


def test_a_run_counts_reverts_and_compares_s1r_s3u_s5u_paired(tmp_path):
    rows = [_row(tmp_path, [BROKEN, OTHER], [GOOD, OTHER], "c1"),     # review broke the first rule
            _row(tmp_path, [GOOD], [GOOD], "c2"),                    # nothing to revert
            _row(tmp_path, [OTHER, BROKEN], [OTHER, GOOD], "c3")]    # review broke the second rule
    s = simulate_run(rows)
    assert s["cases"] == 3 and s["reverted_rules"] == 2 and s["cases_with_a_revert"] == 2
    assert s["cannot_run"] == {"recorded": 2, "simulated": 0}
    assert s["S1r"]["recorded"] == 2 / 3 and s["S1r"]["simulated"] == 1.0 and s["S1r"]["diff"] == 1 / 3
    assert s["S3u"]["recorded"] == s["S3u"]["simulated"]      # S3u credits a rule that loads, runnable or not
    assert len(s["S1r"]["ci"]) == 2


def test_rows_without_the_rules_before_review_are_left_out(tmp_path):
    row = _row(tmp_path, [GOOD], [GOOD])
    row["pipeline"] = {}
    assert simulate_run([row])["cases"] == 0
