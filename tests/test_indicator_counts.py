"""Tests for Change 53's measure (`eval/indicator_counts.py`): per run - indicators listed (total, median per report),
used by a rule (the pipeline's own `indicator_use` record), the used share, and per type listed -> used. Offline."""

from __future__ import annotations

from eval.indicator_counts import run_counts


def _row(indicators, used):
    return {"pipeline": {"indicators": [{"value": v, "type": t} for v, t in indicators],
                         "indicator_use": {"given": len(indicators), "used": used, "unused": []}}}


def test_listed_used_share_and_types():
    rows = [_row([("cmd.exe", "process"), ("abc123", "hash"), ("evil.com", "domain")], ["cmd.exe", "evil.com"]),
            _row([("x.dll", "file_path")], []),
            _row([], [])]
    c = run_counts(rows)
    assert (c["reports"], c["listed"], c["used"], c["median_listed"]) == (3, 4, 2, 1)
    assert c["used_share"] == 0.5
    assert c["by_type"]["hash"] == {"listed": 1, "used": 0} and c["by_type"]["domain"] == {"listed": 1, "used": 1}
    assert c["hashes_and_ips"] == 1


def test_a_report_without_the_record_counts_its_list_and_nothing_used():
    c = run_counts([{"pipeline": {"indicators": [{"value": "a", "type": "process"}]}}])
    assert (c["listed"], c["used"]) == (1, 0)
