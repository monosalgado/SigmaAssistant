"""Tests for "wrong, or just different?" (log-source picks, user 2026-09-29): does a log source the
analysis picked, that is not the gold rule's, match ANOTHER human-written SigmaHQ rule for the same
report? A report often supports several valid rules (Operation Triangulation has a DNS rule and a
proxy rule), and S3 compares against one of them.

Offline. "The same report" = a rule citing one of the case's input URLs, where that URL is cited
by at most MAX_CITING rules in SigmaHQ (a generic reference, such as a tool's GitHub page, would
link unrelated rules).
"""

from __future__ import annotations

from eval.alternative_logsources import alternatives, classify, reference_index


def _write(path, rule_id, logsource, refs):
    lines = [f"title: t", f"id: {rule_id}", "references:"] + [f"    - {r}" for r in refs] + ["logsource:"]
    lines += [f"    {k}: {v}" for k, v in logsource.items()]
    lines += ["detection:", "    s:", "        a: b", "    condition: s"]
    path.write_text("\n".join(lines) + "\n")


def test_rules_are_indexed_by_the_reports_they_cite(tmp_path):
    _write(tmp_path / "a.yml", "gold-1", {"category": "proxy"}, ["https://blog.example/triangulation/#c2"])
    _write(tmp_path / "b.yml", "other-2", {"category": "dns"}, ["https://blog.example/triangulation"])
    index = reference_index([tmp_path])
    # fragment and trailing slash do not make a different report
    assert sorted(r for r, _ in index["https://blog.example/triangulation"]) == ["gold-1", "other-2"]


def test_the_alternatives_are_the_other_rules_citing_the_cases_report(tmp_path):
    _write(tmp_path / "a.yml", "gold-1", {"category": "proxy"}, ["https://blog.example/t"])
    _write(tmp_path / "b.yml", "other-2", {"category": "dns"}, ["https://blog.example/t"])
    case = {"rule_id": "gold-1", "references_usable": ["https://blog.example/t"]}
    assert alternatives(case, reference_index([tmp_path])) == [{"category": "dns"}]


def test_a_url_cited_by_too_many_rules_links_nothing(tmp_path):
    for i in range(7):
        _write(tmp_path / f"r{i}.yml", f"r-{i}", {"category": "webserver"}, ["https://github.com/some/tool"])
    case = {"rule_id": "r-0", "references_usable": ["https://github.com/some/tool"]}
    assert alternatives(case, reference_index([tmp_path]), max_citing=5) == []


def test_a_pick_is_the_gold_another_human_rule_neither_or_missing():
    gold = {"category": "proxy"}
    alts = [{"category": "dns"}]
    assert classify({"category": "proxy"}, gold, alts) == "gold"
    assert classify({"category": "dns", "product": None}, gold, alts) == "another human rule"
    assert classify({"category": "process_creation", "product": "windows"}, gold, alts) == "neither"
    assert classify(None, gold, alts) == "no pick"
