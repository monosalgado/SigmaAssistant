"""Tests for reading the saved chats (`data/sessions.json`) as evidence for the professor's
question (2026-09-28): the rules the assistant wrote in April, for which reports, with which
version of the pipeline, and how often the same report got a different rule.

Offline. A chat carries no timestamp, so each run is dated by its rules' `date:` field, which
the generation prompt has filled from `{current_date}` since the pipeline's first commit
(7271080). The pipeline version is told apart by the stage results it saved: the
attack-vector stage arrived with f457855, the per-attempt generations with ae91c46.
"""

from __future__ import annotations

from eval.old_sessions import code_era, mentions, models_used, repeats, result_runs, rule_summary, runs, totals

RULE_OK = """title: A
date: 2026-04-15
logsource:
    category: webserver
    product: citrix
detection:
    selection:
        cs-uri-stem|contains: '/saml/login'
    condition: selection
"""

# The condition at the top level, outside `detection` - as a 12 April rule has it.
RULE_NO_CONDITION = """title: B
date: 2026-04-12
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\msdt.exe'
condition: selection
"""


def _answer(*rules, meta=None, text="Here are the rules."):
    content = text + "".join(f"\n```yaml\n{r}```\n" for r in rules)
    msg = {"role": "assistant", "content": content}
    if meta is not None:
        msg["pipeline_metadata"] = meta
    return msg


def _user(text):
    return {"role": "user", "content": text}


GREETING = {"role": "assistant", "content": "Hello! I am your Sigma Rule Assistant."}


def test_a_rule_is_summarised_by_its_log_source_date_and_whether_it_is_complete():
    assert rule_summary(RULE_OK) == {"logsource": "webserver/citrix", "date": "2026-04-15", "complete": True,
                                     "on_table": None}
    assert rule_summary(RULE_NO_CONDITION)["complete"] is False
    assert rule_summary("title: [unclosed")["logsource"] == "(does not parse)"


def test_the_pipeline_version_is_told_apart_by_the_stage_results_it_saved():
    assert code_era(None) == "no stage results saved"
    assert code_era({"attack_summary": "x", "logsource_suggestions": []}) == "f41d0a5"
    assert code_era({"attack_summary": "x", "attack_vector": {}}) == "f457855"
    assert code_era({"attack_vector": {}, "generations": []}) == "ae91c46"


def test_each_answer_with_rules_is_one_run_of_the_url_asked_before_it():
    sessions = {
        "s1": [GREETING, _user("Help me with this: https://example.com/a#part"),
               _answer(RULE_OK, RULE_NO_CONDITION, meta={"attack_vector": {}, "enrichment_sources": [1, 2]}),
               _user("what is cs-uri?"), {"role": "assistant", "content": "It is the URI."}],
    }
    rows = runs(sessions)
    assert len(rows) == 1
    row = rows[0]
    assert row["url"] == "https://example.com/a"
    assert row["date"] == "2026-04-12"          # the earliest of its rules' dates
    assert row["era"] == "f457855"
    assert row["logsources"] == ["webserver/citrix", "process_creation/windows"]
    assert row["complete"] == 1 and row["enrichment_sources"] == 2


def test_a_message_without_a_url_keeps_its_text():
    rows = runs({"s": [_user("Attackers dump lsass with procdump"), _answer(RULE_OK)]})
    assert rows[0]["url"] == "Attackers dump lsass with procdump"


def test_repeats_are_the_urls_run_more_than_once_in_date_order():
    sessions = {
        "s1": [_user("https://example.com/a"), _answer(RULE_OK)],
        "s2": [_user("https://example.com/a/"), _answer(RULE_NO_CONDITION)],
        "s3": [_user("https://example.com/b"), _answer(RULE_OK)],
    }
    out = repeats(runs(sessions))
    assert list(out) == ["https://example.com/a"]
    group = out["https://example.com/a"]
    assert [r["date"] for r in group["runs"]] == ["2026-04-12", "2026-04-15"]
    assert group["first_logsources"] == ["process_creation/windows", "webserver/citrix"]
    assert group["distinct_first_logsources"] == 2


def test_which_runs_mention_given_strings_anywhere_in_the_answer_or_its_stage_results():
    # Used to check whether a prompt's worked example came from a report the assistant had
    # already been run on: its strings appear in that report's saved stage results.
    sessions = {
        "s1": [_user("https://example.com/a"),
               _answer(RULE_OK, meta={"attack_summary": "patch decrypted with password Bingb0ng"})],
        "s2": [_user("https://example.com/b"), _answer(RULE_OK, text="uses remoteVersion=")],
        "s3": [_user("https://example.com/c"), _answer(RULE_OK)],
    }
    found = mentions(runs(sessions), sessions, ["Bingb0ng", "remoteVersion", "absent"])
    assert [(r["url"], terms) for r, terms in found] == [
        ("https://example.com/a", ["Bingb0ng"]), ("https://example.com/b", ["remoteVersion"])]


TABLE = {"with_category": [{"category": "webserver", "products": [None], "fields": []},
                           {"category": "process_creation", "products": ["linux", "windows"], "fields": []}],
         "without_category": [{"product": "linux", "service": "auditd", "fields": []}]}


def test_each_rule_is_checked_against_the_log_sources_sigmahqs_rules_use():
    # `webserver` has no product in SigmaHQ's rules: `webserver/citrix` is not one of them.
    assert rule_summary(RULE_OK, TABLE)["on_table"] is False
    assert rule_summary(RULE_NO_CONDITION, TABLE)["on_table"] is True
    assert rule_summary(RULE_OK)["on_table"] is None


def test_a_run_counts_its_rules_whose_log_source_sigmahq_uses():
    rows = runs({"s": [_user("https://example.com/a"), _answer(RULE_OK, RULE_NO_CONDITION)]}, TABLE)
    assert rows[0]["on_table"] == 1


def test_totals_per_pipeline_version_and_overall():
    sessions = {"s1": [_user("https://example.com/a"), _answer(RULE_OK, RULE_NO_CONDITION, meta={"attack_vector": {}})],
                "s2": [_user("https://example.com/b"), _answer(RULE_OK, meta={"attack_summary": "x"})]}
    out = totals(runs(sessions, TABLE))
    assert out["f457855"] == {"answers": 1, "rules": 2, "complete": 1, "on_table": 1}
    assert out["f41d0a5"] == {"answers": 1, "rules": 1, "complete": 1, "on_table": 0}
    assert out["all"] == {"answers": 2, "rules": 3, "complete": 2, "on_table": 1}


def test_an_evaluation_result_file_is_read_the_same_way_one_row_per_case():
    # So the April chats and a September run are counted by the same code.
    rows = [{"rule_id": "r1", "rules_yaml": [RULE_OK, RULE_NO_CONDITION], "config": {"arm": "c36_yaml"}},
            {"rule_id": "r2", "rules_yaml": [], "config": {"arm": "c36_yaml"}}]
    out = result_runs(rows, TABLE)
    assert len(out) == 1
    assert out[0]["era"] == "c36_yaml" and out[0]["rules"] == 2 and out[0]["on_table"] == 1
    assert totals(out)["all"] == {"answers": 1, "rules": 2, "complete": 1, "on_table": 1}


def test_the_models_a_result_file_called():
    rows = [{"llm_calls": [{"model": "qwen3-coder:30b"}, {"model": "qwen3-coder:30b"}]},
            {"llm_calls": [{"model": "gemini-2.5-flash"}]}, {"llm_calls": None}]
    assert models_used(rows) == {"qwen3-coder:30b": 2, "gemini-2.5-flash": 1}
