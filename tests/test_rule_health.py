"""Offline tests for eval/rule_health.py (definitions fixed in the log, 2026-11-09 evening): properties of every
delivered rule that need no expert rule - does it run, does SigmaHQ use its log source and its fields together, are
its values in the report, its shape - and per case: rule and tactic counts, regeneration, candidate patterns from
places no log records that were used anyway, where the "do not use" hits sit, and pages that hold no report.
No model, no network, no knowledge base."""

from __future__ import annotations

from eval.rule_health import (
    case_health,
    do_not_use_hits,
    expert_health,
    generic_cases,
    generic_pages,
    generic_share,
    page_key,
    reference_from_rules,
    rule_health,
    run_summary,
    unlogged_patterns_used,
)

SIGMAHQ = [
    {"logsource": {"category": "process_creation", "product": "windows"},
     "detection": {"selection": {"Image|endswith": "\\cmd.exe", "CommandLine|contains": "whoami"},
                   "filter_main": {"ParentImage|endswith": "\\explorer.exe"}, "condition": "selection and not filter_main"}},
    {"logsource": {"category": "process_creation", "product": "linux"},
     "detection": {"selection": {"User": "root"}, "condition": "selection"}},
    {"logsource": {"category": "webserver"},
     "detection": {"selection": {"cs-uri-query|contains": "cmd="}, "condition": "selection"}},
    {"logsource": {"product": "windows", "service": "security"},
     "detection": {"selection": {"EventID": 4698, "TaskName|contains": "x"}, "condition": "selection"}},
]
REFERENCE = reference_from_rules(SIGMAHQ)

RULE = """title: Shell started by the update service
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\\\\wsusservice.exe'
    selection_child:
        Image|endswith: '\\\\cmd.exe'
        CommandLine|contains: 'whoami /priv'
    condition: all of selection_*
"""
REPORT = "The attacker's payload made WsusService.exe start cmd.exe, which ran whoami /priv on the server."


# --- the reference: which fields SigmaHQ's rules use with each log source -------------------------------------------

def test_the_reference_joins_a_categorys_fields_over_its_products():
    assert REFERENCE["categories"]["process_creation"] == {"Image", "CommandLine", "ParentImage", "User"}


def test_a_rule_without_a_category_is_filed_under_its_product_and_service():
    assert REFERENCE["services"][("windows", "security")] == {"EventID", "TaskName"}
    assert "webserver" in REFERENCE["categories"] and ("windows", "security") not in REFERENCE["categories"]


# --- per rule ------------------------------------------------------------------------------------------------------

def test_a_rule_that_loads_and_whose_condition_parses_runs():
    health = rule_health(RULE, REFERENCE)
    assert health["readable"] is True and health["runs"] is True


def test_a_rule_whose_condition_names_no_selection_is_readable_but_does_not_run():
    health = rule_health(RULE.replace("all of selection_*", "all of selection_ *"), REFERENCE)
    assert health["readable"] is True and health["runs"] is False


def test_text_that_is_not_a_rule_is_unreadable_and_judged_on_nothing_else():
    health = rule_health("just some words", REFERENCE)
    assert health["readable"] is False and health["runs"] is False
    assert health["logsource_known"] is None and health["unused_fields"] is None


def test_the_log_source_is_named_by_its_category_or_by_product_and_service():
    assert rule_health(RULE, REFERENCE)["logsource"] == "process_creation"
    by_service = RULE.replace("    category: process_creation\n    product: windows",
                              "    product: windows\n    service: security")
    assert rule_health(by_service, REFERENCE)["logsource"] == "windows/security"


def test_a_log_source_sigmahq_uses_is_known_and_one_it_does_not_use_is_not():
    assert rule_health(RULE, REFERENCE)["logsource_known"] is True
    unknown = rule_health(RULE.replace("process_creation", "exploit_attempt"), REFERENCE)
    assert unknown["logsource_known"] is False
    assert unknown["unused_fields"] is None            # not judged: there is nothing to compare with


def test_fields_sigmahq_uses_with_that_log_source_are_not_reported():
    assert rule_health(RULE, REFERENCE)["unused_fields"] == []


def test_a_field_sigmahq_never_uses_with_that_log_source_is_reported_without_its_modifier():
    web = """title: Web
logsource:
    category: webserver
detection:
    selection:
        request_body|contains: 'cmd='
        cs-uri-query|contains: 'x'
    condition: selection
"""
    assert rule_health(web, REFERENCE)["unused_fields"] == ["request_body"]


def test_field_names_are_compared_as_written_and_exclusions_count_too():
    odd = RULE.replace("CommandLine|contains", "commandline|contains").replace(
        "    condition: all of selection_*",
        "    filter_main:\n        IntegrityLevel: 'System'\n    condition: all of selection_* and not filter_main")
    assert rule_health(odd, REFERENCE)["unused_fields"] == ["IntegrityLevel", "commandline"]


def test_values_of_six_characters_or_more_are_looked_up_in_the_report():
    health = rule_health(RULE, REFERENCE, REPORT)
    # \\wsusservice.exe, \\cmd.exe and "whoami /priv": all three are long enough, all three are in the report
    assert health["values"] == 3 and health["values_in_report"] == 3
    absent = rule_health(RULE.replace("whoami /priv", "net user /add"), REFERENCE, REPORT)
    assert absent["values"] == 3 and absent["values_in_report"] == 2


def test_short_values_are_not_judged_and_without_the_report_nothing_is_looked_up():
    short = RULE.replace("whoami /priv", "/c")
    assert rule_health(short, REFERENCE, REPORT)["values"] == 2
    assert rule_health(RULE, REFERENCE)["values"] == 3 and rule_health(RULE, REFERENCE)["values_in_report"] is None


def test_an_exclusion_is_a_filter_selection_or_a_not_in_the_condition():
    assert rule_health(RULE, REFERENCE)["has_exclusion"] is False
    named = RULE.replace("    condition: all of selection_*",
                         "    filter_main:\n        User: 'SYSTEM'\n    condition: all of selection_* and not filter_main")
    assert rule_health(named, REFERENCE)["has_exclusion"] is True
    negated = RULE.replace("all of selection_*", "selection_parent and not selection_child")
    assert rule_health(negated, REFERENCE)["has_exclusion"] is True


def test_a_parent_process_field_and_the_level_are_recorded():
    health = rule_health(RULE, REFERENCE)
    assert health["uses_parent"] is True and health["level"] == "high"
    no_parent = RULE.replace("ParentImage", "OriginalFileName")
    assert rule_health(no_parent, REFERENCE)["uses_parent"] is False


# --- candidate patterns from places no log records -----------------------------------------------------------------

def _vector(*patterns):
    return {"payload_signatures": [{"pattern": p, "where": w, "derived_from": "q"} for p, w in patterns]}


def test_a_pattern_from_inside_a_file_used_in_a_rule_is_listed_with_the_field_it_lands_in():
    used = unlogged_patterns_used(_vector(("whoami /priv", "file_content")), [RULE])
    assert used == [{"pattern": "whoami /priv", "where": "file_content", "fields": ["CommandLine"]}]


def test_a_pattern_from_a_place_that_is_logged_is_not_listed():
    assert unlogged_patterns_used(_vector(("whoami /priv", "process_cmdline"), ("cmd=", "request_uri")), [RULE]) == []


def test_an_unlogged_pattern_no_rule_uses_is_not_listed_and_very_short_ones_are_not_judged():
    vector = _vector(("certutil -decode", "network_payload"), ("/c", "request_body"))
    assert unlogged_patterns_used(vector, [RULE.replace("whoami /priv", "/c dir")]) == []


def test_matching_ignores_case_backslashes_and_regex_characters_at_the_ends_as_the_coverage_check_does():
    used = unlogged_patterns_used(_vector((".*\\WsusService.exe$", "response_body")), [RULE])
    assert used == [{"pattern": ".*\\WsusService.exe$", "where": "response_body", "fields": ["ParentImage"]}]


# --- where the "do not use" hits sit -------------------------------------------------------------------------------

def test_a_reported_string_that_is_only_in_the_title_is_not_in_a_detection():
    hits = do_not_use_hits(["update service"], [RULE])
    assert hits == {"in_detection": [], "elsewhere": ["update service"], "not_found": []}


def test_a_reported_string_inside_a_detection_value_is_in_a_detection():
    hits = do_not_use_hits(["whoami /priv", "Mandiant"], [RULE])
    assert hits == {"in_detection": ["whoami /priv"], "elsewhere": [], "not_found": ["Mandiant"]}


# --- pages that hold no report --------------------------------------------------------------------------------------

def test_a_page_is_named_by_host_and_path_only():
    assert page_key("https://www.Example.com/blog/a/?utm=1#top") == page_key("http://example.com/blog/a")
    assert page_key("https://example.com/blog/a") != page_key("https://example.com/blog/b")


def test_the_same_text_saved_for_two_different_pages_marks_both_as_generic():
    pages = {"https://vendor.com/blog/attack-one": "Our consulting services", "https://old.vendor.com/x/attack-two":
             "Our consulting services", "https://other.org/report": "A real report"}
    assert generic_pages(pages) == {"https://vendor.com/blog/attack-one", "https://old.vendor.com/x/attack-two"}


def test_one_page_under_two_spellings_of_its_address_is_not_generic_and_empty_pages_never_are():
    pages = {"https://vendor.com/post?tab=readme": "A real report", "https://www.vendor.com/post/#demo": "A real report",
             "https://a.com/1": "", "https://b.com/2": ""}
    assert generic_pages(pages) == set()


def test_a_cases_generic_share_is_the_share_of_its_input_characters_from_generic_pages():
    generic = {"https://vendor.com/blog/one"}
    assert generic_share({"https://vendor.com/blog/one": "x" * 30}, generic) == 1.0
    assert generic_share({"https://vendor.com/blog/one": "x" * 30, "https://other.org/r": "y" * 10}, generic) == 0.75
    assert generic_share({}, generic) is None and generic_share({"https://a.com": ""}, generic) is None


def test_the_cases_with_generic_input_are_listed_most_generic_first_with_the_pages_concerned():
    generic = {"https://vendor.com/blog/one", "https://vendor.com/blog/two"}
    cases = {"a": {"title": "Partly"}, "b": {"title": "Wholly"}, "c": {"title": "Real"}}
    pages = {"a": {"https://vendor.com/blog/one": "x" * 10, "https://other.org/r": "y" * 30},
             "b": {"https://vendor.com/blog/two": "x" * 10},
             "c": {"https://other.org/r": "y" * 30}}
    assert generic_cases(cases, pages, generic) == [
        {"rule_id": "b", "title": "Wholly", "share": 1.0, "urls": ["https://vendor.com/blog/two"]},
        {"rule_id": "a", "title": "Partly", "share": 0.25, "urls": ["https://vendor.com/blog/one"]}]


# --- per case and per run -------------------------------------------------------------------------------------------

def _row(rules, tactics=("initial_access", "execution"), retried=False, warnings=(), violations=(), patterns=()):
    return {"rule_id": "r1", "title": "Case", "rules_yaml": list(rules),
            "pipeline": {"attack_vector": dict(_vector(*patterns), kill_chain_stages=list(tactics)),
                         "generation_retried": retried,
                         "coverage_check": {"warnings": list(warnings), "blacklist_violations": list(violations)}}}


def test_a_case_counts_its_rules_tactics_regeneration_and_warnings():
    case = case_health(_row([RULE, RULE], retried=True, warnings=["w1", "w2"]), REFERENCE, REPORT, 0.0)
    assert case["n_rules"] == 2 and case["tactics"] == 2 and case["regenerated"] is True
    assert case["coverage_warnings"] == 2 and case["generic_share"] == 0.0 and len(case["rules"]) == 2


def test_a_case_counts_its_patterns_and_which_unlogged_ones_were_used():
    row = _row([RULE], patterns=(("whoami /priv", "file_content"), ("zzzzzz", "network_payload"), ("cmd.exe", "process_cmdline")))
    case = case_health(row, REFERENCE)
    assert case["patterns"] == 3 and case["unlogged_patterns"] == 2
    assert [u["pattern"] for u in case["unlogged_patterns_used"]] == ["whoami /priv"]


def test_a_case_says_where_its_do_not_use_hits_sit():
    case = case_health(_row([RULE], violations=["update service"]), REFERENCE)
    assert case["do_not_use_hits"]["elsewhere"] == ["update service"] and case["do_not_use_hits"]["in_detection"] == []


def test_a_run_adds_up_its_rules_and_keeps_first_rules_apart():
    broken = RULE.replace("all of selection_*", "all of selection_ *")
    cases = [case_health(_row([RULE, broken]), REFERENCE, REPORT, 0.0),
             case_health(_row([RULE.replace("ParentImage", "request_body")], tactics=["execution"] * 3, retried=True,
                              warnings=["w"], violations=["update service"],
                              patterns=(("whoami /priv", "file_content"),)), REFERENCE, REPORT, 1.0)]
    s = run_summary(cases)
    assert s["cases"] == 2 and s["all_rules"]["rules"] == 3 and s["first_rules"]["rules"] == 2
    assert s["all_rules"]["run"] == 2 and s["first_rules"]["run"] == 2
    assert s["all_rules"]["with_unused_fields"] == 1 and s["all_rules"]["judged_for_fields"] == 3
    assert s["all_rules"]["with_parent_field"] == 2 and s["all_rules"]["with_exclusion"] == 0
    assert s["all_rules"]["levels"] == {"high": 3}


def test_a_run_reports_values_in_the_report_as_counts():
    s = run_summary([case_health(_row([RULE, RULE.replace("whoami /priv", "net user /add")]), REFERENCE, REPORT)])
    assert s["all_rules"]["values"] == 6 and s["all_rules"]["values_in_report"] == 5
    assert s["first_rules"]["values"] == 3 and s["first_rules"]["values_in_report"] == 3


def test_a_run_counts_rules_against_tactics_and_what_regeneration_left():
    cases = [case_health(_row([RULE, RULE]), REFERENCE),
             case_health(_row([RULE], tactics=["a", "b", "c"], retried=True, warnings=["w"]), REFERENCE),
             case_health(_row([RULE, RULE, RULE], tactics=["a"], retried=True), REFERENCE)]
    s = run_summary(cases)
    assert s["rules_per_case"] == {"median": 2, "max": 3} and s["tactics_per_case"] == {"median": 2, "max": 3}
    assert s["cases_with_rules_at_least_tactics"] == 2
    assert s["regenerated"] == 2 and s["regenerated_still_warned"] == 1 and s["cases_with_coverage_warnings"] == 1


def test_a_run_totals_unlogged_patterns_do_not_use_hits_and_lists_no_report_candidates():
    cases = [case_health(_row([RULE], violations=["update service", "whoami /priv"],
                              patterns=(("whoami /priv", "file_content"), ("cmd.exe", "process_cmdline"))), REFERENCE,
                         None, 1.0),
             case_health(_row([RULE], patterns=(("zzzzzz", "network_payload"),)), REFERENCE, None, 0.5)]
    s = run_summary(cases)
    assert s["patterns"] == 3 and s["unlogged_patterns"] == 2 and s["unlogged_patterns_used"] == 1
    assert s["unlogged_landing"] == {"file_content -> CommandLine": 1}
    assert s["do_not_use_hits"] == {"in_detection": 1, "elsewhere": 1, "not_found": 0}
    assert s["no_report_candidates"] == ["Case"] and s["partly_generic"] == 1


def test_a_run_without_report_texts_or_pages_leaves_those_readings_empty():
    s = run_summary([case_health(_row([RULE]), REFERENCE)])
    assert s["all_rules"]["values_in_report"] is None and s["no_report_candidates"] == [] and s["partly_generic"] == 0


# --- the expert rules of the same cases, read the same way ---------------------------------------------------------

def test_the_expert_rule_of_each_case_is_read_like_ours_and_a_missing_file_is_skipped(tmp_path):
    (tmp_path / "gold").mkdir()
    (tmp_path / "gold" / "a.yml").write_text(RULE.replace(
        "    condition: all of selection_*",
        "    filter_main:\n        User: 'SYSTEM'\n    condition: all of selection_* and not filter_main"))
    rows = [{"rule_id": "a", "rule_path": "gold/a.yml"}, {"rule_id": "b", "rule_path": "gold/missing.yml"}]
    experts = expert_health(rows, REFERENCE, {"a": REPORT}, root=tmp_path)
    assert len(experts) == 1
    assert experts[0]["runs"] is True and experts[0]["has_exclusion"] is True and experts[0]["uses_parent"] is True
    assert experts[0]["values"] == 3 and experts[0]["values_in_report"] == 3


def test_a_run_counts_the_log_sources_of_its_first_rules():
    web = RULE.replace("    category: process_creation\n    product: windows", "    category: webserver")
    s = run_summary([case_health(_row([RULE, web]), REFERENCE), case_health(_row([web]), REFERENCE),
                     case_health(_row([]), REFERENCE)])
    assert s["first_rule_logsources"] == {"process_creation": 1, "webserver": 1}
