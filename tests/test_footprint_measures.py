"""Offline tests for eval/footprint_measures.py: Change 54's mechanism measures, as fixed in its plan (log 2026-11-08,
read C against B since the plan's revision of 2026-11-09): M1 the footprint has a step on SigmaHQ's table, M2 a rule
uses a parent-process field (paired, exact McNemar), M3 the rules follow the footprint, and the descriptive count of
rules that treat a module as a program."""

from __future__ import annotations

from eval.footprint_measures import (
    case_measures,
    module_as_program,
    step_followed,
    summary,
    uses_parent_field,
)

CHILD = """title: Shell under the service
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\\\\java.exe'
        Image|endswith: '\\\\cmd.exe'
    condition: selection
"""
PLAIN = CHILD.replace("        ParentImage|endswith: '\\\\java.exe'\n", "")
LOAD = """title: Module loaded
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\\\\evil.dll'
    condition: selection
"""
TASK = """title: Task
logsource:
    product: windows
    service: taskscheduler
detection:
    selection:
        EventID: 106
    condition: selection
"""


def _step(log_source, action="starts", on_table=True):
    return {"log_source": log_source, "actor": "a", "action": action, "target": "t", "derived_from": "q",
            "on_table": on_table}


def _row(rule_id, rules, steps=None):
    vector = {} if steps is None else {"host_footprint": steps}
    return {"rule_id": rule_id, "rules_yaml": list(rules), "pipeline": {"attack_vector": vector}}


def test_a_parent_process_field_is_parentimage_or_parentcommandline_with_any_modifier():
    assert uses_parent_field(CHILD) is True
    assert uses_parent_field(CHILD.replace("ParentImage|endswith", "ParentCommandLine|contains")) is True
    assert uses_parent_field(PLAIN) is False
    assert uses_parent_field(PLAIN.replace("Image|endswith", "ParentUser")) is False
    assert uses_parent_field("not: [a rule") is False


def test_a_step_is_followed_by_a_rule_in_its_category_or_its_product_and_service():
    assert step_followed(_step("process_creation"), [CHILD]) is True
    assert step_followed(_step("image_load"), [CHILD]) is False
    assert step_followed(_step("windows/taskscheduler"), [CHILD, TASK]) is True
    assert step_followed(_step("windows/security"), [TASK]) is False


def test_a_module_written_as_a_program_is_an_image_ending_in_dll_or_sys_in_a_process_creation_rule():
    assert module_as_program(PLAIN.replace("cmd.exe", "evil.dll")) is True
    assert module_as_program(PLAIN.replace("cmd.exe", "driver.SYS")) is True
    assert module_as_program(PLAIN) is False
    assert module_as_program(LOAD) is False                    # a load rule is where a module belongs


def test_a_case_without_a_footprint_has_no_m1_and_nothing_to_follow():
    case = case_measures(_row("a", [CHILD]))
    assert case["steps"] == 0 and case["m1"] is False and case["parent_rule"] is True
    assert case["m3_source"] is None and case["m3_parent"] is None and case["m3_parent_in_source"] is None


def test_m1_needs_a_step_on_the_table():
    assert case_measures(_row("a", [PLAIN], [_step("made_up", on_table=False)]))["m1"] is False
    assert case_measures(_row("a", [PLAIN], [_step("made_up", on_table=False), _step("image_load", "loads")]))["m1"] is True


def test_m3_reads_only_the_steps_on_the_table():
    followed = case_measures(_row("a", [LOAD], [_step("image_load", "loads")]))
    assert followed["m3_source"] is True and followed["m3_parent"] is None     # no `starts` step: nothing to ask
    missed = case_measures(_row("a", [LOAD], [_step("process_creation"), _step("image_load", "loads", on_table=False)]))
    assert missed["m3_source"] is False and missed["m3_parent"] is False


def test_for_a_starts_step_a_parent_field_is_asked_anywhere_and_in_the_steps_own_log_source():
    in_source = case_measures(_row("a", [CHILD], [_step("process_creation")]))
    assert in_source["m3_parent"] is True and in_source["m3_parent_in_source"] is True
    elsewhere = TASK.replace("EventID: 106", "ParentImage: 'x'")
    apart = case_measures(_row("a", [PLAIN, elsewhere], [_step("process_creation")]))
    assert apart["m3_source"] is True and apart["m3_parent"] is True and apart["m3_parent_in_source"] is False


def test_the_summary_pairs_m2_over_the_cases_both_runs_have():
    a = [_row("1", [PLAIN]), _row("2", [CHILD]), _row("3", [PLAIN]), _row("only-a", [CHILD])]
    b = [_row("1", [CHILD], [_step("process_creation")]), _row("2", [CHILD], [_step("process_creation")]),
         _row("3", [PLAIN], [_step("image_load", "loads")])]
    s = summary(a, b)
    assert s["cases"] == 3
    assert s["m2"]["a_true"] == 1 and s["m2"]["b_true"] == 2 and s["m2"]["only_a"] == 0 and s["m2"]["only_b"] == 1
    assert s["m2"]["p"] == 1.0


def test_the_summary_counts_m1_and_m3_in_the_second_run():
    a = [_row("1", [PLAIN]), _row("2", [PLAIN]), _row("3", [PLAIN])]
    b = [_row("1", [CHILD], [_step("process_creation")]), _row("2", [PLAIN], [_step("image_load", "loads")]),
         _row("3", [PLAIN], [_step("made_up", on_table=False)])]
    s = summary(a, b)
    assert s["m1"] == 2
    assert s["m3_source"] == {"followed": 1, "of": 2}
    assert s["m3_parent"] == {"followed": 1, "of": 1} and s["m3_parent_in_source"] == {"followed": 1, "of": 1}
    assert s["steps"] == {"total": 3, "on_table": 2, "by_action": {"starts": 2, "loads": 1}}


def test_the_summary_counts_modules_written_as_programs_in_both_runs():
    module = PLAIN.replace("cmd.exe", "evil.dll")
    s = summary([_row("1", [module, PLAIN])], [_row("1", [PLAIN], [_step("process_creation")])])
    assert s["module_as_program"] == {"a": {"rules": 1, "cases": 1}, "b": {"rules": 0, "cases": 0}}
