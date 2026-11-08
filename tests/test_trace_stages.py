"""Offline tests for eval/trace_stages.py - Diagnosis D1 (rule generation; plan in the log 2026-11-08): each saved
web-app run's stage outputs side by side, with the words for the attack's host behaviour marked. The marks help the
reading; they are not a measure."""

from __future__ import annotations

from eval.trace_stages import final_message, input_lines, marks, stages, summary_row

RULE = "title: Java Shell\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    ParentImage|endswith: '\\\\java.exe'\n"


def _session(with_state=True):
    meta = {"poc_attack_flow": "The payload runs cmd.exe through ProcessBuilder",
            "poc_behavioral_indicators": [{"value": "cmd.exe /c calc", "type": "command"}],
            "web_enrichment": {"additional_context": "Attackers ran certutil."},
            "attack_vector": {"protocol": "TCP", "primary_telemetry": "network_connection",
                              "kill_chain_stages": ["initial access", "execution"]},
            "attack_summary": "Deserialization in ActiveMQ.", "indicators": [{"value": "61616", "type": "port"}],
            "ttp_mappings": [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"}],
            "logsource_suggestions": [{"category": "network_connection", "product": "windows", "reasoning": "port"}],
            "logsource_primary": "network_connection/windows", "pre_review_rules": [RULE]}
    final = {"role": "assistant", "content": f"Rules:\n```yaml\n{RULE}```\n", "pipeline_metadata": meta,
             "context": {"sigma": ["title: Example\nlogsource:\n  category: process_creation\n"]}}
    msgs = [{"role": "user", "content": "https://example.org/report"}]
    if with_state:
        msgs.append({"role": "assistant", "content": "", "pipeline_metadata": meta,
                     "state": {"preprocessed": {"combined_text": "Intro line.\nThe bean starts cmd via ProcessBuilder.\n"
                                                                  "Unrelated line about Java versions.\nEnd."}}})
    msgs.append(final)
    return msgs


def test_marks_find_the_parent_the_child_and_the_log_words():
    found = marks("java.exe spawned cmd.exe; see ParentImage in process_creation; PowerShell too")
    assert found["parent"] == ["java.exe", "parentimage", "spawned"]
    assert found["child"] == ["cmd.exe", "powershell"]
    assert found["log"] == ["process_creation"]


def test_shell_inside_powershell_is_not_a_second_mark():
    assert marks("PowerShell")["child"] == ["powershell"]


def test_the_final_message_is_the_last_assistant_message_with_stage_outputs():
    session = _session()
    assert final_message(session) is session[-1]


def test_stages_come_in_pipeline_order_with_the_input_when_saved():
    names = [name for name, _ in stages(_session())]
    assert names == ["input", "poc", "web", "attack_vector", "analysis", "examples", "rules_before_review", "rules"]
    text = dict(stages(_session()))
    assert "ProcessBuilder" in text["input"] and "primary_telemetry: network_connection" in text["attack_vector"]
    assert text["rules"].startswith("title: Java Shell") and "certutil" in text["web"]


def test_an_input_that_was_not_saved_is_shown_as_such():
    assert dict(stages(_session(with_state=False)))["input"] is None


def test_input_lines_keep_only_lines_with_a_parent_or_child_mark():
    lines, total = input_lines("Intro line.\nThe bean starts cmd via ProcessBuilder.\nJava versions.\nEnd.", cap=10)
    assert lines == ["The bean starts cmd via ProcessBuilder.", "Java versions."] and total == 2
    lines, total = input_lines("cmd one\ncmd two\ncmd three", cap=2)
    assert len(lines) == 2 and total == 3


def test_the_summary_row_lists_each_stages_marks():
    row = summary_row(_session())
    assert row["poc"]["child"] == ["cmd.exe"] and row["poc"]["parent"] == ["processbuilder"]
    assert row["attack_vector"]["log"] == [] and row["rules"]["log"] == ["process_creation"]
    assert row["input"]["child"] == ["cmd"]
