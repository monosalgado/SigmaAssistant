"""Offline tests for Change 28 (plan 2.6): the analysis prompt's log-source reference table
lists every log source SigmaHQ's main rule set uses — generated, not hand-written.

Why: the hand-written table had 13 rows, no source without a category (so the gold rules
defined by a service — Windows Security, zeek/http — were never suggested), and cells the
model copied into its answers: "linux-windows/apache-iis" as the product of web suggestions
(no SigmaHQ web rule has a product), "windows/sysmon". The table is built from
`data/sigma/rules` — the rules the retrieval index uses — never from
`rules-emerging-threats`, which holds the evaluation's answers. The model still chooses.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.pipeline import prompts
from backend.pipeline.sigma_logsource import (
    FIELDS_PER_SOURCE,
    LOGSOURCE_TABLE_PATH,
    build_logsource_table,
    detection_fields,
    format_category_table,
    format_service_table,
    load_known_services,
    load_logsource_table,
    on_table,
)
from backend.pipeline.stage_analysis import AnalysisStage

REPO = Path(__file__).resolve().parent.parent

RULES = {
    "pc_win.yml": """
title: a
logsource: {category: process_creation, product: windows}
detection:
    selection: {Image|endswith: '\\\\x.exe', CommandLine|contains: 'y'}
    condition: selection
""",
    "pc_lin.yml": """
title: b
logsource: {category: process_creation, product: linux}
detection:
    selection:
        - {Image|endswith: '/bin/z'}
        - {User: root}
    condition: selection
""",
    "web.yml": """
title: c
logsource: {category: webserver}
detection:
    selection: {cs-uri-query|contains: 'a', cs-method: POST}
    condition: selection
""",
    "sec.yml": """
title: d
logsource: {product: windows, service: security}
detection:
    selection: {EventID: 4624, LogonType: 3}
    condition: selection
""",
    "ct.yml": """
title: e
logsource: {product: aws, service: cloudtrail}
detection:
    selection: {eventName: X, eventSource: Y}
    timeframe: 5m
    condition: selection
""",
    "fe_sysmon.yml": """
title: f
logsource: {category: file_event, product: windows, service: sysmon}
detection:
    selection: {TargetFilename|endswith: '.dll'}
    condition: selection
""",
    "proxy_kw.yml": """
title: g
logsource: {category: proxy}
detection:
    keywords: ['a', 'b']
    condition: keywords
""",
    "linux_only.yml": """
title: h
logsource: {product: linux}
detection:
    keywords: ['segfault']
    condition: keywords
""",
    "broken.yml": "title: [unclosed\n",
}


@pytest.fixture
def table(tmp_path):
    for name, body in RULES.items():
        (tmp_path / name).write_text(body, encoding="utf-8")
    return build_logsource_table(tmp_path)


def _cat(table, name):
    return next(r for r in table["with_category"] if r["category"] == name)


def _svc(table, product, service):
    return next(r for r in table["without_category"]
                if r["product"] == product and r["service"] == service)


# --- building the table from rules ---------------------------------------

def test_a_category_lists_the_products_its_rules_use(table):
    assert _cat(table, "process_creation")["products"] == ["linux", "windows"]


def test_a_category_whose_rules_have_no_product_says_so(table):
    """webserver/proxy rules carry no product; the table must not invent one."""
    assert _cat(table, "webserver")["products"] == [None]
    assert _cat(table, "proxy")["products"] == [None]


def test_rules_without_a_category_are_listed_by_product_and_service(table):
    assert _svc(table, "windows", "security")["fields"] == ["EventID", "LogonType"]
    assert _svc(table, "aws", "cloudtrail")["fields"] == ["eventName", "eventSource"]
    assert _svc(table, "linux", None)["fields"] == []


def test_a_category_rule_that_also_names_a_service_is_listed_under_its_category_only(table):
    assert _cat(table, "file_event")["products"] == ["windows"]
    assert all(r["service"] != "sysmon" for r in table["without_category"])


def test_fields_come_from_the_detection_without_modifiers_most_used_first(table):
    assert _cat(table, "process_creation")["fields"] == ["Image", "CommandLine", "User"]
    assert _cat(table, "webserver")["fields"] == ["cs-method", "cs-uri-query"]


def test_keyword_detections_add_no_fields_and_broken_files_are_skipped(table):
    assert _cat(table, "proxy")["fields"] == []
    assert len(table["with_category"]) == 4 and len(table["without_category"]) == 3


def test_rows_are_in_alphabetical_order_not_by_frequency(table):
    """Order carries no hint about which source is common."""
    cats = [r["category"] for r in table["with_category"]]
    assert cats == sorted(cats)


def test_detection_fields_reads_maps_and_lists_of_maps():
    det = {"sel": {"A|contains": 1, "B": 2}, "sel2": [{"C|endswith": 3}, {"A": 4}],
           "kw": ["x"], "condition": "sel", "timeframe": "1m"}
    assert detection_fields(det) == {"A", "B", "C"}


def test_fields_are_capped_per_source(tmp_path):
    many = {f"F{i}": i for i in range(FIELDS_PER_SOURCE + 3)}
    (tmp_path / "r.yml").write_text(json.dumps({
        "title": "x", "logsource": {"category": "c"},
        "detection": {"s": many, "condition": "s"}}), encoding="utf-8")
    assert len(build_logsource_table(tmp_path)["with_category"][0]["fields"]) == FIELDS_PER_SOURCE


# --- rendering for the prompt --------------------------------------------

def test_the_category_table_shows_a_missing_product_as_none(table):
    text = format_category_table(table)
    assert "| webserver | (none) | cs-method, cs-uri-query |" in text
    assert "| process_creation | linux, windows | Image, CommandLine, User |" in text


def test_the_service_table_has_one_row_per_product_and_service(table):
    text = format_service_table(table)
    assert "| windows | security | EventID, LogonType |" in text
    assert "| linux | (none) |" in text


# --- the spec check (used to measure; nothing is enforced) ---------------

@pytest.mark.parametrize("sug, expected", [
    ({"category": "webserver"}, True),
    ({"category": "webserver", "product": "-"}, True),
    ({"category": "webserver", "product": "linux-windows/apache-iis"}, False),
    ({"category": "process_creation", "product": "Windows"}, True),
    ({"category": "process_creation", "product": "windows", "service": "sysmon"}, False),
    ({"category": "process_creation"}, False),
    ({"product": "windows", "service": "security"}, True),
    ({"category": "-", "product": "aws", "service": "cloudtrail"}, True),
    ({"product": "windows", "service": "made_up"}, False),
    ({"category": "email"}, False),
    ({}, False),
])
def test_a_suggestion_is_on_the_table_only_in_one_of_the_two_forms(table, sug, expected):
    assert on_table(sug, table) is expected


# --- the committed table --------------------------------------------------

def test_the_committed_table_is_complete_and_from_the_main_rule_set():
    t = load_logsource_table()
    assert t["source"] == "data/sigma/rules"
    cats = {r["category"]: r for r in t["with_category"]}
    assert len(cats) == 35
    assert cats["webserver"]["products"] == [None] and cats["proxy"]["products"] == [None]
    assert cats["process_creation"]["products"] == ["linux", "macos", "windows"]
    pairs = {(r["product"], r["service"]) for r in t["without_category"]}
    assert {("windows", "security"), ("zeek", "http"), ("aws", "cloudtrail")} <= pairs
    assert ("fortios", "sslvpnd") not in pairs  # emerging-threats only


def test_the_service_rows_are_exactly_change_25s_known_services():
    """One definition of 'a service SigmaHQ uses', so the two can never disagree."""
    t = load_logsource_table()
    with_service = {(r["product"], r["service"]) for r in t["without_category"] if r["service"]}
    assert with_service == load_known_services()


def test_the_committed_table_is_what_the_script_builds():
    rules = REPO / "data/sigma/rules"
    if not rules.is_dir():
        pytest.skip("data/sigma not present (rebuilt locally, not committed)")
    t = load_logsource_table()
    built = build_logsource_table(rules)
    assert built["with_category"] == t["with_category"]
    assert built["without_category"] == t["without_category"]


def test_the_table_file_is_where_the_code_reads_it():
    assert LOGSOURCE_TABLE_PATH.name == "sigma_logsource_table.json"
    assert LOGSOURCE_TABLE_PATH.is_file()


# --- the prompt ----------------------------------------------------------

def test_the_hand_written_cells_are_gone():
    assert "linux-windows/apache-iis" not in prompts.COMBINED_ANALYSIS
    assert "windows/sysmon" not in prompts.COMBINED_ANALYSIS
    assert "aws/azure/gcp" not in prompts.COMBINED_ANALYSIS


def test_the_prompt_takes_both_generated_tables():
    assert "{logsource_categories}" in prompts.COMBINED_ANALYSIS
    assert "{logsource_services}" in prompts.COMBINED_ANALYSIS


def test_the_prompt_explains_the_two_forms_of_a_log_source():
    part3 = prompts.COMBINED_ANALYSIS.split("## PART 3")[1]
    assert "category and a product" in part3
    assert "product and a service, without a category" in part3


def test_the_output_example_follows_sigmas_convention():
    """A category with no service; no Sysmon wording for the model to copy."""
    example = prompts.COMBINED_ANALYSIS.split('"logsource_suggestions"')[1]
    assert '"service": null' in example
    assert "sysmon" not in example.lower()


# --- where it applies ----------------------------------------------------

class _Capture:
    model_name = "fake"

    def __init__(self):
        self.prompt = None

    def generate(self, prompt, **kwargs):
        self.prompt = prompt
        return json.dumps({"indicators": [], "ttp_mappings": [], "logsource_suggestions": []})


class _NoRag:
    def search(self, *args, **kwargs):
        return {}


def test_the_analysis_stage_puts_the_committed_tables_in_its_prompt():
    client = _Capture()
    ctx = {"preprocessed": {"combined_text": "text", "segments": [], "url_content": []}}
    AnalysisStage(client, "fake", _NoRag()).run(ctx)
    t = load_logsource_table()
    assert format_category_table(t) in client.prompt
    assert format_service_table(t) in client.prompt
    assert "| windows | security |" in client.prompt
