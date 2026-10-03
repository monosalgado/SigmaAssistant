"""Change 40's prompt change removed (user 2026-10-03: "remove change 40, keep 39").

The two-arm run (log 2026-10-03) did not pass its gate: S5vu 0.105 -> 0.075 (-0.030, 95% CI [-0.065, +0.003]),
and the first rule's share of indicators barely moved (6.8% -> 8.2%). The rule-writing prompt goes back to its
form before Change 40 (indicators as a JSON dump under the attack summary, the earlier instruction 12). Kept:
the record of which indicators the rules use (measurement only), and Change 39. Offline; no LLM.
"""

from __future__ import annotations

import json

from backend.pipeline import prompts

T = prompts.RULE_GENERATION
RULE = ("title: t\nlogsource: {category: process_creation, product: windows}\ndetection:\n"
        "  selection:\n    Image|endswith: '\\\\schtasks.exe'\n  condition: selection\n")


def test_the_indicators_are_back_under_the_attack_summary():
    assert "Strings the Report Gives" not in T
    assert T.index("### Attack Summary") < T.index("### Extracted Threat Indicators\n{indicators}")


def test_instruction_12_is_the_earlier_one():
    line = next(l for l in T.splitlines() if l.startswith("12. "))
    assert line == ("12. Include specific detection criteria based on the extracted indicators; "
                    "small details improve specificity.")


def test_the_rule_writer_gets_the_indicators_as_before():
    from backend.pipeline import stage_generate
    assert not hasattr(stage_generate, "format_indicators")


def test_change_39_stays():
    from eval.count_example_copies import INLINE_EXAMPLES
    for example in INLINE_EXAMPLES:
        assert example not in prompts.ATTACK_VECTOR_EXTRACTION.lower()


def test_the_pipeline_still_records_which_indicators_the_rules_use():
    from backend.pipeline.orchestrator import PipelineOrchestrator
    from eval.run_eval import DIAGNOSIS_FIELDS
    context = {"attack_vector": {}, "generation": {"rules": [{"yaml_content": RULE}]},
               "extraction": {"indicators": [{"value": "schtasks.exe"}, {"value": "CVE-2024-1"}]}}
    PipelineOrchestrator._run_coverage_check(None, context)
    assert context["indicator_use"] == {"given": 2, "used": ["schtasks.exe"], "unused": ["CVE-2024-1"]}
    assert PipelineOrchestrator._pipeline_metadata(context)["indicator_use"] == context["indicator_use"]
    assert "indicator_use" in DIAGNOSIS_FIELDS
