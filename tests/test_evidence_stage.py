"""Tests for Change 41 (user 2026-10-03: "design the split"; chose "Like payload patterns" and "Leave it as is"):
a separate evidence step copies, verbatim, the strings in the report a detection rule could match on; code keeps
only those the report really contains and adds them to the payload signatures the rule writer already follows.

Why (tuning set, log 2026-10-03): of the human rules' values that occur in the report, the first rule uses about
a quarter. About a third of the misses were never passed on by any step; the rest were mostly offered in the
analysis's long, mixed indicator list (median 20 per case), which the rule writer does not use - also when that
list is presented as "the strings the report gives" (Change 40: no gain). The payload signatures - a short list,
checked by code with one retry - are used (76%). So the report's own strings join that list, checked first.

The model decides which strings; code only checks them against the report and records. The analysis is unchanged.
Offline: stand-in clients; no LLM.
"""

from __future__ import annotations

import json
import re

from backend.pipeline import prompts
from backend.pipeline.stage_attack_vector import AttackVectorStage
from backend.pipeline.stage_evidence import MAX_ITEMS, EvidenceStage, check_evidence

P = prompts.EVIDENCE_EXTRACTION
REPORT = ("The loader runs reg.exe save HKLM\\SAM %TEMP%\\~reg_sam.save and then\n"
          "   cmd.exe /c wmic /node:10.0.0.5 process call create. It writes C:\\Users\\Public\\winupd.log.")


# --- the prompt ------------------------------------------------------------------------------

def test_the_prompt_asks_for_strings_copied_exactly_as_the_report_writes_them():
    t = " ".join(P.lower().split())
    assert "exactly as the report writes" in t and "do not complete, shorten, generalise or invent" in t
    assert f"at most {MAX_ITEMS}" in t


def test_the_prompt_gets_the_report_the_attack_and_the_strings_to_leave_out():
    filled = P.format(text="REPORT", attack_vector_summary="VECTOR", incidental="AVOID")
    assert "REPORT" in filled and "VECTOR" in filled and "AVOID" in filled


def test_the_prompts_example_holds_placeholders_only():
    body = P[P.index("{{"):].replace("{{", "{").replace("}}", "}")
    example = json.loads(body[:body.rindex("}") + 1].split("\nIf the report")[0])
    item = example["evidence"][0]
    assert set(item) == {"string", "quote", "kind", "activity"}
    assert all(str(v).startswith("<") and str(v).endswith(">") for v in item.values())


def test_the_prompt_names_no_value_and_no_log_source():
    assert not re.search(r"`[^`<]+`", P)                       # no literal example value
    for name in ("process_creation", "webserver", "file_event", "registry_set"):
        assert name not in P


# --- the check -------------------------------------------------------------------------------

def _item(string, kind="command_line", quote="q", activity="a"):
    return {"string": string, "kind": kind, "quote": quote, "activity": activity}


def test_a_string_the_report_contains_is_kept_whatever_its_case_spacing_or_escaping():
    kept, dropped = check_evidence([_item("REG.EXE save hklm\\\\sam %temp%\\\\~reg_sam.save"),
                                    _item("cmd.exe /c  wmic /node:10.0.0.5")], REPORT, [], [])
    assert [k["pattern"] for k in kept] == ["REG.EXE save hklm\\\\sam %temp%\\\\~reg_sam.save",
                                           "cmd.exe /c  wmic /node:10.0.0.5"]
    assert dropped == []


def test_a_string_the_report_does_not_contain_is_dropped_and_recorded():
    kept, dropped = check_evidence([_item("powershell -enc"), _item("winupd.log")], REPORT, [], [])
    assert [k["pattern"] for k in kept] == ["winupd.log"]
    assert dropped == [{"string": "powershell -enc", "reason": "not in the report"}]


def test_incidental_duplicate_short_and_surplus_strings_are_dropped():
    items = [_item("winupd.log"), _item("winupd.log"), _item("ab"), _item("wmic /node:"), _item("reg.exe save")]
    kept, dropped = check_evidence(items, REPORT, incidental=["C:\\Users\\Public"],
                                   existing_patterns=["reg.exe save"])
    assert [k["pattern"] for k in kept] == ["winupd.log", "wmic /node:"]
    assert [d["reason"] for d in dropped] == ["duplicate", "too short", "duplicate"]
    many = [_item(w) for w in REPORT.split() if len(w) > 3]
    assert len(check_evidence(many, REPORT, [], [])[0]) == MAX_ITEMS


def test_a_string_on_the_incidental_list_is_dropped():
    kept, dropped = check_evidence([_item("C:\\Users\\Public\\winupd.log")], REPORT,
                                   incidental=[{"value": "C:\\Users\\Public\\winupd.log"}], existing_patterns=[])
    assert kept == [] and dropped == [{"string": "C:\\Users\\Public\\winupd.log", "reason": "incidental"}]


def test_a_kept_string_becomes_a_payload_signature_marked_as_evidence():
    kept, _ = check_evidence([_item("winupd.log", kind="file_path", quote="It writes C:\\Users\\Public\\winupd.log.",
                                    activity="drops a log")], REPORT, [], [])
    assert kept == [{"pattern": "winupd.log", "where": "file_path",
                     "derived_from": "It writes C:\\Users\\Public\\winupd.log.", "source": "evidence",
                     "activity": "drops a log"}]


# --- the stage -------------------------------------------------------------------------------

class _Client:
    model_name = "fake"

    def __init__(self, answer=None, fail=False):
        self.answer, self.fail, self.prompts = answer, fail, []

    def generate(self, prompt, **kwargs):
        self.prompts.append(prompt)
        if self.fail:
            raise RuntimeError("timed out")
        return json.dumps(self.answer)


def _context():
    return {"preprocessed": {"combined_text": REPORT},
            "attack_vector": {"initial_access_vector": "a loader", "payload_signatures": [
                {"pattern": "reg.exe save", "where": "process_cmdline", "derived_from": "x"}],
                "incidental_artifacts": []}}


def test_the_stage_adds_the_kept_strings_to_the_payload_signatures_and_records_everything():
    client = _Client({"evidence": [_item("wmic /node:"), _item("powershell -enc"), _item("reg.exe save")]})
    context = EvidenceStage(client, "fake").run(_context())
    patterns = [s["pattern"] for s in context["attack_vector"]["payload_signatures"]]
    assert patterns == ["reg.exe save", "wmic /node:"]
    assert context["evidence"] == {"proposed": 3, "kept": ["wmic /node:"], "error": None,
                                   "dropped": [{"string": "powershell -enc", "reason": "not in the report"},
                                               {"string": "reg.exe save", "reason": "duplicate"}]}
    assert "cmd.exe /c wmic" in " ".join(client.prompts[0].split())       # the report reached the prompt


def test_if_the_call_fails_nothing_is_added():
    context = EvidenceStage(_Client(fail=True), "fake").run(_context())
    assert [s["pattern"] for s in context["attack_vector"]["payload_signatures"]] == ["reg.exe save"]
    assert context["evidence"]["kept"] == [] and "timed out" in context["evidence"]["error"]


def test_the_rule_writer_sees_up_to_sixteen_payload_signatures():
    av = {"payload_signatures": [{"pattern": f"p{i}", "where": "w", "derived_from": "d"} for i in range(20)]}
    assert len(AttackVectorStage.format_payload_signatures(av).splitlines()) == 16


# --- in the pipeline -------------------------------------------------------------------------

def test_the_evidence_step_runs_after_the_attack_vector_and_before_the_analysis():
    import inspect
    from backend.pipeline.orchestrator import PipelineOrchestrator
    for method in (PipelineOrchestrator.run_sync, PipelineOrchestrator._analysis_events):
        src = inspect.getsource(method)
        assert src.index("self.attack_vector.run") < src.index("self.evidence.run") < src.index("self.analysis.run")


def test_the_record_reaches_the_saved_results():
    from backend.pipeline.orchestrator import PipelineOrchestrator
    from eval.run_eval import DIAGNOSIS_FIELDS
    assert PipelineOrchestrator._pipeline_metadata({"evidence": {"kept": ["x"]}})["evidence"] == {"kept": ["x"]}
    assert "evidence" in DIAGNOSIS_FIELDS
