"""Tests for Change 45, part 4: the web stage's place, record and evaluation mode (user 2026-10-06; design in the log).

- The web stage runs after the PoC stage (the PoC stage scans the text for GitHub links; it should read only the
  report's own), in both the synchronous and the streamed/assisted paths.
- What the web stage did is saved with the row (`pipeline_metadata["web_enrichment"]`, `run_eval.DIAGNOSIS_FIELDS`).
- The evaluation never searches live: `run_eval.py` needs `--no-web-enrich` or `--web-snapshots FILE` (not both); with
  a file, every query is answered from it (a missing one is recorded as missing), nothing is sent, and rule pages are
  dropped (`exclude_rule_pages`); the file and its SHA-256 are recorded in the run's config.
Offline.
"""

from __future__ import annotations

import inspect
import json
from types import SimpleNamespace

from backend.pipeline.orchestrator import PipelineOrchestrator
from backend.pipeline.stage_web_enrich import WebEnrichStage
from eval import run_eval

PAGE = {"title": "T", "url": "https://a.example/x", "content": "page text"}


def _order(method) -> bool:
    source = inspect.getsource(method)
    return source.index("self.poc_analysis.run(") < source.index("self.web_enrich.run(")


def test_the_web_stage_runs_after_the_poc_stage_in_every_path():
    assert _order(PipelineOrchestrator.run_sync)
    assert _order(PipelineOrchestrator._analysis_events)


def test_the_web_record_is_saved_with_the_row():
    record = {"search_queries": ["q"], "results": [{"url": "u", "reason": None}], "digest": {"kept": []}}
    assert PipelineOrchestrator._pipeline_metadata({"enrichment": record})["web_enrichment"] == record
    assert "web_enrichment" in run_eval.DIAGNOSIS_FIELDS


def test_the_evaluation_needs_the_web_off_or_a_saved_file(tmp_path):
    snap = tmp_path / "snap.jsonl"
    snap.write_text("")
    assert run_eval.web_mode_error(False, None)                     # would search live
    assert run_eval.web_mode_error(True, str(snap))                 # both
    assert run_eval.web_mode_error(False, str(tmp_path / "none"))   # the file does not exist
    assert run_eval.web_mode_error(True, None) is None
    assert run_eval.web_mode_error(False, str(snap)) is None


def test_with_a_saved_file_queries_are_answered_from_it_and_rule_pages_are_dropped(tmp_path):
    snap = tmp_path / "snap.jsonl"
    snap.write_text(json.dumps({"query": "saved q", "results": [PAGE], "error": None}) + "\n")
    client = SimpleNamespace(web_search=lambda q: (_ for _ in ()).throw(AssertionError("sent live")))
    stage = WebEnrichStage(client, "fake")
    agent = SimpleNamespace(client=client, orchestrator=SimpleNamespace(web_enrich=stage))
    with run_eval.web_search_from_file(agent, str(snap)):
        assert stage.exclude_rule_pages is True
        hit = client.web_search("saved q")
        miss = client.web_search("other q")
    assert hit["results"] == [PAGE] and hit["error"] is None
    assert miss["results"] == [] and miss["error"] == "not in the saved file"
    assert stage.exclude_rule_pages is False
    try:
        client.web_search("after")
        raise AssertionError("the live search was not restored")
    except AssertionError as e:
        assert str(e) == "sent live"


def test_the_run_config_records_the_saved_file_and_its_hash(tmp_path):
    snap = tmp_path / "snap.jsonl"
    snap.write_text("x\n")
    args = SimpleNamespace(arm="a", no_web_enrich=False, web_snapshots=str(snap), min_chars=2000, code=None)
    agent = SimpleNamespace(client=SimpleNamespace(model_name="m"))
    config = run_eval.run_config(agent, args, head_revision=lambda: "abc")
    assert config["web_enrich"] is True and config["web_snapshots"]["path"] == str(snap)
    assert len(config["web_snapshots"]["sha256"]) == 64


def test_the_progress_message_says_what_the_web_stage_did():
    from backend.pipeline.stage_web_enrich import web_detail
    assert "limit" in web_detail({"limited": True, "results": [], "search_queries": ["q"]}).lower()
    done = web_detail({"search_queries": ["q"], "sources": [{"url": "a"}, {"url": "b"}],
                       "results": [{}, {}, {}], "rule_pages": ["r"], "digest": {"kept": [{}] * 4}})
    assert "2 pages read" in done and "4 findings" in done and "1 published rule" in done
    assert web_detail({}) == "No web search"
