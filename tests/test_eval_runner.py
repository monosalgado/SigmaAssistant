"""Tests for the evaluation runner.

Constraint: fully offline — no VPN, no network, no LLM calls. The integration test
runs the real `PreprocessStage` against a temporary HTML file, which makes no LLM
call when no image is attached.

The important case here is the snapshot interception: if it silently fell through
to the live network, the evaluation would stop being reproducible while still
producing results that looked fine.

See thesis/ENGINEERING_LOG.md, Change 6.
"""

from __future__ import annotations

import pytest

from eval.run_eval import (
    _SnapshotRequests,
    snapshot_key,
    extract_rule_yamls,
    run_case,
    run_cases,
    snapshots_instead_of_network,
    stratified_sample,
    web_enrichment_disabled,
)


# --------------------------------------------------------------------------
# Pulling rules out of the pipeline's markdown response
# --------------------------------------------------------------------------

def test_single_yaml_block_extracted():
    text = "Here is the rule:\n```yaml\ntitle: X\n```\nDone."
    assert extract_rule_yamls(text) == ["title: X"]


def test_multiple_rules_all_extracted():
    """The pipeline can emit several rules; all are kept so best-of-N can be
    computed later without paying for another run."""
    text = "```yaml\ntitle: A\n```\ntext\n```yaml\ntitle: B\n```"
    assert extract_rule_yamls(text) == ["title: A", "title: B"]


def test_uppercase_fence_is_matched():
    assert extract_rule_yamls("```YAML\ntitle: X\n```") == ["title: X"]


def test_response_without_yaml_yields_nothing():
    """A refusal produces no rules; the runner must not invent one."""
    assert extract_rule_yamls("I cannot generate a rule for this.") == []


def test_empty_response_is_safe():
    assert extract_rule_yamls("") == []
    assert extract_rule_yamls(None) == []


# --------------------------------------------------------------------------
# Stratified sampling
# --------------------------------------------------------------------------

def _cases(counts: dict) -> list:
    out = []
    for category, n in counts.items():
        for i in range(n):
            out.append({"rule_id": f"{category}-{i}", "category": category})
    return out


def test_sample_larger_than_population_returns_everything():
    cases = _cases({"a": 3})
    assert len(stratified_sample(cases, 10, seed=0)) == 3


def test_sampling_is_deterministic_for_a_seed():
    cases = _cases({"process_creation": 50, "webserver": 20, "proxy": 5})
    first = [c["rule_id"] for c in stratified_sample(cases, 20, seed=0)]
    second = [c["rule_id"] for c in stratified_sample(cases, 20, seed=0)]
    assert first == second


def test_rare_categories_survive_sampling():
    """A uniform sample would drop the non-Windows categories, which are exactly
    the ones the corpus expansion (A3) was meant to affect."""
    cases = _cases({"process_creation": 120, "webserver": 50, "proxy": 3, "dns": 1})
    sampled = stratified_sample(cases, 30, seed=0)
    categories = {c["category"] for c in sampled}
    assert "proxy" in categories
    assert "dns" in categories


def test_sample_respects_requested_size():
    cases = _cases({"a": 40, "b": 30, "c": 10})
    assert len(stratified_sample(cases, 25, seed=0)) == 25


# --------------------------------------------------------------------------
# Snapshot shim
# --------------------------------------------------------------------------

def test_known_url_is_served_from_disk(tmp_path):
    page = tmp_path / "page.html"
    page.write_bytes(b"<html><body><p>cached</p></body></html>")
    shim = _SnapshotRequests({"https://example.com/a": str(page)})

    response = shim.get("https://example.com/a")
    assert response.status_code == 200
    assert b"cached" in response.content
    assert shim.served == 1


def test_unknown_url_returns_404_rather_than_raising():
    """A missing snapshot should degrade like a dead link in production, not
    crash the run."""
    shim = _SnapshotRequests({})
    response = shim.get("https://example.com/missing")
    assert response.status_code == 404
    assert shim.missed == 1


def test_fragment_url_is_served_from_the_unfragmented_snapshot(tmp_path):
    """The manifest keeps `#fragment`, the pipeline strips it. Without
    normalisation the lookup misses and the case silently loses its only page.
    """
    page = tmp_path / "page.html"
    page.write_bytes(b"<html><body><p>cached</p></body></html>")
    shim = _SnapshotRequests({snapshot_key("https://example.com/a#section-2"): str(page)})

    response = shim.get("https://example.com/a")
    assert response.status_code == 200
    assert shim.served == 1
    assert shim.missed == 0


def test_fragment_is_ignored_in_both_directions(tmp_path):
    """Normalising both sides means it does not matter which form arrives."""
    page = tmp_path / "page.html"
    page.write_bytes(b"<html><body><p>cached</p></body></html>")
    shim = _SnapshotRequests({snapshot_key("https://example.com/a"): str(page)})

    assert shim.get("https://example.com/a#top").status_code == 200
    assert shim.served == 1


def test_snapshot_key_only_strips_the_fragment():
    """Query strings are server-visible and must survive; fragments are not."""
    assert snapshot_key("https://example.com/a?b=1#frag") == "https://example.com/a?b=1"
    assert snapshot_key("https://example.com/a?b=1") == "https://example.com/a?b=1"
    assert snapshot_key("https://example.com/a") == "https://example.com/a"
    # A different page is still a different key.
    assert snapshot_key("https://example.com/a") != snapshot_key("https://example.com/b")


def test_requests_module_is_restored_afterwards():
    """A leaked patch would silently disable network access for the rest of the
    process."""
    import backend.pipeline.stage_preprocess as module

    original = module.requests
    with snapshots_instead_of_network({}):
        assert module.requests is not original
    assert module.requests is original


def test_requests_restored_even_when_the_body_raises():
    import backend.pipeline.stage_preprocess as module

    original = module.requests
    with pytest.raises(ValueError):
        with snapshots_instead_of_network({}):
            raise ValueError("boom")
    assert module.requests is original


# --------------------------------------------------------------------------
# Web-enrichment toggle
# --------------------------------------------------------------------------

class _Client:
    def web_search(self, query):
        return {"text": "live result", "sources": [{"url": "u", "title": "t"}]}


def test_web_enrichment_can_be_stubbed_and_restored():
    client = _Client()
    with web_enrichment_disabled(client, disabled=True):
        assert client.web_search("q") == {"text": "", "sources": []}
    assert client.web_search("q")["text"] == "live result"


def test_web_enrichment_untouched_when_not_disabled():
    client = _Client()
    with web_enrichment_disabled(client, disabled=False):
        assert client.web_search("q")["text"] == "live result"


# --------------------------------------------------------------------------
# Integration: the real stage reads the snapshot, not the network
# --------------------------------------------------------------------------

def test_preprocess_stage_reads_snapshot_instead_of_network(tmp_path):
    """Runs the production PreprocessStage under the shim. If interception ever
    broke, this would attempt a live fetch and the assertion on content would
    fail rather than passing silently."""
    from backend.pipeline.stage_preprocess import PreprocessStage

    page = tmp_path / "advisory.html"
    page.write_bytes(
        b"<html><head><title>Advisory</title></head><body>"
        b"<p>" + b"Attackers ran powershell with an encoded command. " * 20 + b"</p>"
        b"</body></html>"
    )
    url = "https://example.com/advisory"

    stage = PreprocessStage(client=None, model_name="")
    with snapshots_instead_of_network({url: str(page)}) as shim:
        context = stage.run({"original_query": url, "media_file": None})

    assert shim.served == 1
    url_content = context["preprocessed"]["url_content"]
    assert len(url_content) == 1
    assert url_content[0]["url"] == url
    assert "encoded command" in url_content[0]["text"]
    assert url_content[0]["title"] == "Advisory"


def test_missing_snapshot_leaves_no_url_content(tmp_path):
    """A 404 must produce an empty result the pipeline can handle, not an
    exception that aborts the case."""
    from backend.pipeline.stage_preprocess import PreprocessStage

    stage = PreprocessStage(client=None, model_name="")
    with snapshots_instead_of_network({}):
        context = stage.run({"original_query": "https://example.com/gone",
                             "media_file": None})

    assert context["preprocessed"]["url_content"] == []


# --------------------------------------------------------------------------
# One case end to end, with a stand-in pipeline (plan 1.1b)
# --------------------------------------------------------------------------
# The real agent's analyze_attack catches every exception and returns the error as
# ordinary response text. When the harness called it, a crashed case became a
# normal-looking row with error None and zero rules, so gate 4 could never fire.

GENERATED_RULE = """title: Encoded PowerShell
id: 5e3d3601-0000-4000-8000-000000000000
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: ' -enc '
    condition: selection
level: high
"""

GOLD = {
    "title": "Gold",
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {"selection": {"Image|endswith": "\\powershell.exe"},
                  "condition": "selection"},
}


class _Orchestrator:
    def __init__(self, result=None, raises=None):
        self.result, self.raises = result, raises

    def run_sync(self, description, history=None, media_file=None):
        if self.raises:
            raise self.raises
        return self.result


class _Agent:
    """Mirrors the real SigmaAgent, including its catch-all in analyze_attack."""

    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.client = type("C", (), {"web_search": lambda self, q: {}})()

    def analyze_attack(self, description, history=None, media_file=None):
        try:
            return self.orchestrator.run_sync(description=description)
        except Exception as e:
            return {"rule": f"Error during analysis: {e}", "context": {},
                    "pipeline_metadata": None}


def _case():
    return {"rule_id": "r-1", "rule_path": "x.yml", "title": "t",
            "category": "process_creation", "product": "windows",
            "urls": ["https://example.com/a"], "url_to_path": {},
            "text_chars": 5000, "gold": GOLD}


def test_normal_response_is_scored():
    agent = _Agent(_Orchestrator(result={
        "rule": "```yaml\n" + GENERATED_RULE + "```", "context": {},
        "pipeline_metadata": {}}))
    row = run_case(agent, _case(), config={}, no_web_enrich=True)
    assert row["error"] is None
    assert row["n_rules"] == 1
    assert row["scores"]["validity"]["parses"] is True
    assert row["scores"]["logsource"]["exact_match"] is True
    assert "llm_calls" in row and "telemetry" in row


def test_pipeline_crash_becomes_a_case_error():
    agent = _Agent(_Orchestrator(raises=ValueError("boom")))
    row = run_case(agent, _case(), config={}, no_web_enrich=True)
    assert row["error"] == "ValueError: boom"
    assert "boom" in row["traceback"]
    assert row["scores"] is None and row["n_rules"] == 0


def test_snapshot_counts_are_kept_on_a_crash():
    """Gate 1 must be computable for every row, crashed ones included."""
    agent = _Agent(_Orchestrator(raises=RuntimeError("stage failed")))
    row = run_case(agent, _case(), config={}, no_web_enrich=True)
    assert row["snapshots_served"] == 0 and row["snapshots_missed"] == 0
    assert row["poc_snapshots_served"] == 0 and row["poc_snapshots_missed"] == 0


# --------------------------------------------------------------------------
# The row keeps the pipeline's intermediate results (plan 1.1c)
# --------------------------------------------------------------------------

METADATA = {
    "attack_vector": {"vuln_class": "command_injection", "primary_telemetry": "process_creation"},
    "attack_summary": "summary",
    "indicators": [{"value": "powershell.exe", "type": "process"}],
    "ttp_mappings": [{"technique_id": "T1059.001"}],
    "logsource_suggestions": [{"category": "process_creation", "product": "windows"}],
    "logsource_primary": "process_creation/windows",
    "suggested_log_sources": ["Sysmon EID 1"],
    "coverage_check": {"warnings": []},
    "validation_issues": [],
    "poc_snippets_found": 0,
    "generations": [{"rules": 1, "ids_replaced": 0}],
    "generation_retried": False,
    "enrichment_sources": [],          # deliberately not kept: empty on the all-local setup
}


def test_row_keeps_the_diagnosis_fields():
    agent = _Agent(_Orchestrator(result={
        "rule": "```yaml\n" + GENERATED_RULE + "```", "context": {},
        "pipeline_metadata": METADATA}))
    row = run_case(agent, _case(), config={}, no_web_enrich=True)
    kept = row["pipeline"]
    assert kept["attack_vector"]["primary_telemetry"] == "process_creation"
    assert kept["logsource_suggestions"][0]["category"] == "process_creation"
    assert kept["generations"] == [{"rules": 1, "ids_replaced": 0}]
    assert kept["generation_retried"] is False
    assert "enrichment_sources" not in kept


def test_response_text_is_kept_when_no_rule_is_extracted():
    """The two zero-rule baseline cases could not be diagnosed: only the length of
    their 86-character response was stored."""
    agent = _Agent(_Orchestrator(result={
        "rule": "I was unable to generate a rule.", "context": {},
        "pipeline_metadata": METADATA}))
    row = run_case(agent, _case(), config={}, no_web_enrich=True)
    assert row["n_rules"] == 0
    assert row["response_text"] == "I was unable to generate a rule."


def test_response_text_is_not_duplicated_when_rules_exist():
    """rules_yaml already holds the rules; the full text would double the file."""
    agent = _Agent(_Orchestrator(result={
        "rule": "```yaml\n" + GENERATED_RULE + "```", "context": {},
        "pipeline_metadata": METADATA}))
    assert "response_text" not in run_case(agent, _case(), config={}, no_web_enrich=True)


def test_missing_metadata_does_not_break_the_row():
    """Conversational answers return pipeline_metadata None."""
    agent = _Agent(_Orchestrator(result={"rule": "hello", "context": {},
                                         "pipeline_metadata": None}))
    row = run_case(agent, _case(), config={}, no_web_enrich=True)
    assert row["error"] is None and row["pipeline"] == {}


# --------------------------------------------------------------------------
# A case with a failed LLM call is not written; the run stops (plan 1.2, defect 12)
# --------------------------------------------------------------------------
# With the backend unreachable, every stage swallows its failed call and the case
# "completes" in seconds with zero rules. Written, that row made resume skip the
# case. The committed evidence (baseline60.jsonl.corrupt.bak) also holds a second
# shape: a case that hung for 3.6 h with one failed call of five and still wrote
# rules. Both must stop the run instead.

import io
import json as _json

from backend.telemetry import TELEMETRY, stage_scope


class _ScriptedOrchestrator:
    """Per case (keyed by its URL): how many LLM calls succeed and fail, and
    whether the pipeline then raises."""

    def __init__(self, script):
        self.script, self.ran = script, []

    def run_sync(self, description, history=None, media_file=None):
        self.ran.append(description)
        ok, failed, raises = self.script[description]
        for i in range(ok + failed):
            with stage_scope("analysis" if i < ok else "review"):
                TELEMETRY.record(backend="ollama", tier="economy", model="m",
                                 operation="generate", latency_s=0.1, prompt_chars=1,
                                 ok=i < ok, error=None if i < ok else "connection refused")
        if raises:
            raise raises
        return {"rule": "```yaml\n" + GENERATED_RULE + "```", "context": {},
                "pipeline_metadata": {}}


def _cases_for(*names):
    out = []
    for name in names:
        case = _case()
        case["rule_id"], case["urls"] = name, [f"https://example.com/{name}"]
        out.append(case)
    return out


def _run(script_by_name, names):
    orchestrator = _ScriptedOrchestrator(
        {f"https://example.com/{k}": v for k, v in script_by_name.items()})
    out = io.StringIO()
    result = run_cases(_Agent(orchestrator), _cases_for(*names), {}, True, out)
    rows = [_json.loads(line) for line in out.getvalue().splitlines()]
    return result, rows, orchestrator.ran


def test_clean_run_writes_every_case():
    (n_ok, n_failed, stopped), rows, _ = _run(
        {"a": (3, 0, None), "b": (3, 0, None)}, ["a", "b"])
    assert (n_ok, n_failed, stopped) == (2, 0, None)
    assert [r["rule_id"] for r in rows] == ["a", "b"]


def test_all_calls_failed_stops_without_writing_the_row():
    """The defect-12 signature: backend unreachable, every call fails."""
    (n_ok, _, stopped), rows, ran = _run(
        {"a": (3, 0, None), "b": (0, 4, None), "c": (3, 0, None)}, ["a", "b", "c"])
    assert [r["rule_id"] for r in rows] == ["a"]      # b not written
    assert len(ran) == 2                               # c never started
    assert "b" in stopped and "4 of 4" in stopped
    assert n_ok == 1


def test_one_failed_call_also_stops_the_run():
    """The second shape in the evidence: a partial failure that still wrote rules."""
    (_, _, stopped), rows, _ = _run({"a": (4, 1, None)}, ["a"])
    assert rows == []
    assert "1 of 5" in stopped and "review" in stopped


def test_crash_with_every_call_ok_is_written_as_an_error_row():
    """A pipeline bug is a finding about the pipeline, not a connection problem."""
    (n_ok, n_failed, stopped), rows, _ = _run(
        {"a": (3, 0, ValueError("bug")), "b": (3, 0, None)}, ["a", "b"])
    assert stopped is None and (n_ok, n_failed) == (1, 1)
    assert rows[0]["error"] == "ValueError: bug"


def test_the_stop_message_says_how_to_resume():
    (_, _, stopped), _, _ = _run({"a": (0, 2, None)}, ["a"])
    assert "rerun the same command" in stopped.lower()


def test_row_carries_the_cases_contamination_flag():
    """plan 1.3b: the summariser reports clean and flagged cases separately."""
    case = _case()
    case["contamination"] = {"flagged": True,
                             "reasons": [{"reason": "sigma_in_text", "detail": None}]}
    agent = _Agent(_Orchestrator(result={"rule": "no rule", "context": {},
                                         "pipeline_metadata": {}}))
    row = run_case(agent, case, config={}, no_web_enrich=True)
    assert row["contamination"]["flagged"] is True


def test_a_case_without_a_flag_is_recorded_as_unknown():
    agent = _Agent(_Orchestrator(result={"rule": "no rule", "context": {},
                                         "pipeline_metadata": {}}))
    assert run_case(agent, _case(), config={}, no_web_enrich=True)["contamination"] is None
