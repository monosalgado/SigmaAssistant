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
    extract_rule_yamls,
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
