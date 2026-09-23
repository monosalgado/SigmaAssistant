"""Serving the PoC stage's GitHub fetches from snapshots (plan 1.3a, defect 16).

Offline: files in tmp_path, a stand-in fetch function for the builder, and a fake
LLM client. The PoC stage used to fetch GitHub live during evaluation, outside the
page snapshots, so 43 of 303 cases were not reproducible.
"""

from __future__ import annotations

import json

import pytest

import backend.pipeline.stage_poc_analysis as poc_module
from backend.pipeline.stage_poc_analysis import PoCAnalysisStage
from eval.build_poc_snapshots import snapshot_urls
from eval.run_eval import load_github_manifest, poc_snapshots_instead_of_network

RAW = "https://raw.githubusercontent.com/acme/exploit/main/poc.py"
GIST = "https://api.github.com/gists/abc123"
GONE = "https://raw.githubusercontent.com/acme/deleted/main/x.py"


class _Resp:
    def __init__(self, status_code, content=b""):
        self.status_code, self.content = status_code, content


def _fetch(url):
    return {RAW: _Resp(200, b"import os\nos.system('whoami')\n"),
            GIST: _Resp(200, json.dumps({"files": {"a.sh": {"content": "curl x | sh",
                                                             "language": "Shell"}}}).encode()),
            GONE: _Resp(404)}[url]


@pytest.fixture
def store(tmp_path):
    manifest = tmp_path / "github_manifest.jsonl"
    snapshot_urls([RAW, GIST, GONE], tmp_path / "github", manifest, fetch=_fetch)
    return manifest


def test_builder_records_every_url_with_its_status(store):
    entries = {json.loads(l)["fetch_url"]: json.loads(l) for l in store.read_text().splitlines()}
    assert entries[RAW]["status"] == 200 and entries[RAW]["bytes"] > 0
    assert entries[GONE]["status"] == 404 and entries[GONE]["path"] is None


def test_builder_does_not_refetch_what_it_already_has(store, tmp_path):
    def must_not_be_called(url):
        raise AssertionError(f"refetched {url}")
    snapshot_urls([RAW, GIST, GONE], tmp_path / "github", store, fetch=must_not_be_called)
    assert len(store.read_text().splitlines()) == 3


def test_stored_file_is_served_with_its_content(store):
    with poc_snapshots_instead_of_network(load_github_manifest(store)) as shim:
        resp = poc_module.requests.get(RAW, timeout=8)
    assert resp.status_code == 200 and "whoami" in resp.text
    assert (shim.served, shim.missed) == (1, 0)


def test_gist_json_is_served(store):
    with poc_snapshots_instead_of_network(load_github_manifest(store)):
        data = poc_module.requests.get(GIST).json()
    assert data["files"]["a.sh"]["content"] == "curl x | sh"


def test_a_recorded_404_is_served_as_a_404_not_counted_as_missed(store):
    """The file was gone when snapshotted; replaying that is faithful, not a miss."""
    with poc_snapshots_instead_of_network(load_github_manifest(store)) as shim:
        assert poc_module.requests.get(GONE).status_code == 404
    assert (shim.served, shim.missed) == (1, 0)


def test_an_unknown_url_is_a_counted_miss_and_never_goes_live(store):
    with poc_snapshots_instead_of_network(load_github_manifest(store)) as shim:
        assert poc_module.requests.get("https://raw.githubusercontent.com/x/y/z/w").status_code == 404
    assert (shim.served, shim.missed) == (0, 1)


def test_the_real_requests_module_is_restored(store):
    original = poc_module.requests
    with pytest.raises(RuntimeError):
        with poc_snapshots_instead_of_network(load_github_manifest(store)):
            raise RuntimeError("stage failed")
    assert poc_module.requests is original


def test_real_poc_stage_reads_the_snapshot_not_the_network(store):
    """End to end: the stored content reaches the model's prompt."""
    class _Client:
        model_name = "fake"
        def __init__(self): self.prompts = []
        def generate(self, prompt, **kw):
            self.prompts.append(prompt)
            return '{"behavioral_indicators": [], "attack_flow": ""}'

    client = _Client()
    context = {"preprocessed": {"combined_text":
               "PoC at https://github.com/acme/exploit/blob/main/poc.py", "segments": []}}
    with poc_snapshots_instead_of_network(load_github_manifest(store)) as shim:
        context = PoCAnalysisStage(client, "fake").run(context)
    assert shim.served == 1
    assert context["poc_analysis"]["snippets_found"] == 1
    assert "whoami" in client.prompts[0]
