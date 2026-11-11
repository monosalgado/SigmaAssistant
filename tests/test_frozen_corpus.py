"""The corpus is frozen (plan in the log, 2026-11-10, Change 61 point 4): which cases pass the 2,000-character
threshold is the selection made with the page reader of 2026-11-10, so a change of the reader cannot move a case in
or out of a set, nor the seed-0 sample. Offline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval.run_eval import FROZEN_CORPUS, load_cases

GOLD = "title: Gold\nlogsource:\n    category: process_creation\ndetection:\n    selection:\n        Image: x\n    condition: selection\n"


def _repo(tmp_path, pages: dict) -> tuple:
    """A manifest with one case per page; a page's text is the given length of prose."""
    (tmp_path / "gold.yml").write_text(GOLD)
    lines = []
    for rule_id, chars in pages.items():
        page = tmp_path / f"{rule_id}.html"
        page.write_text(f"<html><body><p>{'a' * chars}</p></body></html>")
        lines.append(json.dumps({"rule_id": rule_id, "rule_path": "gold.yml", "title": rule_id, "status": "ok",
                                 "logsource": {"category": "process_creation"},
                                 "snapshots": [{"url": f"https://example.com/{rule_id}", "path": page.name}]}))
    manifest = tmp_path / "manifest.jsonl"
    manifest.write_text("\n".join(lines) + "\n")
    return manifest, tmp_path


def _ids(cases):
    return [c["rule_id"] for c in cases]


def test_without_a_freeze_the_threshold_decides_as_before(tmp_path):
    manifest, root = _repo(tmp_path, {"long": 3000, "short": 500})
    assert _ids(load_cases(manifest, root, 2000, frozen=None)) == ["long"]


def test_a_frozen_case_is_kept_even_if_its_text_is_now_shorter(tmp_path):
    manifest, root = _repo(tmp_path, {"long": 3000, "short": 500})
    frozen = {"min_chars": 2000, "considered": ["long", "short"], "selected": ["long", "short"]}
    assert _ids(load_cases(manifest, root, 2000, frozen=frozen)) == ["long", "short"]


def test_a_case_the_freeze_left_out_stays_out_even_if_its_text_is_now_longer(tmp_path):
    manifest, root = _repo(tmp_path, {"long": 3000, "short": 500})
    frozen = {"min_chars": 2000, "considered": ["long", "short"], "selected": ["short"]}
    assert _ids(load_cases(manifest, root, 2000, frozen=frozen)) == ["short"]


def test_a_case_the_freeze_never_saw_is_judged_by_its_length(tmp_path):
    manifest, root = _repo(tmp_path, {"long": 3000, "new_long": 2500, "new_short": 100})
    frozen = {"min_chars": 2000, "considered": ["long"], "selected": ["long"]}
    assert _ids(load_cases(manifest, root, 2000, frozen=frozen)) == ["long", "new_long"]


def test_another_threshold_ignores_the_freeze(tmp_path):
    manifest, root = _repo(tmp_path, {"long": 3000, "short": 500})
    frozen = {"min_chars": 2000, "considered": ["long", "short"], "selected": ["long", "short"]}
    assert _ids(load_cases(manifest, root, 400, frozen=frozen)) == ["long", "short"]
    assert _ids(load_cases(manifest, root, 2500, frozen=frozen)) == ["long"]


def test_the_rows_still_record_the_length_the_current_reader_gives(tmp_path):
    manifest, root = _repo(tmp_path, {"short": 500})
    frozen = {"min_chars": 2000, "considered": ["short"], "selected": ["short"]}
    assert load_cases(manifest, root, 2000, frozen=frozen)[0]["text_chars"] == 500


REPO = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(not (REPO / "eval" / "snapshots").is_dir(), reason="the saved pages are local only")
def test_the_committed_freeze_reproduces_todays_selection_for_every_manifest():
    frozen = json.loads(FROZEN_CORPUS.read_text())
    for manifest in sorted((REPO / "eval").glob("manifest*.jsonl")):
        assert _ids(load_cases(manifest, REPO, 2000, frozen=frozen)) == _ids(load_cases(manifest, REPO, 2000, frozen=None))
