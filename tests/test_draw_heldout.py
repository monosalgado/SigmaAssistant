"""Offline tests for eval/draw_heldout.py — plan 2.9, the held-out confirmation.

Every Phase 2 change was found and measured on the same 60 cases. The held-out cases are
drawn once, by committed code, from the corpus cases that appear in NO result file (not
only the 60 tuning cases: pilots, probes and preflight smoke runs count too), with the
harness's own stratified sampler, and written as a manifest subset that both the final
pipeline and baseline v2's code can run with `--manifest`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval.draw_heldout import (
    HELDOUT_PATH,
    select_heldout,
    subset_manifest_lines,
    used_rule_ids,
    write_once,
)

REPO = Path(__file__).resolve().parent.parent


def _case(i, category="process_creation"):
    return {"rule_id": f"r{i:03d}", "category": category, "product": "windows"}


def test_used_ids_come_from_every_result_file_including_backups(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.jsonl").write_text('{"rule_id": "r001"}\n{"rule_id": "r002"}\n', encoding="utf-8")
    (tmp_path / "sub" / "b.jsonl.bak").write_text('{"rule_id": "r003"}\nnot json\n\n', encoding="utf-8")
    (tmp_path / "notes.txt").write_text('{"rule_id": "r009"}\n', encoding="utf-8")
    assert used_rule_ids(tmp_path) == {"r001", "r002", "r003"}


def test_no_used_case_is_drawn_and_the_size_is_right():
    cases = [_case(i, "process_creation" if i % 2 else "webserver") for i in range(40)]
    used = {f"r{i:03d}" for i in range(0, 40, 3)}
    drawn = select_heldout(cases, used, 10, seed=0)
    assert len(drawn) == 10
    assert not {c["rule_id"] for c in drawn} & used


def test_the_draw_is_reproducible():
    cases = [_case(i) for i in range(30)]
    a = [c["rule_id"] for c in select_heldout(cases, set(), 8, seed=0)]
    b = [c["rule_id"] for c in select_heldout(cases, set(), 8, seed=0)]
    assert a == b


def test_the_subset_keeps_the_manifest_lines_verbatim_in_manifest_order(tmp_path):
    manifest = tmp_path / "m.jsonl"
    lines = [json.dumps({"rule_id": f"r{i}", "x": i}) for i in range(5)]
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert subset_manifest_lines(manifest, {"r3", "r1"}) == [lines[1], lines[3]]


def test_the_held_out_list_is_written_once(tmp_path):
    out = tmp_path / "heldout.jsonl"
    write_once(out, ["a", "b"])
    assert out.read_text(encoding="utf-8") == "a\nb\n"
    with pytest.raises(FileExistsError):
        write_once(out, ["c"])


def test_the_committed_held_out_list():
    """60 distinct manifest cases, none of them in the tuning runs' result files."""
    ids = [json.loads(l)["rule_id"] for l in HELDOUT_PATH.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(ids) == len(set(ids)) == 60
    manifest = {json.loads(l)["rule_id"] for l in (REPO / "eval/manifest.jsonl").open(encoding="utf-8")}
    assert set(ids) <= manifest
    tuning = {json.loads(l)["rule_id"] for l in (REPO / "eval/results/p2g_shared60.jsonl").open(encoding="utf-8")}
    assert not set(ids) & tuning
