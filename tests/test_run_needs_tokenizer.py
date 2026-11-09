"""Tests: a run stops before its first case when the code it runs counts tokens but has no tokenizer (found 2026-11-09).

Since Change 49 (2026-10-08) the pipeline counts each prompt with Qwen's tokenizer and refuses one over the 30,000-token
ceiling. `backend/token_count.py` looks for the file next to its own code, in data/tokenizer/, which is gitignored;
without it the counter counts characters / 2 and only prints a note. The first three-arm session (2026-11-08/09) ran
each arm from a `git worktree` checkout, which has no such file: every arm counted characters / 2, more prompts were
refused than in a run in the main checkout, and two arms failed the fast-case gate. Offline; no LLM, no network.
"""

from __future__ import annotations

from eval.run_eval import TOKENIZER_FILE, missing_tokenizer


def _checkout(tmp_path, counts_tokens=True):
    root = tmp_path / "checkout"
    (root / "backend").mkdir(parents=True)
    if counts_tokens:
        (root / "backend" / "token_count.py").write_text("# Change 49's counter\n")
    return root


def _harness(tmp_path):
    root = tmp_path / "harness"
    (root / TOKENIZER_FILE).parent.mkdir(parents=True)
    (root / TOKENIZER_FILE).write_text("{}")
    return root


def _link(root, target):
    (root / TOKENIZER_FILE).parent.mkdir(parents=True)
    (root / TOKENIZER_FILE).symlink_to(target)


def test_code_that_counts_tokens_without_its_tokenizer_is_not_run(tmp_path):
    why = missing_tokenizer(_checkout(tmp_path), harness_root=_harness(tmp_path))
    assert why is not None
    assert "qwen3-coder-tokenizer.json" in why and "characters / 2" in why


def test_the_reason_says_how_to_link_the_main_checkouts_file(tmp_path):
    harness = _harness(tmp_path)
    why = missing_tokenizer(_checkout(tmp_path), harness_root=harness)
    assert "ln -s" in why and str(harness / TOKENIZER_FILE) in why


def test_a_checkout_with_the_file_linked_runs(tmp_path):
    harness = _harness(tmp_path)
    root = _checkout(tmp_path)
    _link(root, harness / TOKENIZER_FILE)
    assert missing_tokenizer(root, harness_root=harness) is None


def test_a_link_to_nowhere_counts_as_missing(tmp_path):
    root = _checkout(tmp_path)
    _link(root, tmp_path / "nowhere.json")
    assert missing_tokenizer(root, harness_root=_harness(tmp_path)) is not None


def test_code_from_before_change_49_counts_no_tokens_and_needs_no_file(tmp_path):
    assert missing_tokenizer(_checkout(tmp_path, counts_tokens=False), harness_root=_harness(tmp_path)) is None


def test_without_a_file_to_link_the_reason_says_where_the_file_comes_from(tmp_path):
    why = missing_tokenizer(_checkout(tmp_path), harness_root=tmp_path / "no-harness-file")
    assert why is not None
    assert "ln -s" not in why and "backend/token_count.py" in why
