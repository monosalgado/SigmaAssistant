"""Tests for Change 49, part 1: counting tokens on the laptop, before a request is sent (user 2026-10-08: "we are
breaking the spark and we need to stop that"; exact counts chosen, Qwen's tokenizer file downloaded to data/tokenizer/).

`count_tokens` uses that file; without it, a conservative estimate (characters / 2 - every call recorded so far has
>= 2.0 characters per token), so a missing file makes the limits stricter, never looser. `truncate_to_tokens` keeps a
text's opening within a token budget (the web digest shows the report's first 6,000 tokens). Offline; the tests that
need the file skip without it.
"""

from __future__ import annotations

import pytest

from backend import token_count
from backend.token_count import TOKENIZER_PATH, count_tokens, truncate_to_tokens

MISSING = TOKENIZER_PATH.parent / "no-such-tokenizer.json"
needs_file = pytest.mark.skipif(not TOKENIZER_PATH.exists(), reason="tokenizer file not downloaded")


def test_without_the_file_the_estimate_is_conservative():
    assert count_tokens("a" * 10, path=MISSING) == 5
    assert count_tokens("a" * 11, path=MISSING) == 6           # rounded up
    assert count_tokens("", path=MISSING) == 0
    assert truncate_to_tokens("abcdefghij", 3, path=MISSING) == "abcdef"


@needs_file
def test_with_the_file_the_count_is_qwens():
    from tokenizers import Tokenizer
    tok = Tokenizer.from_file(str(TOKENIZER_PATH))
    text = "powershell.exe -enc SQBFAFgA and C:\\Users\\Public\\x.dll"
    assert count_tokens(text) == len(tok.encode(text, add_special_tokens=False).ids)
    assert count_tokens("Hello world") == 2
    assert count_tokens("") == 0


@needs_file
def test_the_opening_of_a_text_within_a_budget():
    text = " ".join(f"word{i}" for i in range(500))
    opening = truncate_to_tokens(text, 100)
    assert text.startswith(opening) and 95 <= count_tokens(opening) <= 100
    assert truncate_to_tokens("short text", 100) == "short text"


def test_a_missing_file_is_said_once(capsys):
    token_count._cache.pop(str(MISSING), None)
    count_tokens("x", path=MISSING)
    count_tokens("y", path=MISSING)
    assert capsys.readouterr().out.count("No tokenizer file") == 1
