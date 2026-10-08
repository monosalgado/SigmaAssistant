"""Counting tokens on the laptop, before a request is sent (Change 49).

All three Spark halts (2026-10-06/07/08) came during a call with a long prompt, so the client refuses a request over
a ceiling and the web digest is sent in pieces; both need the count before the request leaves. The count is Qwen's:
the model's own `tokenizer.json` (7,032,399 bytes, huggingface.co/Qwen/Qwen3-Coder-30B-A3B-Instruct at `b2cff64`),
kept in data/tokenizer/ (gitignored). Without the file, a conservative estimate - characters / 2; every call recorded
so far has >= 2.0 characters per token (web pages ~2.3, prose ~3.9) - so a missing file makes the limits stricter,
never looser.
"""

from __future__ import annotations

import math
from pathlib import Path

TOKENIZER_PATH = Path(__file__).resolve().parent.parent / "data" / "tokenizer" / "qwen3-coder-tokenizer.json"
CHARS_PER_TOKEN_FLOOR = 2.0

_cache = {}


def _tokenizer(path=None):
    """The tokenizer at `path` (default TOKENIZER_PATH), or None if the file is missing - said once."""
    key = str(path or TOKENIZER_PATH)
    if key not in _cache:
        if Path(key).exists():
            from tokenizers import Tokenizer
            _cache[key] = Tokenizer.from_file(key)
        else:
            print(f"[token_count] No tokenizer file at {key}; counting characters / {CHARS_PER_TOKEN_FLOOR:g} "
                  "(stricter than the real count)")
            _cache[key] = None
    return _cache[key]


def count_tokens(text: str, path=None) -> int:
    text = text or ""
    tok = _tokenizer(path)
    if tok is None:
        return math.ceil(len(text) / CHARS_PER_TOKEN_FLOOR)
    return len(tok.encode(text, add_special_tokens=False).ids) if text else 0


def truncate_to_tokens(text: str, max_tokens: int, path=None) -> str:
    """The longest opening of `text` with at most `max_tokens` tokens (cut at a token boundary)."""
    text = text or ""
    tok = _tokenizer(path)
    if tok is None:
        return text[:int(max_tokens * CHARS_PER_TOKEN_FLOOR)]
    enc = tok.encode(text, add_special_tokens=False)
    if len(enc.ids) <= max_tokens:
        return text
    return text[:enc.offsets[max_tokens][0]] if max_tokens > 0 else ""
