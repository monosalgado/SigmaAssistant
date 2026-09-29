"""Tests for Change 37 (better log-source picks, step 1): an answer whose JSON holds a stray
backslash - a Windows path such as C:\\Windows, a regex such as \\d - is repaired and read, instead of
being thrown away whole (the analysis stage lost its log-source recommendation this way in 2-4 of 60
tuning cases per run: "Invalid \\escape"; the same defect Change 36 removed from generation).

In an answer that failed on a stray backslash, every backslash is doubled except the escapes a path
never contains (\\" \\\\ \\/ \\uXXXX), so C:\\temp stays a folder instead of becoming "C:" + a tab.
An answer that already parses is untouched: the repair runs only after `json.loads` has failed.
"""

from __future__ import annotations

import json

import pytest

from backend.pipeline.base_stage import PipelineStage, repair_json_escapes


class _Stage(PipelineStage):
    name = "t"

    def run(self, context):
        return context


def _stage():
    return _Stage(client=None, model_name="m")


def test_a_windows_path_in_an_answer_is_read_as_written():
    answer = '{"path": "C:\\Windows\\System32\\wermgr.exe"}'          # what the model sends
    with pytest.raises(json.JSONDecodeError):
        json.loads(answer)
    assert _stage().parse_json(answer) == {"path": "C:\\Windows\\System32\\wermgr.exe"}


def test_in_a_repaired_answer_quotes_backslashes_and_unicode_escapes_are_kept():
    answer = '{"q": "say \\"hi\\"", "slash": "a\\/b", "back": "a\\\\b", "u": "\\u00e9", "p": "C:\\x"}'
    assert _stage().parse_json(answer) == {"q": 'say "hi"', "slash": "a/b", "back": "a\\b", "u": "é",
                                           "p": "C:\\x"}


def test_in_a_repaired_answer_a_path_keeps_its_backslash_before_t_n_b():
    # An answer that failed on a stray backslash writes paths with single backslashes: C:\temp is a
    # folder, not "C:" + a tab. Control characters do not belong in these short values.
    answer = '{"p": "C:\\temp\\new\\bin\\x.dll"}'
    assert _stage().parse_json(answer) == {"p": "C:\\temp\\new\\bin\\x.dll"}


def test_a_u_that_is_not_a_unicode_escape_is_a_backslash():
    # C:\Users: \u followed by "sers" is not a \uXXXX escape.
    assert _stage().parse_json('{"p": "C:\\Users\\bob"}') == {"p": "C:\\Users\\bob"}


def test_a_regex_in_an_answer_keeps_its_backslashes():
    assert _stage().parse_json('{"pattern": "\\d+\\.exe"}') == {"pattern": "\\d+\\.exe"}


def test_every_backslash_but_a_quote_backslash_slash_or_unicode_escape_is_doubled():
    assert repair_json_escapes('"a\\qb \\n \\\\ \\u0041 \\uZZ"') == '"a\\\\qb \\\\n \\\\ \\u0041 \\\\uZZ"'


def test_an_answer_that_is_broken_in_another_way_still_fails():
    with pytest.raises(json.JSONDecodeError):
        _stage().parse_json('{"a": 1,,}')


def test_an_answer_that_parses_is_not_touched():
    # "\n" is a valid escape: a readable answer is read exactly as before.
    assert _stage().parse_json('{"p": "C:\\new"}') == {"p": "C:\new"}
