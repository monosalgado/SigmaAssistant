"""Offline tests for eval/page_reader_effect.py (Change 61's offline measure, plan in the log 2026-11-10): two page
readers on the same saved pages - characters, the cut, code blocks kept, code next to prose, spaces kept."""

from __future__ import annotations

from eval.page_reader_effect import blocks_after_prose, blocks_of, glued_elements, page_summary

OLD = "--- Code/Config Snippets ---\n\n```\nwhoami /priv /all\n```\n\n--- Article Content ---\n\nIt ran a command."
NEW = "It ran a command:\n\n```\nwhoami /priv /all\n```\n\nThen it slept."
MOVED = "Intro.\n\n--- Code further down the page (moved here: the page is longer than the reader keeps) ---\n```\nx = 1 and more\n```"


def test_the_code_blocks_of_a_text_are_its_fenced_contents():
    assert blocks_of(OLD) == ["whoami /priv /all"] and blocks_of(NEW) == ["whoami /priv /all"] and blocks_of("none") == []


def test_a_block_counts_as_after_prose_when_the_line_before_it_is_text():
    assert blocks_after_prose(NEW) == 1
    assert blocks_after_prose(OLD) == 0          # after a heading of the reader
    assert blocks_after_prose(MOVED) == 0        # after the moved-code heading
    assert blocks_after_prose("```\na = 1 and b\n```\n\n```\nc = 2 and d\n```") == 0


def test_glued_elements_are_those_whose_stripped_text_loses_a_space():
    html = "<p>It ran <code>whoami</code> then.</p><p><b>Ex</b>ample text.</p><li>A plain item here.</li>"
    assert glued_elements(html) == {"elements": 3, "glued": 1}


def test_a_page_summary_compares_the_two_readers():
    s = page_summary(OLD, NEW, limit=40000)
    assert s["blocks_old"] == 1 and s["kept"] == 1 and s["after_prose"] == 1
    assert s["chars_old"] == len(OLD) and s["chars_new"] == len(NEW) and s["at_cut_old"] is False
    assert page_summary(OLD, "nothing", limit=40000)["kept"] == 0
    cut = page_summary(OLD, NEW, limit=40000, old_uncut=50000, new_uncut=39000)
    assert cut["at_cut_old"] is True and cut["at_cut_new"] is False
