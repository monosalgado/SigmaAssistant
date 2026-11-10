"""Offline tests for eval/poc_snippets.py (Change 57's offline measure, plan in the log 2026-11-10): of the cases
whose pages link to GitHub code that is saved, in how many does the PoC step's prompt hold it?"""

from __future__ import annotations

from eval.poc_snippets import has_linked_code, snippet_sources, summary

PROMPT = """You are ...
### Snippet 1 (python, from inline)
```python
x
```

### Snippet 2 (unknown, from github: https://github.com/o/r/blob/main/poc.py)
```unknown
y
```
"""


def test_the_sources_of_the_snippets_are_read_from_the_prompts_headings_in_order():
    assert snippet_sources(PROMPT) == ["inline", "github"]
    assert snippet_sources("") == [] and snippet_sources(None) == []


def test_a_case_has_linked_code_when_a_file_it_links_to_was_saved_with_a_body():
    targets = [{"fetch_url": "https://raw.githubusercontent.com/o/r/main/poc.py"},
               {"fetch_url": "https://raw.githubusercontent.com/o/r/main/gone.py"}]
    saved = {"https://raw.githubusercontent.com/o/r/main/poc.py": {"status": 200, "path": "/x/poc.py"},
             "https://raw.githubusercontent.com/o/r/main/gone.py": {"status": 404, "path": None}}
    assert has_linked_code(targets, saved) is True
    assert has_linked_code(targets[1:], saved) is False and has_linked_code([], saved) is False


def test_the_summary_counts_the_cases_with_linked_code_and_those_where_it_is_read():
    cases = [{"linked": True, "sources": ["inline"] * 5}, {"linked": True, "sources": ["github", "inline"]},
             {"linked": False, "sources": ["inline"]}, {"linked": False, "sources": []}]
    assert summary(cases) == {"cases": 4, "with_code": 3, "with_linked_code": 2, "linked_code_read": 1}


def test_the_harness_keeps_change_57s_records_in_the_row():
    from eval.run_eval import DIAGNOSIS_FIELDS
    assert "first_pass_rules" in DIAGNOSIS_FIELDS and "regeneration_reason" in DIAGNOSIS_FIELDS
    assert "review_returned" in DIAGNOSIS_FIELDS          # Change 60
