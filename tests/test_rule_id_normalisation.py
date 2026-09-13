"""Tests for rule-id normalisation (Change 9, defect 10).

Fully offline: `normalize_rule_id` is a pure function, no LLM and no network.

Context: observed 2026-09-13 on a live run over the Bumblebee DFIR report. The
model emitted `id: 5a3b4c5d-6e7f-8g9h-1i2j-3k4l5m6n7o8p`, which is UUID-shaped
but contains non-hex characters. pySigma rejected the whole rule with
SigmaIdentifierError, so a rule with sound detection logic scored invalid on S1
for a cosmetic reason.
"""

from __future__ import annotations

import uuid

import pytest
import yaml

from backend.pipeline.stage_generate import normalize_rule_id


VALID_ID = "8f7e2b1a-3c4d-4e5f-8a9b-0c1d2e3f4a5b"

# The exact string produced by the model on 2026-09-13.
OBSERVED_BAD_ID = "5a3b4c5d-6e7f-8g9h-1i2j-3k4l5m6n7o8p"


def _rule(id_line: str) -> str:
    return (
        "title: Suspicious rundll32 Execution\n"
        f"{id_line}"
        "status: experimental\n"
        "logsource:\n"
        "    category: process_creation\n"
        "    product: windows\n"
        "detection:\n"
        "    selection:\n"
        "        Image|endswith: '\\rundll32.exe'\n"
        "    condition: selection\n"
        "level: high\n"
    )


def _extract_id(yaml_content: str):
    return yaml.safe_load(yaml_content)["id"]


# --- ids that must be replaced ----------------------------------------------

@pytest.mark.parametrize(
    "bad",
    [
        OBSERVED_BAD_ID,
        "not-a-uuid",
        "12345",
        "",
        "   ",
        # right shape, one non-hex character
        "8f7e2b1a-3c4d-4e5f-8a9b-0c1d2e3f4a5z",
        # too short
        "8f7e2b1a-3c4d-4e5f-8a9b",
    ],
)
def test_invalid_ids_are_replaced_with_a_real_uuid(bad):
    original = _rule(f"id: {bad}\n")
    fixed, replaced = normalize_rule_id(original)

    assert replaced is True
    new_id = _extract_id(fixed)
    assert new_id != bad
    uuid.UUID(str(new_id))  # raises if still not a UUID


# --- ids that must be left alone --------------------------------------------

@pytest.mark.parametrize(
    "good",
    [
        VALID_ID,
        VALID_ID.upper(),
        f"'{VALID_ID}'",
        f'"{VALID_ID}"',
    ],
)
def test_valid_ids_are_preserved_untouched(good):
    original = _rule(f"id: {good}\n")
    fixed, replaced = normalize_rule_id(original)

    assert replaced is False
    assert fixed == original


# --- structural guarantees ---------------------------------------------------

def test_replacement_changes_nothing_but_the_id():
    original = _rule(f"id: {OBSERVED_BAD_ID}\n")
    fixed, _ = normalize_rule_id(original)

    before = yaml.safe_load(original)
    after = yaml.safe_load(fixed)
    before.pop("id")
    after.pop("id")
    assert before == after


def test_missing_id_is_inserted_directly_after_title():
    original = _rule("")
    assert "id:" not in original

    fixed, replaced = normalize_rule_id(original)

    assert replaced is True
    uuid.UUID(str(_extract_id(fixed)))
    lines = fixed.splitlines()
    assert lines[0].startswith("title:")
    assert lines[1].startswith("id: ")  # SigmaHQ field order preserved


def test_rule_without_title_still_gets_an_id():
    original = "logsource:\n    category: process_creation\n"
    fixed, replaced = normalize_rule_id(original)

    assert replaced is True
    uuid.UUID(str(_extract_id(fixed)))


def test_nested_id_keys_are_not_touched():
    """Only a column-0 `id:` is the rule identifier."""
    original = (
        f"title: Test\nid: {VALID_ID}\n"
        "detection:\n"
        "    selection:\n"
        "        id: not-a-uuid-but-a-field-name\n"
        "    condition: selection\n"
    )
    fixed, replaced = normalize_rule_id(original)

    assert replaced is False
    assert fixed == original


def test_every_document_in_a_multi_rule_yaml_is_checked():
    """A valid first id must not stop the second from being repaired."""
    original = (
        f"title: First\nid: {VALID_ID}\nlevel: high\n"
        "---\n"
        f"title: Second\nid: {OBSERVED_BAD_ID}\nlevel: low\n"
    )
    fixed, replaced = normalize_rule_id(original)

    assert replaced is True
    assert VALID_ID in fixed           # the good one survived
    assert OBSERVED_BAD_ID not in fixed  # the bad one did not
    for doc in yaml.safe_load_all(fixed):
        uuid.UUID(str(doc["id"]))


def test_empty_input_does_not_raise():
    assert normalize_rule_id("") == ("", False)


def test_generated_ids_are_unique_across_calls():
    ids = {
        _extract_id(normalize_rule_id(_rule("id: bad\n"))[0])
        for _ in range(20)
    }
    assert len(ids) == 20


# --- the end-to-end claim: pySigma now accepts the rule ----------------------

def test_repaired_rule_passes_pysigma_where_the_original_failed():
    from sigma.collection import SigmaCollection
    from sigma.exceptions import SigmaError

    original = _rule(f"id: {OBSERVED_BAD_ID}\n")

    with pytest.raises(SigmaError):
        SigmaCollection.from_yaml(original)

    fixed, _ = normalize_rule_id(original)
    collection = SigmaCollection.from_yaml(fixed)  # must not raise
    assert len(collection.rules) == 1
