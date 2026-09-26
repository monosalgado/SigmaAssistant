"""Offline tests for Change 33 (prompt review item 1; user, 2026-09-26: in the shared run):
the rule writer's worked example follows SigmaHQ's conventions and has nothing to copy.

Why: the example tagged `attack.credential_access`; SigmaHQ writes hyphens (3,021 of 3,021
in the main set, 389 of 389 gold tags) and pySigma flags the underscore form — 136 issues in
the Change 28 run, whose rules used the underscore in 137 of 143 tactic tags, although each
prompt also carries three real SigmaHQ rules. Its id `12345678-1234-…` is a valid UUID, so
the rule-id check (Change 9) kept copies and rules shared an id. The example's id is now a
placeholder that is not a UUID: a copy is replaced by Change 9 like any invalid id.
"""

from __future__ import annotations

import json
import re

import yaml

from backend.pipeline import prompts
from backend.pipeline.stage_generate import _is_valid_uuid, normalize_rule_id

GEN = prompts.RULE_GENERATION


def _example_rule() -> dict:
    block = GEN.split("### Few-shot Example", 1)[1].split("**Output**:", 1)[1]
    block = block.split("Respond with JSON only.")[0].strip()
    data = json.loads(block.replace("{{", "{").replace("}}", "}"))
    return yaml.safe_load(data["rules"][0]["yaml_content"].replace("{current_date}", "2026-01-01"))


def test_no_underscore_tactic_tag_is_left_in_the_prompt():
    assert not re.search(r"attack\.[a-z]+_[a-z]", GEN)


def test_the_example_uses_sigmahqs_hyphenated_tactics():
    tags = _example_rule()["tags"]
    assert "attack.credential-access" in tags and "attack.t1003.001" in tags


def test_the_tag_instruction_asks_for_the_hyphenated_form():
    line = next(l for l in GEN.splitlines() if l.startswith("11. "))
    assert "hyphen" in line and "attack.credential-access" in line


def test_the_old_example_id_is_gone_and_the_new_one_is_not_a_uuid():
    assert "12345678-1234-1234-1234-123456789abc" not in GEN
    example_id = str(_example_rule()["id"])
    assert not _is_valid_uuid(example_id)


def test_a_copied_example_id_is_replaced_by_the_rule_id_check():
    example_id = str(_example_rule()["id"])
    fixed, replaced = normalize_rule_id(f"title: x\nid: {example_id}\n")
    assert replaced and example_id not in fixed


def test_the_example_is_still_a_complete_rule():
    rule = _example_rule()
    for field in ("title", "id", "status", "description", "references", "author", "date",
                  "tags", "logsource", "detection", "falsepositives", "level"):
        assert field in rule, field
