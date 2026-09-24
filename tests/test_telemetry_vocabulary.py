"""Offline tests for plan 2.2a: the attack-vector stage's telemetry label reaches
the analysis and generation stages in Sigma's vocabulary.

Baseline v2 (plan 2.1): the rule's logsource category was the attack-vector
label verbatim in 24 of 41 wrong rules, and 17 of 41 used a category no SigmaHQ
rule uses (`webserver_access_log` 15). The stage's own choice is not changed;
only the words the later stages read.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest

from backend.pipeline import prompts
from backend.pipeline.stage_attack_vector import (
    SIGMA_CATEGORY_FOR_TELEMETRY,
    TELEMETRY_IN_WORDS,
    AttackVectorStage,
)

REPO = Path(__file__).resolve().parent.parent


def _vocabulary() -> set:
    """The labels the attack-vector prompt lets the model choose from."""
    line = next(l for l in prompts.ATTACK_VECTOR_EXTRACTION.splitlines()
                if l.startswith("- `primary_telemetry`"))
    return set(re.findall(r"`([a-z_]+)`", line)) - {"primary_telemetry"}


def _summary(label):
    return AttackVectorStage.format_vector_summary({
        "initial_access_vector": "x", "primary_telemetry": label})


def _telemetry_line(label) -> str:
    return next(l for l in _summary(label).splitlines() if "telemetry" in l.lower())


def test_every_label_the_stage_may_choose_is_covered():
    vocabulary = _vocabulary()
    assert len(vocabulary) == 13
    assert vocabulary == set(SIGMA_CATEGORY_FOR_TELEMETRY) | set(TELEMETRY_IN_WORDS)
    assert not set(SIGMA_CATEGORY_FOR_TELEMETRY) & set(TELEMETRY_IN_WORDS)


@pytest.mark.parametrize("label, category", [
    ("webserver_access_log", "webserver"),
    ("web_proxy", "proxy"),
    ("firewall", "firewall"),
    ("dns", "dns"),
    ("process_creation", "process_creation"),
    ("file_event", "file_event"),
    ("registry_event", "registry_event"),
])
def test_labels_with_a_sigma_category_are_shown_as_that_category(label, category):
    line = _telemetry_line(label)
    assert f"category `{category}`" in line
    if label != category:
        assert label not in line


@pytest.mark.parametrize("label", ["waf", "network_ids", "cloud_audit",
                                   "email_gateway", "auth_log", "other"])
def test_labels_without_a_sigma_category_are_described_in_words(label):
    line = _telemetry_line(label)
    assert TELEMETRY_IN_WORDS[label] in line
    assert "no single Sigma logsource category" in line
    assert "`" not in line and "_" not in line  # nothing that looks like a field value


def test_a_label_outside_the_vocabulary_is_shown_in_words():
    line = _telemetry_line("webserver_logs")
    assert "webserver logs" in line and "_" not in line


def test_a_missing_label_is_unknown():
    line = _telemetry_line(None)
    assert "unknown" in line and "_" not in line


def test_the_stages_own_record_is_not_changed():
    """The raw label stays in the context and in evaluation rows (plan 2.1 reads it)."""
    vector = {"initial_access_vector": "x", "primary_telemetry": "webserver_access_log"}
    before = copy.deepcopy(vector)
    AttackVectorStage.format_vector_summary(vector)
    assert vector == before


def test_mapped_categories_are_used_by_sigmahq_rules():
    """Checked against the local SigmaHQ corpus; skipped where it is not present."""
    corpus = REPO / "data/sigma"
    if not corpus.is_dir():
        pytest.skip("data/sigma not present (it is rebuilt locally, not committed)")
    from eval.diagnose_logsource import corpus_categories
    assert set(SIGMA_CATEGORY_FOR_TELEMETRY.values()) <= corpus_categories(corpus)
