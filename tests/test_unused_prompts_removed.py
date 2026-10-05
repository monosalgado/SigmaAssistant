"""H8 (prompt review §5 item 8; user 2026-10-05: "go in that order"): the five prompts nothing calls are deleted, so
`prompts.py` holds only what the pipeline sends. Behaviour unchanged. Offline.
"""

from __future__ import annotations

from backend.pipeline import prompts

REMOVED = ("ENTITY_EXTRACTION", "TTP_MAPPING", "RULE_VALIDATION", "RULE_OPTIMIZATION", "WEB_SEARCH_QUERIES")
IN_USE = ("INTENT_CLASSIFICATION", "IMAGE_TRANSCRIPTION", "RULE_GENERATION", "POC_CODE_ANALYSIS", "CONVERSATIONAL",
          "ATTACK_VECTOR_EXTRACTION", "COMBINED_ANALYSIS", "COMBINED_REVIEW")


def test_the_unused_prompts_are_gone_and_the_used_ones_stay():
    for name in REMOVED:
        assert not hasattr(prompts, name), name
    for name in IN_USE:
        assert isinstance(getattr(prompts, name), str), name
