"""Tests for the bare-URL intent short-circuit (Change 8, defect 8).

Fully offline: `is_bare_url_input` is a pure function, no LLM and no network.

Context: measured 2026-09-13 on 30 real CTI reference URLs, the LLM intent
classifier routed 17/30 (57%) to "question"/"chat". Those intents return a
conversational answer and skip all seven grounding stages, so the page is never
fetched and any rule is written from the URL string alone.
"""

from __future__ import annotations

import pytest

from backend.pipeline.orchestrator import is_bare_url_input


# --- inputs that MUST short-circuit to generate_rule -------------------------

@pytest.mark.parametrize(
    "message",
    [
        "https://thedfirreport.com/2022/09/26/bumblebee-round-two/",
        "http://example.com/report",
        "  https://unit42.paloaltonetworks.com/operation-ke3chang/  ",
        # multiple URLs, which is what run_eval passes and what users paste
        "https://support.citrix.com/article/CTX276688 https://dmaasland.github.io/posts/citrix.html",
        # trailing filler should still count as bare
        "https://securelist.com/apt-slingshot/84312/ please",
        "https://www.exploit-db.com/exploits/47297\n",
    ],
)
def test_bare_url_inputs_are_detected(message):
    assert is_bare_url_input(message) is True


# --- inputs that MUST still reach the LLM classifier -------------------------

@pytest.mark.parametrize(
    "message",
    [
        "",
        "   ",
        "Hello, how are you?",
        "What log source should I use for network connections?",
        "Detect mimikatz credential dumping via LSASS memory access",
        "Can you add a filter for the admin account in that rule?",
        # a genuine question *about* a link keeps enough prose to be classified
        "Can you explain what this article says about the exploit chain? "
        "https://securelist.com/operation-triangulation/109842/",
        # refinement referencing a link
        "That rule is too noisy, please narrow it using the details in "
        "https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up/",
    ],
)
def test_non_bare_inputs_are_not_short_circuited(message):
    assert is_bare_url_input(message) is False


def test_none_message_does_not_raise():
    assert is_bare_url_input(None) is False


def test_text_without_any_url_is_never_bare():
    assert is_bare_url_input("thedfirreport.com/2022/09/26/bumblebee") is False


def test_classify_intent_short_circuits_without_calling_the_llm():
    """The short-circuit must happen before any LLM call is made."""
    from backend.pipeline.orchestrator import PipelineOrchestrator

    class ExplodingClient:
        def generate(self, *a, **kw):
            raise AssertionError("classify_intent must not call the LLM for a bare URL")

    orch = PipelineOrchestrator.__new__(PipelineOrchestrator)
    orch.client = ExplodingClient()

    result = orch.classify_intent("https://thedfirreport.com/2022/09/26/bumblebee-round-two/")

    assert result["intent"] == "generate_rule"
    assert "bare URL" in result["reasoning"]


def test_classify_intent_still_calls_the_llm_for_prose():
    """Non-bare input must still be classified by the model, not forced."""
    from backend.pipeline.orchestrator import PipelineOrchestrator

    calls = []

    class RecordingClient:
        def generate(self, prompt, **kw):
            calls.append(prompt)
            return '{"intent": "question", "reasoning": "asking for guidance"}'

    orch = PipelineOrchestrator.__new__(PipelineOrchestrator)
    orch.client = RecordingClient()

    result = orch.classify_intent("What log source should I use for network connections?")

    assert len(calls) == 1
    assert result["intent"] == "question"
