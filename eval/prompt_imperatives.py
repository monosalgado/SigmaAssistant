#!/usr/bin/env python3
"""The capitalised orders in each prompt and in the blocks code adds at run time (#6, pipeline quality, the prompt
review's P3; user 2026-10-07). Counted words, in capitals only: MUST, NEVER, MANDATORY, REQUIRED, ALWAYS, ONLY, DO NOT /
NOT, AT LEAST, CRITICAL, IMPORTANT. Offline; reads `backend/pipeline/prompts.py` and `domain_knowledge.py`.

Usage:
    .venv/bin/python eval/prompt_imperatives.py
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

ORDERS = ("MUST", "NEVER", "MANDATORY", "REQUIRED", "ALWAYS", "ONLY", "NOT", "AT LEAST", "CRITICAL", "IMPORTANT")
_ORDER = re.compile(r"\b(AT LEAST|MUST|NEVER|MANDATORY|REQUIRED|ALWAYS|ONLY|NOT|CRITICAL|IMPORTANT)\b")


def count_orders(text: str) -> dict:
    return dict(Counter(_ORDER.findall(text or "")))


def runtime_blocks() -> dict:
    from backend.pipeline.domain_knowledge import format_coverage_feedback, format_kill_chain_requirement
    gaps = {"warnings": ["w"], "payload_signatures_missed": ["p"], "blacklist_violations": ["b"],
            "initial_access_covered": False, "kill_chain_gap": "One stage has no rule.", "version_pin_violations": ["1.0"]}
    return {"kill-chain block (2+ stages)": format_kill_chain_requirement(["initial_access", "execution"]),
            "coverage retry block (all gaps)": format_coverage_feedback(gaps)}


def main() -> int:
    from backend.pipeline import prompts
    texts = {name: value for name, value in vars(prompts).items() if name.isupper() and isinstance(value, str)}
    texts.update(runtime_blocks())
    total = Counter()
    for name, text in texts.items():
        c = count_orders(text)
        total.update(c)
        print(f"{name:34} {sum(c.values()):>3}  {dict(sorted(c.items(), key=lambda kv: -kv[1]))}")
    print(f"\nall: {sum(total.values())}  {dict(total.most_common())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
