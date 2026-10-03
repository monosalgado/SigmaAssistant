"""Evidence extraction (Change 41): a separate step copies, verbatim, the strings in the report a detection rule
could match on; code keeps only those the report really contains and adds them to the attack vector's payload
signatures - the short list the rule writer follows, checked by the coverage check with one retry.

The model decides which strings; code only checks them and records. A string is kept when the report text the
step was given contains it (case, runs of whitespace and a doubled backslash ignored), it is at least 3
characters, it is not on the attack vector's incidental list, and it is neither an existing payload signature nor
a repeat; at most MAX_ITEMS are kept. If the call fails, nothing is added.
"""

from __future__ import annotations

import re

from backend.pipeline import prompts
from backend.pipeline.base_stage import PipelineStage
from backend.pipeline.stage_attack_vector import AttackVectorStage

MAX_ITEMS = 8
_SPACE = re.compile(r"\s+")


def _norm(text) -> str:
    return _SPACE.sub(" ", str(text or "").lower().replace("\\\\", "\\")).strip()


def _incidental_strings(incidental: list) -> list:
    out = []
    for item in incidental or []:
        value = item.get("value") or item.get("string") or item.get("pattern") if isinstance(item, dict) else item
        if _norm(value):
            out.append(_norm(value))
    return out


def check_evidence(items: list, report_text: str, incidental: list, existing_patterns: list):
    """(kept, dropped): kept as payload signatures marked `source: evidence`; dropped as {string, reason}."""
    text = _norm(report_text)
    avoid = [a for a in _incidental_strings(incidental) if len(a) >= 4]
    seen = {_norm(p) for p in existing_patterns or [] if _norm(p)}
    kept, dropped = [], []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        string = str(item.get("string") or "").strip()
        n = _norm(string)
        reason = ("too short" if len(n) < 3 else
                  "not in the report" if n not in text else
                  "incidental" if any(a in n or n in a for a in avoid) else
                  "duplicate" if n in seen else
                  "over the limit" if len(kept) >= MAX_ITEMS else None)
        if reason:
            dropped.append({"string": string, "reason": reason})
            continue
        seen.add(n)
        kept.append({"pattern": string, "where": str(item.get("kind") or "other"),
                     "derived_from": str(item.get("quote") or "")[:200], "source": "evidence",
                     "activity": str(item.get("activity") or "")})
    return kept, dropped


class EvidenceStage(PipelineStage):
    name = "evidence"
    description = "Copying the report's own detectable strings"

    def run(self, context: dict) -> dict:
        text = self.source_text(context["preprocessed"]["combined_text"])
        vector = context.get("attack_vector") or {}
        record = {"proposed": 0, "kept": [], "dropped": [], "error": None}
        prompt = prompts.EVIDENCE_EXTRACTION.format(
            attack_vector_summary=AttackVectorStage.format_vector_summary(vector),
            incidental=AttackVectorStage.format_incidental_blacklist(vector),
            text=text)
        try:
            answer = self.parse_json(self.llm_call(prompt, temperature=0.0, json_mode=True, economy=True))
            items = answer.get("evidence") if isinstance(answer, dict) else None
            if not isinstance(items, list):
                raise ValueError("no evidence list in the answer")
        except Exception as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"
            print(f"[{self.name}] evidence extraction failed, nothing added: {record['error']}")
            context["evidence"] = record
            return context
        signatures = vector.get("payload_signatures") or []
        kept, dropped = check_evidence(items, text, vector.get("incidental_artifacts") or [],
                                       [s.get("pattern") for s in signatures if isinstance(s, dict)])
        vector["payload_signatures"] = signatures + kept
        context["attack_vector"] = vector
        record.update(proposed=len(items), kept=[k["pattern"] for k in kept], dropped=dropped)
        context["evidence"] = record
        print(f"[{self.name}] {len(items)} strings proposed, {len(kept)} kept, {len(dropped)} dropped")
        return context
