"""Log-source ranking (Change 38 v3): a short second model call that orders the analysis stage's
candidate log sources by the evidence each would record.

The analysis finds the text's evidence and judges which items are specific to the attack
(`evidence_inventory`), but within its one long answer it does not rank by its own judgements (log
2026-09-30). Here that comparison is the model's only task. The model decides the order; code only
checks: a log source the model adds must be one SigmaHQ's rules use (Sigma's service convention first,
then `on_table`); every earlier suggestion is kept (one the model leaves out goes to the end); if the
call fails, the analysis's order stands. Everything is recorded for measurement.
"""

from __future__ import annotations

import json

from backend.pipeline import prompts
from backend.pipeline.base_stage import PipelineStage
from backend.pipeline.sigma_logsource import _clean, normalise_suggestion, on_table

_FIELDS = ("category", "product", "service")


def _key(suggestion: dict) -> tuple:
    return tuple(_clean(suggestion.get(f)) for f in _FIELDS)


def _name(suggestion: dict) -> str:
    return "/".join(v for v in _key(suggestion) if v) or "?"


class LogSourceRankingStage(PipelineStage):
    name = "logsource_ranking"
    description = "Ranking the log sources by the evidence each would record"

    def run(self, context: dict) -> dict:  # used only through `rank`, from the analysis stage
        return context

    @staticmethod
    def _candidates(suggestions: list) -> str:
        lines = []
        for i, s in enumerate(suggestions, 1):
            evidence = "; ".join(str(e) for e in (s.get("evidence") or [])) or "(none named)"
            lines.append(f"{i}. {_name(s)} - evidence: {evidence}")
        return "\n".join(lines)

    @staticmethod
    def _inventory(inventory: list) -> str:
        lines = [f"- {item.get('evidence')} | {item.get('log_source')} | specific: "
                 f"{str(bool(item.get('specific'))).lower()}"
                 for item in inventory if isinstance(item, dict)]
        return "\n".join(lines) or "(none)"

    def rank(self, suggestions: list, inventory: list, table: dict, known_services: set):
        """(suggestions in the model's order, a record of what the ranking did)."""
        suggestions = [s for s in suggestions if isinstance(s, dict)]
        before = [_name(s) for s in suggestions]
        record = {"ran": False, "before": before, "after": before, "changed_top": False,
                  "added": [], "dropped": [], "reason": "", "error": None}
        if not suggestions:
            return suggestions, record
        record["ran"] = True
        prompt = prompts.LOGSOURCE_RANKING.format(candidates=self._candidates(suggestions),
                                                  inventory=self._inventory(inventory or []))
        try:
            answer = self.parse_json(self.llm_call(prompt, temperature=0.0, json_mode=True, economy=True))
            ranking = answer.get("ranking") if isinstance(answer, dict) else None
            if not isinstance(ranking, list) or not ranking:
                raise ValueError("no ranking in the answer")
        except Exception as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"
            print(f"[{self.name}] ranking failed, the analysis's order stands: {record['error']}")
            return suggestions, record

        by_key = {_key(s): s for s in suggestions}
        ordered, seen = [], set()
        for item in ranking:
            if not isinstance(item, dict):
                continue
            key = _key(item)
            if key in seen:
                continue
            if key in by_key:
                ordered.append(by_key[key])
                seen.add(key)
                continue
            added = normalise_suggestion({f: item.get(f) for f in _FIELDS}, known_services)
            if _key(added) in by_key or _key(added) in seen:        # the same log source once normalised
                if _key(added) in by_key and _key(added) not in seen:
                    ordered.append(by_key[_key(added)])
                    seen.add(_key(added))
                continue
            if on_table(added, table):
                added.update(evidence=item.get("evidence") or [], added_by=self.name)
                ordered.append(added)
                seen.add(_key(added))
                record["added"].append(_name(added))
            else:
                record["dropped"].append(_name(item))
        ordered += [s for s in suggestions if _key(s) not in seen]      # none is lost
        record.update(after=[_name(s) for s in ordered], changed_top=_key(ordered[0]) != _key(suggestions[0]),
                      reason=str(answer.get("reason", "")))
        return ordered, record
