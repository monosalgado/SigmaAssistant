"""The check an analyst's edited rule gets on every edit (Change 47; design decision 3: "pySigma validation itself is
automatic on every edit - no button").

The pipeline's own deterministic validation (`stage_review.validate_rule_text`: pySigma parse, condition resolution,
the core validators) plus one warning: a log source that no SigmaHQ rule uses (`sigma_logsource.on_table`). No model
call; the rule is never changed - the check only reports.
"""

from __future__ import annotations

import yaml

from backend.pipeline.sigma_logsource import load_logsource_table, on_table
from backend.pipeline.stage_review import validate_rule_text

_TABLE = load_logsource_table()


def _logsource(text: str):
    try:
        rule = yaml.safe_load(text)
    except yaml.YAMLError:
        return None, None
    if not isinstance(rule, dict):
        return None, None
    ls = rule.get("logsource")
    return (rule.get("title") if isinstance(rule.get("title"), str) else None), (ls if isinstance(ls, dict) else None)


def check_rule(text: str) -> dict:
    """{"valid", "errors", "warnings", "issues": [{"severity", "field", "message"}], "title", "logsource"}."""
    text = text or ""
    issues = list(validate_rule_text(text, "rule")) if text.strip() else [
        {"severity": "error", "field": "rule", "message": "The rule is empty"}]
    title, logsource = _logsource(text)
    if logsource and not on_table(logsource, _TABLE):
        shown = ", ".join(f"{k}: {logsource[k]}" for k in ("category", "product", "service") if logsource.get(k))
        issues.append({"severity": "warning", "field": "rule.logsource",
                       "message": f"No SigmaHQ rule uses this log source ({shown}). Check the spelling, or use one "
                                  f"SigmaHQ's rules use."})
    errors = sum(1 for i in issues if i["severity"] == "error")
    return {"valid": errors == 0, "errors": errors, "warnings": sum(1 for i in issues if i["severity"] == "warning"),
            "issues": issues, "title": title, "logsource": logsource}
