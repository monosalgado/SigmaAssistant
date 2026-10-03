"""Deterministic, offline scorers for generated Sigma rules.

Why this exists
---------------
Changes 1-3 all landed with their effect on rule quality unmeasured. These scorers
turn "does the output look better?" into numbers that can be compared across
ablation arms.

What is measured — the S (static) metric family
-----------------------------------------------
S1  parse validity      - does the output parse as a Sigma rule at all?
S2  validator issues    - how many pySigma core-validator issues, by severity?
S3  logsource match     - does logsource agree with the human-authored rule?
S4  ATT&CK agreement    - do the attack.tXXXX tags agree?
S5  detection fields    - do the detection field names agree?

S1 and S2 are absolute (a rule is valid or it is not). S3-S5 are *agreement with a
human analyst*, not correctness: a rule that differs from the gold rule may still be
a good detection.

Metric families (see thesis/OUTLINE.md section 5):
    S1-S6  static  - offline, from rule text alone. S1-S5 are implemented here;
                     S6 (backend compilability) is not built.
    R1-R2  runtime - detection efficacy / false-positive rate. Require detonated
                     telemetry; not built.
    C1-C2  cost    - tokens and latency. See backend/telemetry.py.
Do not reuse the old E0-E7 numbering: it collided across files and is retired.

What is NOT measured, and cannot be
-----------------------------------
Detection efficacy (R1) and false-positive rate (R2). There is no telemetry corpus
here, so true-positive and false-positive rates are out of reach. S5 in particular
compares field *names* and ignores their values, so `Image|endswith: \\evil.exe` and
`Image|endswith: \\good.exe` score identically. These are structural agreement
metrics. Claiming they measure whether a rule catches attacks would be indefensible.

Everything runs offline against local files. No LLM, no network, no API budget.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Optional

import yaml

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.validation import SigmaValidator
from sigma.validators.base import SigmaValidationIssueSeverity
from sigma.validators.core import validators as CORE_VALIDATORS

# Mirrors stage_review.py so evaluation and runtime agree on what counts as an error.
_SEVERITY_NAMES = {
    SigmaValidationIssueSeverity.HIGH: "error",
    SigmaValidationIssueSeverity.MEDIUM: "warning",
    SigmaValidationIssueSeverity.LOW: "info",
}

# attack.t1059 or attack.t1059.001
_TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

_FENCE_RE = re.compile(r"^\s*```(?:ya?ml)?\s*\n(.*?)\n\s*```\s*$", re.DOTALL)


def strip_code_fences(text: str) -> str:
    """Remove a surrounding markdown code fence if present.

    Applied at the LLM-output boundary: models frequently wrap YAML in ```yaml
    fences, which is not valid YAML and would otherwise be scored as a parse
    failure that has nothing to do with rule quality.
    """
    if not text:
        return ""
    match = _FENCE_RE.match(text.strip())
    return match.group(1) if match else text.strip()


def _prf(predicted: set, gold: set) -> dict:
    """Precision/recall/F1 between two sets.

    Returns None for a metric that is undefined rather than silently substituting
    0.0 or 1.0, so undefined cases can be excluded from aggregates instead of
    biasing them.
    """
    overlap = predicted & gold
    precision = len(overlap) / len(predicted) if predicted else None
    recall = len(overlap) / len(gold) if gold else None
    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None if (precision is None or recall is None) else 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "n_predicted": len(predicted),
        "n_gold": len(gold),
        "n_overlap": len(overlap),
    }


# --------------------------------------------------------------------------
# S1 + S2: validity and validator issues
# --------------------------------------------------------------------------

def score_validity(rule_text: str) -> dict:
    """S1/S2. Parse with pySigma and run the core validators.

    A fresh SigmaValidator is constructed per call. Several core validators keep
    state across rules (duplicate title, identifier collision); reusing one
    instance leaks that state and reports phantom issues on unrelated rules.
    """
    result = {
        "parses": False,
        "parse_error": None,
        "issue_count": 0,
        "issues_by_severity": {"error": 0, "warning": 0, "info": 0},
        "issue_types": [],
    }

    text = strip_code_fences(rule_text)
    if not text:
        result["parse_error"] = "empty output"
        return result

    try:
        collection = SigmaCollection.from_yaml(text)
    except (yaml.YAMLError, SigmaError) as exc:
        result["parse_error"] = f"{type(exc).__name__}: {exc}"
        return result
    except Exception as exc:  # pySigma raises a few undeclared types
        result["parse_error"] = f"{type(exc).__name__}: {exc}"
        return result

    if not collection.rules:
        result["parse_error"] = "no rules in document"
        return result

    result["parses"] = True

    validator = SigmaValidator(CORE_VALIDATORS.values())
    try:
        issues = list(validator.validate_rules(collection.rules))
    except Exception as exc:
        result["validation_error"] = f"{type(exc).__name__}: {exc}"
        return result

    for issue in issues:
        name = _SEVERITY_NAMES.get(issue.severity, "info")
        result["issues_by_severity"][name] += 1
        result["issue_types"].append(type(issue).__name__)
    result["issue_count"] = len(issues)
    return result


# --------------------------------------------------------------------------
# S3: logsource agreement
# --------------------------------------------------------------------------

def _norm(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().lower()
    return text or None


def score_logsource(predicted: dict, gold: dict) -> dict:
    """S3. Per-field logsource agreement.

    Fields absent from both rules count as agreeing: omitting `service` when the
    gold rule also omits it is correct, not a miss.
    """
    predicted = predicted or {}
    gold = gold or {}
    per_field = {}
    for field in ("category", "product", "service"):
        p = _norm(predicted.get(field))
        g = _norm(gold.get(field))
        per_field[field] = {
            "predicted": p,
            "gold": g,
            "match": p == g,
            "gold_present": g is not None,
        }
    scored = [f for f in per_field.values() if f["gold_present"]]
    return {
        "exact_match": all(f["match"] for f in per_field.values()),
        "fields_matched": sum(1 for f in scored if f["match"]),
        "fields_scored": len(scored),
        "per_field": per_field,
    }


# --------------------------------------------------------------------------
# S4: ATT&CK technique agreement
# --------------------------------------------------------------------------

def extract_techniques(tags: Iterable) -> set:
    """Pull ATT&CK technique IDs from a Sigma `tags` list.

    Tactic tags (attack.execution) and non-ATT&CK tags (cve.*, detection.*) are
    ignored: only techniques are comparable across rules.
    """
    found = set()
    for tag in tags or []:
        match = _TECHNIQUE_RE.match(str(tag).strip())
        if match:
            found.add(match.group(1).lower())
    return found


def score_attack_tags(predicted_tags: Iterable, gold_tags: Iterable) -> dict:
    """S4. Technique agreement, reported at two granularities.

    `exact` treats t1059.001 and t1059 as different. `parent` collapses
    sub-techniques onto their parent, which credits a prediction that identifies
    the right technique but the wrong variant. Reporting both avoids arguing for
    whichever definition happens to flatter the result.
    """
    predicted = extract_techniques(predicted_tags)
    gold = extract_techniques(gold_tags)
    parent = lambda ids: {i.split(".")[0] for i in ids}
    return {
        "exact": _prf(predicted, gold),
        "parent": _prf(parent(predicted), parent(gold)),
        "predicted": sorted(predicted),
        "gold": sorted(gold),
    }


# --------------------------------------------------------------------------
# S5: detection field agreement
# --------------------------------------------------------------------------

def extract_detection_fields(detection: Any) -> set:
    """Collect field names used anywhere in a Sigma `detection` block.

    Sigma allows selections to be dicts, lists of dicts, or nested combinations,
    so this walks the structure. Modifiers are stripped (`Image|endswith` ->
    `image`) because they qualify a field rather than identify a different one.
    The `condition` key is skipped: it is boolean logic, not a field.
    """
    fields = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                name = str(key).split("|")[0].strip().lower()
                if name:
                    fields.add(name)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    if isinstance(detection, dict):
        for key, value in detection.items():
            if str(key).strip().lower() == "condition":
                continue
            walk(value)
    return fields


def score_detection_fields(predicted: Any, gold: Any) -> dict:
    """S5. Overlap of detection field names.

    Structural only: values are ignored, so this cannot distinguish a rule that
    matches the right process from one that matches the wrong process using the
    same field.
    """
    result = _prf(extract_detection_fields(predicted), extract_detection_fields(gold))
    result["predicted_fields"] = sorted(extract_detection_fields(predicted))
    result["gold_fields"] = sorted(extract_detection_fields(gold))
    return result


def normalise_value(value: Any) -> Optional[str]:
    """A detection value as S5v compares it: lower-cased, `*` wildcards at the ends removed, a
    doubled backslash read as one (rules differ in how they escape a path)."""
    if value is None:
        return None
    text = str(value).strip().lower().strip("*").replace("\\\\", "\\").strip()
    return text or None


def extract_detection_values(detection: Any) -> set:
    """(field, value) pairs a Sigma `detection` looks for. The field is the name before the first
    `|`, as in S5; a bare keyword list has field "". Selections named `filter...` (SigmaHQ's
    convention for exclusions), `condition` and `timeframe` are skipped."""
    values = set()

    def walk(node: Any, field: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, str(key).split("|")[0].strip().lower())
        elif isinstance(node, list):
            for item in node:
                walk(item, field)
        else:
            value = normalise_value(node)
            if value:
                values.add((field, value))

    if isinstance(detection, dict):
        for name, selection in detection.items():
            name = str(name).strip().lower()
            if name in ("condition", "timeframe") or name.startswith("filter"):
                continue
            walk(selection, "")
    return values


def value_matches(gold: str, predicted: str) -> bool:
    """A human value is found by one of ours that contains it (ours is at least as specific), or
    that it contains if ours is at least half as long; under 3 characters, only when equal."""
    if len(gold) < 3 or len(predicted) < 3:
        return gold == predicted
    return gold in predicted or (predicted in gold and 2 * len(predicted) >= len(gold))


def score_detection_values(predicted: Any, gold: Any) -> dict:
    """S5v (roadmap R8). Overlap of the values the detection looks for: recall in any field and in
    the same field, precision and F1 in any field. Undefined (None) on a side with no values."""
    ours, theirs = extract_detection_values(predicted), extract_detection_values(gold)
    found = {g for g in theirs if any(value_matches(g[1], p[1]) for p in ours)}
    found_same_field = {g for g in theirs if any(p[0] == g[0] and value_matches(g[1], p[1]) for p in ours)}
    matched = {p for p in ours if any(value_matches(g[1], p[1]) for g in theirs)}
    recall = len(found) / len(theirs) if theirs else None
    precision = len(matched) / len(ours) if ours else None
    if recall is None or precision is None:
        f1 = None
    else:
        f1 = 0.0 if recall + precision == 0 else 2 * precision * recall / (precision + recall)
    return {
        "recall": recall,
        "recall_same_field": len(found_same_field) / len(theirs) if theirs else None,
        "precision": precision,
        "f1": f1,
        "n_gold": len(theirs),
        "n_predicted": len(ours),
        "found": sorted({g[1] for g in found}),
        "missing": sorted({g[1] for g in theirs - found}),
        "unmatched": sorted({p[1] for p in ours - matched}),
    }


# --------------------------------------------------------------------------
# Top level
# --------------------------------------------------------------------------

def score_case(generated_rule_text: str, gold_rule: dict) -> dict:
    """Score one generated rule against its human-authored counterpart.

    `gold_rule` is the parsed YAML of the emerging-threats rule. Content metrics
    (S3-S5) are only computed when the generated rule parses; scoring an
    unparseable rule's fields would compare against nothing meaningful.
    """
    scores = {"validity": score_validity(generated_rule_text)}

    parsed = None
    if scores["validity"]["parses"]:
        try:
            parsed = yaml.safe_load(strip_code_fences(generated_rule_text))
        except yaml.YAMLError:
            parsed = None

    if not isinstance(parsed, dict):
        scores["logsource"] = None
        scores["attack"] = None
        scores["detection_fields"] = None
        return scores

    scores["logsource"] = score_logsource(parsed.get("logsource"), gold_rule.get("logsource"))
    scores["attack"] = score_attack_tags(parsed.get("tags"), gold_rule.get("tags"))
    scores["detection_fields"] = score_detection_fields(
        parsed.get("detection"), gold_rule.get("detection")
    )
    return scores
