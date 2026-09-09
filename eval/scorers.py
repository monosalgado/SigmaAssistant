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
