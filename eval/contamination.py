"""Does a detection rule reach the pipeline for this case? (plan 1.3b)

Not a product defect: an analyst whose source contains a rule is well served by
the pipeline reading it. It is a threat to the evaluation's validity: on such a
case the task is partly "adapt the rule that is already there", which can inflate
the scores. Flagged cases are reported separately, never silently dropped.

Three routes, each reported with its detail so every flag can be checked by hand:

  reference_is_rule   An input URL is a rule file or a rule repository.
  sigma_in_text       A Sigma rule is printed in the page text: `logsource:`,
                      `detection:` and `condition:` within 3,000 characters.
  poc_downloads_rule  A file the PoC stage downloads is rule-like: in the SigmaHQ
                      organisation, under a sigma / sigma-rules directory, in Azure
                      Sentinel's Detections, in nuclei-templates, or a .yml/.yaml.

The `.yml` criterion over-counts (a YAML file of TTPs is not a detection rule), so
the flag is an upper bound under this definition. That is disclosed with any number.
"""

from __future__ import annotations

import re

_RULE_URL_RE = re.compile(
    r"(github\.com/SigmaHQ/|/sigma[-_]?rules?/|\.ya?ml($|[?#])|Azure-Sentinel/Detections"
    r"|nuclei-templates|detection\.fyi|sigma\.nasbench)",
    re.IGNORECASE,
)
_RULE_PATH_RE = re.compile(
    r"(^|/)sigma[-_]?rules?(/|$)|/sigma/|Azure-Sentinel/Detections|nuclei-templates",
    re.IGNORECASE,
)
_SIGMA_WINDOW = 3000


def _sigma_rule_in(text: str) -> bool:
    for match in re.finditer(r"logsource\s*:", text):
        window = text[match.start(): match.start() + _SIGMA_WINDOW]
        if re.search(r"detection\s*:", window) and re.search(r"condition\s*:", window):
            return True
    return False


def _rule_like(target: dict) -> bool:
    source = target["source_url"]
    owner_repo_path = source.split("github.com/", 1)[-1].replace("/blob/", "/", 1)
    return (owner_repo_path.lower().startswith("sigmahq/")
            or bool(_RULE_PATH_RE.search(owner_repo_path))
            or target["path"].lower().endswith((".yml", ".yaml")))


def contamination_reasons(urls: list, combined_text: str, poc_file_targets: list) -> list:
    """Every route by which a detection rule reaches the pipeline, with its detail."""
    reasons = [{"reason": "reference_is_rule", "detail": u}
               for u in urls if _RULE_URL_RE.search(u)]
    if _sigma_rule_in(combined_text):
        reasons.append({"reason": "sigma_in_text", "detail": None})
    reasons += [{"reason": "poc_downloads_rule", "detail": t["source_url"]}
                for t in poc_file_targets if _rule_like(t)]
    return reasons
