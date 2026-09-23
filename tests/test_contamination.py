"""The contamination flag: a detection rule reaches the pipeline (plan 1.3b).

Not a product defect — an analyst whose source contains a rule is well served by
reading it — but on such cases the evaluation partly measures "adapt the rule that
is already there", so they are reported separately. Offline, pure functions.
"""

from __future__ import annotations

from eval.contamination import contamination_reasons

ARTICLE = "The actor used rundll32 to load a DLL and dumped LSASS with procdump."
SIGMA_IN_ARTICLE = ARTICLE + """
Here is our detection:
title: Suspicious rundll32
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\rundll32.exe'
    condition: selection
"""


def _file(owner, repo, path):
    return {"fetch_url": f"https://raw.githubusercontent.com/{owner}/{repo}/main/{path}",
            "source_url": f"https://github.com/{owner}/{repo}/blob/main/{path}", "path": path}


def reasons(urls=("https://blog.example.com/report",), text=ARTICLE, poc=()):
    return {r["reason"] for r in contamination_reasons(list(urls), text, list(poc))}


def test_an_ordinary_article_is_clean():
    assert reasons() == set()


def test_a_sigma_rule_printed_in_the_page_is_flagged():
    assert reasons(text=SIGMA_IN_ARTICLE) == {"sigma_in_text"}


def test_the_three_keys_far_apart_are_not_a_rule():
    """'logsource', 'detection' and 'condition' scattered through prose."""
    text = "logsource: x " + "filler " * 800 + "detection: y condition: z"
    assert reasons(text=text) == set()


def test_a_reference_that_is_a_rule_file_is_flagged():
    assert reasons(urls=["https://github.com/rapid7/Rapid7-Labs/blob/main/Sigma/CVE-2024-3400.yml"]) == {"reference_is_rule"}


def test_a_reference_into_the_sigmahq_repo_is_flagged():
    assert reasons(urls=["https://github.com/SigmaHQ/sigma/pull/1234"]) == {"reference_is_rule"}


def test_a_poc_download_from_sigmahq_is_flagged():
    poc = [_file("SigmaHQ", "sigma", "rules/windows/process_creation/x.yml")]
    assert reasons(poc=poc) == {"poc_downloads_rule"}


def test_a_poc_download_of_a_sentinel_detection_is_flagged():
    poc = [_file("Azure", "Azure-Sentinel", "Detections/MultipleDataSources/SOURGUM_IOC.yaml")]
    assert reasons(poc=poc) == {"poc_downloads_rule"}


def test_a_poc_download_of_exploit_code_is_clean():
    assert reasons(poc=[_file("horizon3ai", "CVE-2021-44077", "exploit.py")]) == set()


def test_each_reason_carries_its_detail():
    out = contamination_reasons(
        ["https://github.com/SigmaHQ/sigma/pull/1"], ARTICLE,
        [_file("SigmaHQ", "sigma", "rules/a.yml")])
    details = {r["reason"]: r["detail"] for r in out}
    assert details["reference_is_rule"] == "https://github.com/SigmaHQ/sigma/pull/1"
    assert details["poc_downloads_rule"] == "https://github.com/SigmaHQ/sigma/blob/main/rules/a.yml"
