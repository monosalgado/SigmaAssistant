"""Which GitHub URLs the PoC stage fetches (plan 1.3a).

The snapshot builder and the stage must agree exactly on the fetch list, or the
evaluation would miss (or over-store) files. Both use `github_fetch_targets`.
Offline: pure function over text.
"""

from __future__ import annotations

from backend.pipeline.stage_poc_analysis import github_fetch_targets

TEXT = """
See https://github.com/acme/exploit/blob/main/poc.py and
https://github.com/acme/exploit/blob/main/payload.ps1, also
https://github.com/other/repo/blob/dev/src/a.c and
https://github.com/fourth/one/blob/main/b.sh (a fourth link).
Gists: https://gist.github.com/alice/abc123 https://gist.github.com/bob/def456
https://gist.github.com/carol/ghi789
"""


def test_file_links_become_raw_urls_capped_at_three():
    files, _ = github_fetch_targets(TEXT)
    assert [t["fetch_url"] for t in files] == [
        "https://raw.githubusercontent.com/acme/exploit/main/poc.py",
        "https://raw.githubusercontent.com/acme/exploit/main/payload.ps1",
        "https://raw.githubusercontent.com/other/repo/dev/src/a.c",
    ]
    assert files[0]["source_url"] == "https://github.com/acme/exploit/blob/main/poc.py"
    assert files[0]["path"] == "poc.py"


def test_gists_become_api_urls_capped_at_two():
    _, gists = github_fetch_targets(TEXT)
    assert [t["fetch_url"] for t in gists] == [
        "https://api.github.com/gists/abc123",
        "https://api.github.com/gists/def456",
    ]
    assert gists[0]["source_url"] == "https://gist.github.com/alice/abc123"


def test_text_without_links_has_no_targets():
    assert github_fetch_targets("no links here") == ([], [])


def test_a_ref_containing_a_dot_is_not_matched():
    """Existing behaviour, pinned rather than changed: the branch pattern `[\\w\\-]+`
    has no dot, so a tag such as v1.2 is skipped. Changing it would change what
    the pipeline fetches, which is a behaviour change of its own."""
    files, _ = github_fetch_targets("https://github.com/o/r/blob/v1.2/x.py")
    assert files == []
