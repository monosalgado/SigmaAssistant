#!/usr/bin/env python3
"""Write backend/pipeline/sigma_known_services.json from the local SigmaHQ rules.

The (product, service) pairs SigmaHQ uses in rules without a category (Change 25).
Built from data/sigma/rules — the directory the retrieval index is built from — and
never from rules-emerging-threats, which holds the evaluation's answers.

Usage:
    .venv/bin/python scripts/build_sigma_known_services.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from backend.pipeline.sigma_logsource import KNOWN_SERVICES_PATH, build_known_services  # noqa: E402


def main() -> int:
    rules = REPO / "data/sigma/rules"
    if not rules.is_dir():
        print(f"{rules} not found: clone SigmaHQ into data/sigma first.")
        return 1
    pairs = sorted(build_known_services(rules), key=lambda p: (p[0] or "", p[1]))
    body = ",\n".join(json.dumps(list(p)) for p in pairs)  # one pair per line
    KNOWN_SERVICES_PATH.write_text("[\n" + body + "\n]\n", encoding="utf-8")
    print(f"{len(pairs)} product/service pairs written to {KNOWN_SERVICES_PATH.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
