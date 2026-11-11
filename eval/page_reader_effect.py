#!/usr/bin/env python3
"""Two page readers on the saved pages (Change 61's offline measure, plan in the log 2026-11-10).

The old reader is this checkout's `PreprocessStage._extract_page_content`; the new one is the same function in
another checkout (`--code`). Per page: characters; whether it reaches the 40,000-character cut; the old reader's code
blocks and how many the new reader keeps; how many of the new reader's blocks follow a line of prose; and, from the
HTML alone, how many `p` and `li` elements lose a space when their text is stripped and joined (the old reader's
`get_text(strip=True)`). Per case set: those figures, and the cases on either side of the 2,000-character threshold.
No model, no network.

Usage:
    .venv/bin/python eval/page_reader_effect.py --code ../SigmaAssistant-c61 [--cases RUN.jsonl --scope windows-linux]
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

_FENCE = re.compile(r"```[^\n]*\n(.*?)\n```", re.DOTALL)
_READER_HEADINGS = ("--- Code/Config Snippets ---", "--- Article Content ---", "--- Code further down the page")


def blocks_of(text: str) -> list:
    return [m.group(1).strip() for m in _FENCE.finditer(text or "")]


def blocks_after_prose(text: str) -> int:
    """Blocks whose nearest non-empty line before them is text, not another block or a heading of the reader."""
    count = 0
    for m in _FENCE.finditer(text or ""):
        before = [line for line in text[:m.start()].splitlines() if line.strip()]
        if before and not before[-1].strip().startswith("```") and not before[-1].startswith(_READER_HEADINGS):
            count += 1
    return count


def glued_elements(html) -> dict:
    from bs4 import BeautifulSoup
    elements = glued = 0
    for tag in BeautifulSoup(html, "html.parser").find_all(["p", "li"]):
        stripped = tag.get_text(strip=True)
        if len(stripped) <= 5:
            continue
        elements += 1
        spaced = " ".join(tag.get_text().split())
        if stripped.replace(" ", "") == spaced.replace(" ", "") and stripped.count(" ") < spaced.count(" "):
            glued += 1
    return {"elements": elements, "glued": glued}


def page_summary(old: str, new: str, limit: int, old_uncut: int = None, new_uncut: int = None) -> dict:
    """`*_uncut`: the length each reader gives without the budget (a page is cut when it is over the budget; the new
    reader cuts at a line break, so its text is seldom exactly the budget long)."""
    old_blocks = blocks_of(old)
    new_text = new or ""
    old_uncut = len(old) if old_uncut is None else old_uncut
    new_uncut = len(new_text) if new_uncut is None else new_uncut
    return {"chars_old": len(old), "chars_new": len(new_text), "at_cut_old": old_uncut > limit - 1,
            "at_cut_new": new_uncut > limit, "uncut_old": old_uncut, "uncut_new": new_uncut,
            "blocks_old": len(old_blocks),
            "kept": sum(1 for b in old_blocks if b in new_text), "blocks_new": len(blocks_of(new_text)),
            "after_prose": blocks_after_prose(new_text)}


def _reader(code: Path):
    spec = importlib.util.spec_from_file_location("page_reader_under_test",
                                                  code / "backend" / "pipeline" / "stage_preprocess.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.PreprocessStage(None, "")


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--code", required=True, type=Path, help="the checkout with the new reader")
    parser.add_argument("--cases", type=Path, default=None, help="a results file naming the cases of a second set")
    parser.add_argument("--scope", default=None)
    parser.add_argument("--min-chars", type=int, default=2000)
    args = parser.parse_args(argv)

    from backend.pipeline.stage_preprocess import PreprocessStage
    from eval.scope import in_scope
    old_reader, new_reader = PreprocessStage(None, ""), _reader(args.code.resolve())
    limit = old_reader.MAX_PAGE_TEXT
    cases = {}
    for line in (REPO / "eval" / "manifest.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            entry = json.loads(line)
            if entry.get("status") == "ok":
                cases[entry["rule_id"]] = entry
    pages, totals = {}, {}
    with contextlib.redirect_stdout(io.StringIO()):
        for rule_id, entry in cases.items():
            old_total = new_total = 0
            for snap in entry.get("snapshots") or []:
                path = REPO / snap["path"]
                if not path.exists():
                    continue
                if str(path) not in pages:
                    html = path.read_bytes()
                    old, _ = old_reader._extract_page_content(html, snap["url"])
                    new, _ = new_reader._extract_page_content(html, snap["url"])
                    lengths = []
                    for reader in (old_reader, new_reader):
                        reader.MAX_PAGE_TEXT = 10 ** 9
                        lengths.append(len(reader._extract_page_content(html, snap["url"])[0]))
                        reader.MAX_PAGE_TEXT = limit
                    pages[str(path)] = dict(page_summary(old, new, limit, *lengths), **glued_elements(html))
                old_total += pages[str(path)]["chars_old"]
                new_total += pages[str(path)]["chars_new"]
            totals[rule_id] = (old_total, new_total)

    def report(ids, label):
        paths = {str(REPO / s["path"]) for rid in ids for s in cases[rid].get("snapshots") or []
                 if (REPO / s["path"]).exists()}
        P = [pages[p] for p in paths]
        add = lambda key: sum(p[key] for p in P)
        crossing = [cases[r]["title"] for r in ids
                    if (totals[r][0] >= args.min_chars) != (totals[r][1] >= args.min_chars)]
        print(f"\n{label}: {len(ids)} cases, {len(P)} pages")
        print(f"  characters: old {add('chars_old'):,}  new {add('chars_new'):,}; without the budget: old "
              f"{add('uncut_old'):,}  new {add('uncut_new'):,}")
        print(f"  pages over the {limit:,}-character budget: old {sum(p['at_cut_old'] for p in P)}  "
              f"new {sum(p['at_cut_new'] for p in P)}")
        print(f"  code blocks of the old reader {add('blocks_old')}: kept by the new {add('kept')} "
              f"(pages keeping fewer: {sum(p['kept'] < p['blocks_old'] for p in P)}); blocks of the new reader "
              f"{add('blocks_new')}, after a line of prose {add('after_prose')}")
        print(f"  p and li elements {add('elements'):,}; losing a space with the old reader {add('glued'):,}")
        print(f"  cases crossing the {args.min_chars:,}-character threshold: {len(crossing)} {crossing}")

    report(list(cases), "the corpus (manifest, status ok)")
    if args.cases:
        rows = [json.loads(l) for l in args.cases.read_text(encoding="utf-8").splitlines() if l.strip()]
        ids = [r["rule_id"] for r in rows if (not args.scope or in_scope(r, args.scope)) and r["rule_id"] in cases]
        report(ids, f"the cases of {args.cases.name}" + (f" ({args.scope})" if args.scope else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
