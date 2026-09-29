#!/usr/bin/env python3
"""The pipeline's prompts in two versions of the code, side by side: which prompts exist, which
pipeline files use them, their size, their inputs (the `{placeholders}` filled at run time) and
what changed. Offline: each version's `backend/pipeline/prompts.py` is read with `git show` and
parsed, never imported, so old code does not run.

Written for the professor's question (2026-09-28): how was the prompt in May, and how different
is it now? The May code is 2ec05f6 (2026-05-14); 7b80426 (2026-04-12) is the version before the
attack-vector stage.

A template's size is not the size of the prompt the model reads: the placeholders are filled
with the report, the retrieved rules and the earlier stages' results.

Usage:
    .venv/bin/python eval/prompt_history.py <rev A> <rev B>                 # the table
    .venv/bin/python eval/prompt_history.py <rev A> <rev B> --diff RULE_GENERATION
"""

from __future__ import annotations

import argparse
import ast
import difflib
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROMPTS_PATH = "backend/pipeline/prompts.py"
_PLACEHOLDER = re.compile(r"(?<!\{)\{([a-z_][a-z0-9_]*)\}(?!\})")
_USE = re.compile(r"prompts\.([A-Z][A-Z0-9_]*)")


def prompt_templates(source: str) -> dict:
    """The module's string constants: NAME = "..." at the top level (docstring and f-strings
    are not constants)."""
    out = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out[target.id] = node.value.value
    return out


def template_inputs(text: str) -> list:
    """The placeholders `str.format` fills, in order of first use; `{{`…`}}` are literal braces."""
    seen = []
    for name in _PLACEHOLDER.findall(text):
        if name not in seen:
            seen.append(name)
    return seen


def prompt_users(grep_lines: list) -> dict:
    """{prompt name: files that use it} from `git grep -n` lines (`rev:path:line:text`).
    Files under an `archive/` folder are left out: the pipeline no longer calls them."""
    users = {}
    for line in grep_lines:
        parts = line.split(":", 3)
        if len(parts) < 4 or "/archive/" in parts[1] or parts[1].endswith("/prompts.py"):
            continue
        for name in _USE.findall(parts[3]):
            users.setdefault(name, set()).add(Path(parts[1]).name)
    return users


def compare(old: dict, new: dict, users_old: dict = None, users_new: dict = None) -> list:
    """One row per prompt in either version: same / changed / added / removed, with sizes and
    the inputs added or removed."""
    users_old, users_new = users_old or {}, users_new or {}
    rows = []
    for name in list(old) + [n for n in new if n not in old]:
        a, b = old.get(name), new.get(name)
        ins_a = template_inputs(a) if a is not None else []
        ins_b = template_inputs(b) if b is not None else []
        status = "added" if a is None else "removed" if b is None else "same" if a == b else "changed"
        rows.append({"name": name, "status": status,
                     "chars_old": None if a is None else len(a), "chars_new": None if b is None else len(b),
                     "inputs_old": ins_a, "inputs_new": ins_b,
                     "inputs_added": [i for i in ins_b if i not in ins_a],
                     "inputs_removed": [i for i in ins_a if i not in ins_b],
                     "used_old": sorted(users_old.get(name, ())), "used_new": sorted(users_new.get(name, ()))})
    return rows


def _git(*args) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def templates_at(rev: str) -> dict:
    return prompt_templates(_git("show", f"{rev}:{PROMPTS_PATH}"))


def users_at(rev: str) -> dict:
    out = subprocess.run(["git", "grep", "-n", "-E", r"prompts\.[A-Z]", rev, "--", "backend/"],
                         cwd=ROOT, capture_output=True, text=True).stdout
    return prompt_users(out.splitlines())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("a")
    parser.add_argument("b")
    parser.add_argument("--diff", metavar="PROMPT", help="print one prompt's line diff between the two versions")
    args = parser.parse_args()
    old, new = templates_at(args.a), templates_at(args.b)
    if args.diff:
        print("".join(difflib.unified_diff((old.get(args.diff) or "").splitlines(True),
                                           (new.get(args.diff) or "").splitlines(True),
                                           f"{args.a}:{args.diff}", f"{args.b}:{args.diff}", n=1)))
        return
    rows = compare(old, new, users_at(args.a), users_at(args.b))
    fmt = lambda v: "-" if v is None else str(v)  # noqa: E731
    print(f"A = {args.a}   B = {args.b}   (chars = template size, before its inputs are filled)\n")
    print(f"{'prompt':<26} {'status':<8} {'chars A':>8} {'chars B':>8}  used by (A -> B)")
    for r in rows:
        used = f"{','.join(r['used_old']) or '(unused)'} -> {','.join(r['used_new']) or '(unused)'}"
        print(f"{r['name']:<26} {r['status']:<8} {fmt(r['chars_old']):>8} {fmt(r['chars_new']):>8}  {used}")
        if r["inputs_added"] or r["inputs_removed"]:
            print(f"{'':<26}   inputs added: {r['inputs_added'] or '-'}   removed: {r['inputs_removed'] or '-'}")
    in_use = [r for r in rows if r["used_new"]]
    print(f"\nPrompts the pipeline uses in B: {len(in_use)}; of these, unchanged since A: "
          f"{sum(1 for r in in_use if r['status'] == 'same')}")


if __name__ == "__main__":
    main()
