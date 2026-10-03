#!/usr/bin/env python3
"""Detection diagnosis: what a run's rules get right and wrong in the detection itself.

Per case, against the human rule (`rule_path`): whether the first rule's log source is right (S3, as
scored); the fields its detection misses and adds (S5); the values it finds and misses (S5v,
`scorers.score_detection_values`); whether a later rule of the same case scores better on either; and with
--grounding, which of our values and of the human's occur in the report's own text (the case's pages,
preprocessed offline from the snapshots, plus the GitHub files the PoC stage reads - as
`count_example_copies.py`). A value of ours absent from the report came from somewhere else (the model's
knowledge, a prompt's example); a human value absent from it could not have been read from the report.

Detection is split by whether the log source is right: S5 is 0.63-0.69 when it is right and 0.04-0.12 when it
is wrong (held-out runs, `s5_by_logsource.py`), so what the detection gets wrong is read where it is right.
Post-hoc and descriptive: diagnose on the tuning set only.

Usage:
    .venv/bin/python eval/diagnose_detection.py eval/results/c36_yaml60.jsonl [--grounding] [--list]
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from eval.scorers import (extract_detection_values, score_detection_fields,  # noqa: E402
                          score_detection_values, value_matches)


def _norm_text(text: str) -> str:
    return (text or "").lower().replace("\\\\", "\\")


def grounded(value: str, text: str, min_chars: int = 3) -> Optional[bool]:
    """Does the report contain the value? A leading path separator is not required (a rule writes
    `\\schtasks.exe`, a report `schtasks.exe`); under min_chars characters it is not judged (None)."""
    v = value.lstrip("\\/")
    if len(v) < min_chars:
        return None
    return v in _norm_text(text)


def _strings(node) -> str:
    """Every string in a stage's saved output, one per line."""
    if isinstance(node, dict):
        return "\n".join(_strings(v) for v in node.values())
    if isinstance(node, list):
        return "\n".join(_strings(v) for v in node)
    return node if isinstance(node, str) else ""


def _rule_writer_inputs(row: dict):
    """What the rule writer is given, rebuilt with the pipeline's own formatting (`RULE_GENERATION`'s
    inputs): {payload patterns, indicator values, descriptions}, and the incidental list it is told to avoid.
    Descriptions: the vector summary (`format_vector_summary`), the payload signatures' quotes, the
    indicators' other fields, the attack summary, the techniques. Only the first 10 payload signatures and the
    first 20 incidental strings are passed on. Retrieved documents are not saved, so a value reaching the rule
    writer only through them counts as never given."""
    from backend.pipeline.stage_attack_vector import AttackVectorStage
    pipeline = row.get("pipeline") or {}
    vector = pipeline.get("attack_vector") or {}
    sigs = [x for x in (vector.get("payload_signatures") or [])[:10] if isinstance(x, dict)]
    indicators = [i for i in pipeline.get("indicators") or [] if isinstance(i, dict)]
    parts = {
        "payload pattern": "\n".join(str(x.get("pattern") or "") for x in sigs),
        "indicator": "\n".join(str(i.get("value") or "") for i in indicators),
        "description": "\n".join([AttackVectorStage.format_vector_summary(vector),
                                   _strings([{k: v for k, v in x.items() if k != "pattern"} for x in sigs]),
                                   _strings([{k: v for k, v in i.items() if k != "value"} for i in indicators]),
                                   _strings(pipeline.get("attack_summary")), _strings(pipeline.get("ttp_mappings"))]),
    }
    return parts, _strings((vector.get("incidental_artifacts") or [])[:20])


def _parse(rule_text):
    try:
        rule = yaml.safe_load(rule_text)
    except yaml.YAMLError:
        return None
    return rule if isinstance(rule, dict) else None


def case_detection(row: dict, gold_rule: dict, text: Optional[str] = None, min_chars: int = 3) -> dict:
    rules = row.get("rules_yaml") or []
    parsed = [_parse(r) for r in rules]
    first = parsed[0] if parsed else None
    gold_detection = gold_rule.get("detection")
    out = {"rule_id": row["rule_id"], "parses": first is not None,
           "s3_right": bool(((row.get("scores") or {}).get("logsource") or {}).get("exact_match")),
           "s5": None, "s5v": None}
    if first is None:
        return out
    fields = score_detection_fields(first.get("detection"), gold_detection)
    values = score_detection_values(first.get("detection"), gold_detection)
    out.update(s5=fields["f1"], s5_precision=fields["precision"], s5_recall=fields["recall"],
               fields_missing=sorted(set(fields["gold_fields"]) - set(fields["predicted_fields"])),
               fields_extra=sorted(set(fields["predicted_fields"]) - set(fields["gold_fields"])),
               s5v=values["f1"], s5v_recall=values["recall"], s5v_recall_same_field=values["recall_same_field"],
               s5v_precision=values["precision"], values_found=values["found"], values_missing=values["missing"],
               values_unmatched=values["unmatched"])
    best = {"s5": (out["s5"], 0), "s5v": (out["s5v"], 0)}
    for i, rule in enumerate(parsed[1:], 1):
        if rule is None:
            continue
        for key, score in (("s5", score_detection_fields(rule.get("detection"), gold_detection)["f1"]),
                           ("s5v", score_detection_values(rule.get("detection"), gold_detection)["f1"])):
            if score is not None and (best[key][0] is None or score > best[key][0]):
                best[key] = (score, i)
    out.update(best_s5=best["s5"][0], best_s5_rule=best["s5"][1],
               best_s5v=best["s5v"][0], best_s5v_rule=best["s5v"][1])
    if text is not None:
        ours = sorted({v for _, v in extract_detection_values(first.get("detection"))})
        theirs = sorted({v for _, v in extract_detection_values(gold_detection)})
        ours_judged = {v: grounded(v, text, min_chars) for v in ours}
        gold_judged = {v: grounded(v, text, min_chars) for v in theirs}
        out.update(ours_judged=sum(g is not None for g in ours_judged.values()),
                   ours_grounded=sum(g is True for g in ours_judged.values()),
                   ours_ungrounded=[v for v, g in ours_judged.items() if g is False],
                   gold_judged=sum(g is not None for g in gold_judged.values()),
                   gold_grounded=sum(g is True for g in gold_judged.values()),
                   gold_ungrounded=[v for v, g in gold_judged.items() if g is False],
                   gold_grounded_found=sum(g is True and v in values["found"] for v, g in gold_judged.items()))
        given, blacklist = _rule_writer_inputs(row)
        later = {v for rule in parsed[1:] if rule for _, v in extract_detection_values(rule.get("detection"))}
        missed = []
        for value, in_report in gold_judged.items():
            if in_report is not True or value in values["found"]:
                continue
            status = ("given as a payload pattern" if grounded(value, given["payload pattern"], min_chars) else
                      "given as an indicator" if grounded(value, given["indicator"], min_chars) else
                      "given only in a description" if grounded(value, given["description"], min_chars) else
                      "blacklisted" if grounded(value, blacklist, min_chars) else "never given")
            missed.append({"value": value, "status": status,
                           "in_later_rule": any(value_matches(value, p) for p in later)})
        out["missed_available"] = missed
    return out


def _mean(values) -> Optional[float]:
    values = [v for v in values if v is not None]
    return sum(values) / len(values) if values else None


def _group(rows: list) -> dict:
    g = {"cases": len(rows)}
    for key in ("s5", "s5_precision", "s5_recall", "s5v", "s5v_recall", "s5v_recall_same_field",
                "s5v_precision", "best_s5", "best_s5v"):
        g[key] = _mean(r.get(key) for r in rows)
    g["s5_perfect"] = sum(r.get("s5") == 1.0 for r in rows)
    g["missed_a_field"] = sum(bool(r.get("fields_missing")) for r in rows)
    g["added_a_field"] = sum(bool(r.get("fields_extra")) for r in rows)
    g["right_fields_no_value"] = sum((r.get("s5") or 0) >= 0.5 and r.get("s5v_recall") == 0 for r in rows)
    g["later_rule_better_s5v"] = sum(r.get("best_s5v_rule", 0) > 0 for r in rows)
    g["fields_missing"] = dict(Counter(f for r in rows for f in r.get("fields_missing") or []).most_common())
    g["fields_extra"] = dict(Counter(f for r in rows for f in r.get("fields_extra") or []).most_common())
    if any("ours_judged" in r for r in rows):
        for side in ("ours", "gold"):
            judged = sum(r.get(f"{side}_judged", 0) for r in rows)
            g[f"{side}_grounded"] = (sum(r.get(f"{side}_grounded", 0) for r in rows), judged)
        g["ours_ungrounded"] = dict(Counter(v for r in rows for v in r.get("ours_ungrounded") or []).most_common())
        g["gold_grounded_found"] = (sum(r.get("gold_grounded_found", 0) for r in rows),
                                    sum(r.get("gold_grounded", 0) for r in rows))
        g["missed_available"] = dict(Counter(m["status"] for r in rows for m in r.get("missed_available") or []))
        g["missed_examples"] = {status: [m["value"] for r in rows for m in r.get("missed_available") or []
                                         if m["status"] == status][:8] for status in g["missed_available"]}
        g["missed_in_later_rule"] = sum(m["in_later_rule"] for r in rows for m in r.get("missed_available") or [])
        g["gold_none_grounded"] = sum(r.get("gold_judged", 0) > 0 and r.get("gold_grounded") == 0 for r in rows)
    return g


def summarise(results: list) -> dict:
    parsed = [r for r in results if r["parses"]]
    return {"cases": len(results), "parses": len(parsed),
            "right": _group([r for r in parsed if r["s3_right"]]),
            "wrong": _group([r for r in parsed if not r["s3_right"]])}


def _case_text(case: dict, url_map: dict) -> str:
    from backend.pipeline.stage_preprocess import PreprocessStage
    from eval.count_example_copies import github_bodies, model_input
    from eval.run_eval import snapshots_instead_of_network
    with snapshots_instead_of_network(case["url_to_path"]), contextlib.redirect_stdout(io.StringIO()):
        ctx = PreprocessStage(None, "").run({"original_query": " ".join(case["urls"]), "history": [],
                                             "media_file": None})
    text = ctx["preprocessed"]["combined_text"]
    return model_input(text, github_bodies(text, url_map))


def _fmt(v) -> str:
    return "  -  " if v is None else f"{v:.3f}"


def print_summary(name: str, s: dict) -> None:
    print(f"\n{name}: {s['cases']} cases, first rule parses in {s['parses']}")
    for label in ("right", "wrong"):
        g = s[label]
        print(f"\n  log source {label}: {g['cases']} cases")
        print(f"    S5  (fields) F1 {_fmt(g['s5'])}  precision {_fmt(g['s5_precision'])}  recall {_fmt(g['s5_recall'])}"
              f"   perfect {g['s5_perfect']}; missed a human field {g['missed_a_field']}; added one {g['added_a_field']}")
        print(f"    S5v (values) F1 {_fmt(g['s5v'])}  precision {_fmt(g['s5v_precision'])}  recall {_fmt(g['s5v_recall'])}"
              f"  (same field {_fmt(g['s5v_recall_same_field'])})")
        print(f"    S5 >= 0.5 but no human value found: {g['right_fields_no_value']} cases")
        print(f"    best rule of the case: S5 {_fmt(g['best_s5'])}, S5v {_fmt(g['best_s5v'])}; "
              f"a later rule has a better S5v in {g['later_rule_better_s5v']}")
        print(f"    human fields missed: {dict(list(g['fields_missing'].items())[:8])}")
        print(f"    fields added:        {dict(list(g['fields_extra'].items())[:8])}")
        if "ours_grounded" in g:
            (og, oj), (gg, gj) = g["ours_grounded"], g["gold_grounded"]
            print(f"    our values in the report: {og} of {oj}; the human's: {gg} of {gj} "
                  f"(cases with none of the human's: {g['gold_none_grounded']})")
            print(f"    of the human's values in the report, ours found {g['gold_grounded_found'][0]} of "
                  f"{g['gold_grounded_found'][1]}")
            print(f"    of those the first rule missed: {g['missed_available']}; "
                  f"a later rule of the case uses {g['missed_in_later_rule']}")
            for status, examples in g["missed_examples"].items():
                print(f"      {status}: {examples}")
            print(f"    our values not in the report, most common: {dict(list(g['ours_ungrounded'].items())[:10])}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("runs", nargs="+")
    parser.add_argument("--grounding", action="store_true", help="also check values against the report's text")
    parser.add_argument("--list", action="store_true", help="one line per case")
    parser.add_argument("--min-value-chars", type=int, default=3,
                        help="judge only values at least this long against the report (sensitivity check)")
    args = parser.parse_args()
    cases, url_map = {}, {}
    if args.grounding:
        from eval.run_eval import load_cases, load_github_manifest
        cases = {c["rule_id"]: c for c in load_cases(REPO / "eval/manifest.jsonl", REPO, 2000)}
        url_map = load_github_manifest(REPO / "eval/github_manifest.jsonl")
    texts = {}
    for run in args.runs:
        rows = [json.loads(l) for l in open(run, encoding="utf-8") if l.strip()]
        results = []
        for row in rows:
            gold = yaml.safe_load(open(REPO / row["rule_path"], encoding="utf-8"))
            text = None
            if args.grounding and row["rule_id"] in cases:
                if row["rule_id"] not in texts:
                    texts[row["rule_id"]] = _case_text(cases[row["rule_id"]], url_map)
                text = texts[row["rule_id"]]
            results.append(case_detection(row, gold, text, args.min_value_chars))
        print_summary(Path(run).stem, summarise(results))
        if args.list:
            for r in results:
                if r["parses"]:
                    print(f"    {r['rule_id'][:8]} S3 {'right' if r['s3_right'] else 'wrong'}  S5 {_fmt(r['s5'])}  "
                          f"S5v {_fmt(r['s5v'])}  missing {r.get('values_missing', [])[:3]}  "
                          f"ours {r.get('values_unmatched', [])[:3]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
