#!/usr/bin/env python3
"""Run GuardScan detectors against the labeled evaluation suite.

Reports precision, recall, and F1 at the (file, detector) level, plus an
explicit known-false-negative tally so limitations stay visible.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.detectors import run_detectors  # noqa: E402

EVAL_DIR = Path(__file__).resolve().parent
LABELS_PATH = EVAL_DIR / "labels.json"


def load_cases() -> list[dict]:
    data = json.loads(LABELS_PATH.read_text(encoding="utf-8"))
    return data["cases"]


def score_case(case: dict) -> dict:
    path = (EVAL_DIR / case["path"]).resolve()
    source = path.read_text(encoding="utf-8")
    predicted = {f.detector for f in run_detectors(source)}
    expected = set(case.get("expected_detectors") or [])
    planted_miss = set(case.get("planted_but_undetected") or [])

    tp = predicted & expected
    fp = predicted - expected
    fn = expected - predicted
    # Known misses are documented separately; they are not counted as scoring FN
    # because expected_detectors is empty by design for those cases.
    known_fn_caught = predicted & planted_miss  # would be surprising
    known_fn_missed = planted_miss - predicted

    return {
        "id": case["id"],
        "role": case["role"],
        "path": case["path"],
        "predicted": sorted(predicted),
        "expected": sorted(expected),
        "tp": sorted(tp),
        "fp": sorted(fp),
        "fn": sorted(fn),
        "known_fn_missed": sorted(known_fn_missed),
        "known_fn_caught": sorted(known_fn_caught),
        "notes": case.get("notes", ""),
    }


def aggregate(results: list[dict]) -> dict:
    tp = fp = fn = 0
    known_fn = 0
    for r in results:
        if r["role"] == "known_false_negative":
            known_fn += len(r["known_fn_missed"])
            # Any unexpected finding on a known-miss case still counts as FP.
            fp += len(r["fp"])
            continue
        tp += len(r["tp"])
        fp += len(r["fp"])
        fn += len(r["fn"])

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    )
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "known_false_negatives": known_fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "cases": len(results),
    }


def print_report(results: list[dict], summary: dict) -> None:
    print("GuardScan labeled evaluation")
    print("=" * 56)
    for r in results:
        status = "OK"
        if r["fp"] or r["fn"]:
            status = "MISMATCH"
        if r["role"] == "known_false_negative":
            status = "KNOWN-FN"
        print(f"[{status}] {r['id']}  ({r['role']})")
        print(f"  predicted: {r['predicted'] or '-'}")
        if r["role"] != "known_false_negative":
            print(f"  expected:  {r['expected'] or '-'}")
        if r["fp"]:
            print(f"  FP: {r['fp']}")
        if r["fn"]:
            print(f"  FN: {r['fn']}")
        if r["known_fn_missed"]:
            print(f"  known miss (documented): {r['known_fn_missed']}")
        if r["notes"]:
            print(f"  note: {r['notes']}")
        print()

    print("Summary (detector-level)")
    print("-" * 56)
    for key in (
        "cases",
        "true_positives",
        "false_positives",
        "false_negatives",
        "known_false_negatives",
        "precision",
        "recall",
        "f1",
    ):
        print(f"  {key}: {summary[key]}")
    print()
    print(
        "Precision/recall exclude documented known-false-negative cases from the "
        "FN tally; those are reported separately as known_false_negatives."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of a human report",
    )
    parser.add_argument(
        "--fail-on-mismatch",
        action="store_true",
        help="Exit 1 if any scoring case has FP or FN (known-FN cases allowed)",
    )
    args = parser.parse_args()

    results = [score_case(c) for c in load_cases()]
    summary = aggregate(results)
    payload = {"summary": summary, "results": results}

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print_report(results, summary)

    if args.fail_on_mismatch:
        bad = [
            r
            for r in results
            if r["role"] != "known_false_negative" and (r["fp"] or r["fn"])
        ]
        return 1 if bad else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
