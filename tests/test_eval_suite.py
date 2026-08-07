"""Final-delivery gate for the labeled evaluation suite."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_labeled_eval_suite_matches_labels():
    result = subprocess.run(
        [sys.executable, str(ROOT / "eval" / "run_eval.py"), "--fail-on-mismatch", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    summary = json.loads(result.stdout)["summary"]
    assert summary["false_positives"] == 0
    assert summary["false_negatives"] == 0
    assert summary["precision"] == 1.0
    assert summary["recall"] == 1.0
    assert summary["known_false_negatives"] >= 1
