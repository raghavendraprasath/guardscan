from __future__ import annotations

from pathlib import Path
from typing import Any

from .detectors import run_detectors
from .explainer import explain_findings


def scan_source(
    source: str,
    *,
    file_label: str = "<stdin>",
    explain: bool = True,
    use_mock_llm: bool | None = None,
) -> dict[str, Any]:
    findings = [f.to_dict() for f in run_detectors(source, file_label)]
    report: dict[str, Any] = {
        "file": file_label,
        "finding_count": len(findings),
        "findings": findings,
    }
    if explain:
        report["explanation"] = explain_findings(
            source, findings, use_mock=use_mock_llm
        )
    return report


def scan_path(
    path: Path,
    *,
    explain: bool = True,
    use_mock_llm: bool | None = None,
) -> dict[str, Any]:
    source = path.read_text(encoding="utf-8")
    return scan_source(
        source,
        file_label=str(path),
        explain=explain,
        use_mock_llm=use_mock_llm,
    )
