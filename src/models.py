from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

Severity = Literal["Critical", "High", "Medium", "Info"]


@dataclass
class Finding:
    id: str
    detector: str
    severity: Severity
    title: str
    line: int | None
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
