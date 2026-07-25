from __future__ import annotations

import re
from pathlib import Path

from .models import Finding

SENSITIVE_FUNCS = (
    "setOwner",
    "setReserves",
    "withdraw",
    "privilegedWithdraw",
    "mint",
    "burn",
    "pause",
    "unpause",
    "transferOwnership",
)


def _lines(source: str) -> list[str]:
    return source.splitlines()


def _line_no(source: str, index: int) -> int:
    return source.count("\n", 0, index) + 1


def _snippet(source: str, index: int, width: int = 120) -> str:
    line_start = source.rfind("\n", 0, index) + 1
    line_end = source.find("\n", index)
    if line_end < 0:
        line_end = len(source)
    return source[line_start:line_end].strip()[:width]


def detect_tx_origin(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in re.finditer(r"\btx\.origin\b", source):
        evidence = _snippet(source, match.start())
        if evidence.lstrip().startswith("//") or evidence.lstrip().startswith("///"):
            continue
        findings.append(
            Finding(
                id="tx-origin-auth",
                detector="tx_origin",
                severity="High",
                title="Authentication uses tx.origin",
                line=_line_no(source, match.start()),
                evidence=evidence,
                recommendation="Use msg.sender for authorization checks, not tx.origin.",
            )
        )
    return findings


def detect_missing_access_control(source: str) -> list[Finding]:
    findings: list[Finding] = []
    # function <name>(...) external|public  without onlyOwner / require(msg.sender nearby
    pattern = re.compile(
        r"function\s+(\w+)\s*\([^)]*\)\s*(external|public)([^{]*)\{",
        re.MULTILINE,
    )
    for match in pattern.finditer(source):
        name = match.group(1)
        mods = match.group(3)
        if name not in SENSITIVE_FUNCS:
            continue
        if re.search(r"\bonlyOwner\b|\bonlyRole\b", mods):
            continue
        # Look ahead a short window for require(msg.sender == owner)
        body_start = match.end()
        window = source[body_start : body_start + 400]
        if re.search(r"require\s*\(\s*msg\.sender\s*==\s*owner", window):
            continue
        if name == "withdraw" and "balances[msg.sender]" in window:
            # user withdraw of own balance is OK for this heuristic
            continue
        findings.append(
            Finding(
                id=f"missing-access-control-{name}",
                detector="missing_access_control",
                severity="Critical",
                title=f"Sensitive function `{name}` appears to lack access control",
                line=_line_no(source, match.start()),
                evidence=_snippet(source, match.start()),
                recommendation=f"Restrict `{name}` with onlyOwner / AccessControl, or an explicit msg.sender check.",
            )
        )
    return findings


def detect_reentrancy(source: str) -> list[Finding]:
    findings: list[Finding] = []
    # Heuristic: .call{value: ...} followed later (within same function) by a storage write
    call_pat = re.compile(r"\.call\s*\{[^}]*value\s*:", re.IGNORECASE)
    for match in call_pat.finditer(source):
        after = source[match.end() : match.end() + 500]
        # Stop at next function boundary to avoid cross-function false positives
        next_fn = re.search(r"\bfunction\s+\w+\s*\(", after)
        if next_fn:
            after = after[: next_fn.start()]
        if re.search(r"balances\s*\[[^\]]+\]\s*=", after) or re.search(
            r"\w+\s*\[[^\]]+\]\s*=\s*0", after
        ):
            findings.append(
                Finding(
                    id="reentrancy-cei",
                    detector="reentrancy",
                    severity="Critical",
                    title="External call before state update (reentrancy heuristic)",
                    line=_line_no(source, match.start()),
                    evidence=_snippet(source, match.start()),
                    recommendation="Follow checks-effects-interactions: update state before external calls, or use a reentrancy guard.",
                )
            )
    return findings


def detect_swap_no_slippage(source: str) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(
        r"function\s+swap\s*\(([^)]*)\)\s*(external|public)",
        re.IGNORECASE,
    )
    for match in pattern.finditer(source):
        params = match.group(1)
        if re.search(r"\bminOut\b|\bamountOutMin\b|\bminAmountOut\b", params, re.I):
            continue
        findings.append(
            Finding(
                id="swap-no-slippage",
                detector="swap_slippage",
                severity="High",
                title="Swap function lacks slippage protection parameter",
                line=_line_no(source, match.start()),
                evidence=_snippet(source, match.start()),
                recommendation="Add a minOut / amountOutMin parameter and revert when output is below the bound.",
            )
        )
    return findings


def detect_unsafe_erc20(source: str) -> list[Finding]:
    findings: list[Finding] = []
    # Infinite approve
    for match in re.finditer(r"\.approve\s*\([^;]*type\s*\(\s*uint256\s*\)\s*\.\s*max", source):
        findings.append(
            Finding(
                id="infinite-approve",
                detector="unsafe_erc20",
                severity="Medium",
                title="Unlimited ERC-20 approval (type(uint256).max)",
                line=_line_no(source, match.start()),
                evidence=_snippet(source, match.start()),
                recommendation="Approve only the required amount, or use permit / allowance management carefully.",
            )
        )
    # transfer / transferFrom not wrapped in require(...) — crude heuristic
    for match in re.finditer(r"\b(\w+)\.(transfer|transferFrom)\s*\(", source):
        line = _snippet(source, match.start())
        stripped = line.lstrip()
        if stripped.startswith("require"):
            continue
        if "function transfer" in line or "function transferFrom" in line:
            continue
        findings.append(
            Finding(
                id=f"unchecked-erc20-{match.group(2)}-{_line_no(source, match.start())}",
                detector="unsafe_erc20",
                severity="Medium",
                title=f"ERC-20 `{match.group(2)}` return value may be ignored",
                line=_line_no(source, match.start()),
                evidence=line,
                recommendation="Check boolean return values (or use SafeERC20) for non-standard tokens.",
            )
        )
    return findings


DETECTORS = (
    detect_missing_access_control,
    detect_reentrancy,
    detect_swap_no_slippage,
    detect_unsafe_erc20,
    detect_tx_origin,
)


def run_detectors(source: str, path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(source))
    # Stable ordering: severity then line
    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Info": 3}
    findings.sort(key=lambda f: (severity_rank.get(f.severity, 9), f.line or 10**9, f.id))
    return findings


def scan_file(path: Path) -> dict:
    source = path.read_text(encoding="utf-8")
    findings = run_detectors(source, str(path))
    return {
        "file": str(path),
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
