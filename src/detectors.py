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

# Broader net than SENSITIVE_FUNCS: catches the same bug under a different name
# (e.g. updateAdmin vs setOwner). Reported at High rather than Critical because
# the name alone is weaker evidence than an exact match above.
SENSITIVE_NAME_RE = re.compile(
    r"^(set|update|change|upgrade|migrate|initiali[sz]e|withdraw|rescue|sweep|drain"
    r"|mint|burn|pause|unpause|grant|revoke|renounce|kill|destroy|emergency|admin)",
    re.IGNORECASE,
)

# An `onlyX` modifier, or an inline sender/role check in the body.
GUARD_MODIFIER_RE = re.compile(r"\bonly[A-Z_]\w*\b|\bauth\b|\brestricted\b")
GUARD_BODY_RE = re.compile(
    r"require\s*\(\s*msg\.sender\s*==|"
    r"if\s*\(\s*msg\.sender\s*!=|"
    r"_check(?:Owner|Role)\s*\(|"
    r"hasRole\s*\("
)

FUNCTION_RE = re.compile(r"function\s+(\w+)\s*\(([^)]*)\)\s*([^{;]*)\{")

# block.* values an attacker or validator can influence.
MANIPULABLE_RANDOM_RE = re.compile(r"blockhash\s*\(|block\.(prevrandao|difficulty)")
# block.timestamp/number are legitimate for deadlines, so require a randomness hint.
WEAK_RANDOM_RE = re.compile(r"block\.(timestamp|number)")
RANDOM_HINT_RE = re.compile(
    r"\b(seed|random|rand|winner|lottery|shuffle|draw|dice|roll)\b|keccak256|%",
    re.IGNORECASE,
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


def _enclosing_function(source: str, index: int) -> re.Match[str] | None:
    """Return the function header whose body contains `index`, if any."""
    found = None
    for match in FUNCTION_RE.finditer(source):
        if match.start() > index:
            break
        found = match
    return found


def _is_guarded(source: str, header: re.Match[str] | None) -> bool:
    if header is None:
        return False
    if GUARD_MODIFIER_RE.search(header.group(3)):
        return True
    return bool(GUARD_BODY_RE.search(source[header.end() : header.end() + 400]))


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
        exact = name in SENSITIVE_FUNCS
        if not exact and not SENSITIVE_NAME_RE.match(name):
            continue
        # A view/pure function cannot mutate state, so missing auth is not this bug.
        if re.search(r"\b(view|pure)\b", mods):
            continue
        if GUARD_MODIFIER_RE.search(mods):
            continue
        # Look ahead a short window for an inline sender/role check
        body_start = match.end()
        window = source[body_start : body_start + 400]
        if GUARD_BODY_RE.search(window):
            continue
        if name == "withdraw" and "balances[msg.sender]" in window:
            # user withdraw of own balance is OK for this heuristic
            continue
        findings.append(
            Finding(
                id=f"missing-access-control-{name}",
                detector="missing_access_control",
                severity="Critical" if exact else "High",
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


def detect_delegatecall(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in re.finditer(r"\.delegatecall\s*\(", source):
        evidence = _snippet(source, match.start())
        if evidence.lstrip().startswith("//"):
            continue
        header = _enclosing_function(source, match.start())
        guarded = _is_guarded(source, header)
        findings.append(
            Finding(
                id=f"delegatecall-{_line_no(source, match.start())}",
                detector="delegatecall",
                severity="High" if guarded else "Critical",
                title=(
                    "`delegatecall` runs external code against this contract's storage"
                    + ("" if guarded else " from an unrestricted function")
                ),
                line=_line_no(source, match.start()),
                evidence=evidence,
                recommendation=(
                    "Restrict the target to a trusted immutable address and gate the caller; "
                    "never delegatecall an address supplied by the caller."
                ),
            )
        )
    return findings


def detect_unprotected_selfdestruct(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in re.finditer(r"\bselfdestruct\s*\(", source):
        evidence = _snippet(source, match.start())
        if evidence.lstrip().startswith("//"):
            continue
        if _is_guarded(source, _enclosing_function(source, match.start())):
            continue
        findings.append(
            Finding(
                id=f"unprotected-selfdestruct-{_line_no(source, match.start())}",
                detector="unprotected_selfdestruct",
                severity="Critical",
                title="`selfdestruct` reachable from an unrestricted function",
                line=_line_no(source, match.start()),
                evidence=evidence,
                recommendation="Gate self-destruction behind an owner/role check, or remove it.",
            )
        )
    return findings


def detect_weak_randomness(source: str) -> list[Finding]:
    findings: list[Finding] = []
    seen_lines: set[int] = set()
    for pattern, needs_hint in ((MANIPULABLE_RANDOM_RE, False), (WEAK_RANDOM_RE, True)):
        for match in pattern.finditer(source):
            line_no = _line_no(source, match.start())
            if line_no in seen_lines:
                continue
            evidence = _snippet(source, match.start())
            if evidence.lstrip().startswith("//"):
                continue
            if needs_hint and not RANDOM_HINT_RE.search(evidence):
                continue
            seen_lines.add(line_no)
            findings.append(
                Finding(
                    id=f"weak-randomness-{line_no}",
                    detector="weak_randomness",
                    severity="High",
                    title="Randomness derived from block data is manipulable",
                    line=line_no,
                    evidence=evidence,
                    recommendation=(
                        "Block values are influenced by validators and visible to callers; "
                        "use a commit-reveal scheme or a VRF oracle instead."
                    ),
                )
            )
    return findings


DETECTORS = (
    detect_missing_access_control,
    detect_reentrancy,
    detect_swap_no_slippage,
    detect_unsafe_erc20,
    detect_tx_origin,
    detect_delegatecall,
    detect_unprotected_selfdestruct,
    detect_weak_randomness,
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
