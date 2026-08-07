import type { Finding, Severity } from "./types";

const SENSITIVE_FUNCS = new Set([
  "setOwner",
  "setReserves",
  "withdraw",
  "privilegedWithdraw",
  "mint",
  "burn",
  "pause",
  "unpause",
  "transferOwnership",
]);

const SENSITIVE_NAME_RE =
  /^(set|update|change|upgrade|migrate|initiali[sz]e|withdraw|rescue|sweep|drain|mint|burn|pause|unpause|grant|revoke|renounce|kill|destroy|emergency|admin)/i;

const GUARD_MODIFIER_RE = /\bonly[A-Z_]\w*\b|\bauth\b|\brestricted\b/;
const GUARD_BODY_RE =
  /require\s*\(\s*msg\.sender\s*==|if\s*\(\s*msg\.sender\s*!=|_check(?:Owner|Role)\s*\(|hasRole\s*\(/;

const FUNCTION_RE = /function\s+(\w+)\s*\(([^)]*)\)\s*([^{;]*)\{/g;

const MANIPULABLE_RANDOM_RE = /blockhash\s*\(|block\.(prevrandao|difficulty)/g;
const WEAK_RANDOM_RE = /block\.(timestamp|number)/g;
const RANDOM_HINT_RE =
  /\b(seed|random|rand|winner|lottery|shuffle|draw|dice|roll)\b|keccak256|%/i;

function lineNo(source: string, index: number): number {
  return source.slice(0, index).split("\n").length;
}

function snippet(source: string, index: number, width = 120): string {
  const lineStart = source.lastIndexOf("\n", index - 1) + 1;
  let lineEnd = source.indexOf("\n", index);
  if (lineEnd < 0) lineEnd = source.length;
  return source.slice(lineStart, lineEnd).trim().slice(0, width);
}

function enclosingFunction(
  source: string,
  index: number,
): RegExpExecArray | null {
  let found: RegExpExecArray | null = null;
  const re = new RegExp(FUNCTION_RE.source, "g");
  let match: RegExpExecArray | null;
  while ((match = re.exec(source))) {
    if (match.index > index) break;
    found = match;
  }
  return found;
}

function isGuarded(source: string, header: RegExpExecArray | null): boolean {
  if (!header) return false;
  if (GUARD_MODIFIER_RE.test(header[3] ?? "")) return true;
  const bodyStart = header.index + header[0].length;
  return GUARD_BODY_RE.test(source.slice(bodyStart, bodyStart + 400));
}

function detectTxOrigin(source: string): Finding[] {
  const findings: Finding[] = [];
  const re = /\btx\.origin\b/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(source))) {
    const evidence = snippet(source, match.index);
    if (evidence.trimStart().startsWith("//") || evidence.trimStart().startsWith("///")) {
      continue;
    }
    findings.push({
      id: "tx-origin-auth",
      detector: "tx_origin",
      severity: "High",
      title: "Authentication uses tx.origin",
      line: lineNo(source, match.index),
      evidence,
      recommendation: "Use msg.sender for authorization checks, not tx.origin.",
    });
  }
  return findings;
}

function detectMissingAccessControl(source: string): Finding[] {
  const findings: Finding[] = [];
  const pattern =
    /function\s+(\w+)\s*\([^)]*\)\s*(external|public)([^{]*)\{/gm;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(source))) {
    const name = match[1];
    const mods = match[3] ?? "";
    const exact = SENSITIVE_FUNCS.has(name);
    if (!exact && !SENSITIVE_NAME_RE.test(name)) continue;
    if (/\b(view|pure)\b/.test(mods)) continue;
    if (GUARD_MODIFIER_RE.test(mods)) continue;
    const bodyStart = match.index + match[0].length;
    const window = source.slice(bodyStart, bodyStart + 400);
    if (GUARD_BODY_RE.test(window)) continue;
    if (name === "withdraw" && window.includes("balances[msg.sender]")) continue;
    findings.push({
      id: `missing-access-control-${name}`,
      detector: "missing_access_control",
      severity: exact ? "Critical" : "High",
      title: `Sensitive function \`${name}\` appears to lack access control`,
      line: lineNo(source, match.index),
      evidence: snippet(source, match.index),
      recommendation: `Restrict \`${name}\` with onlyOwner / AccessControl, or an explicit msg.sender check.`,
    });
  }
  return findings;
}

function detectReentrancy(source: string): Finding[] {
  const findings: Finding[] = [];
  const callPat = /\.call\s*\{[^}]*value\s*:/gi;
  let match: RegExpExecArray | null;
  while ((match = callPat.exec(source))) {
    let after = source.slice(match.index + match[0].length, match.index + match[0].length + 500);
    const nextFn = /\bfunction\s+\w+\s*\(/.exec(after);
    if (nextFn) after = after.slice(0, nextFn.index);
    if (
      /balances\s*\[[^\]]+\]\s*=/.test(after) ||
      /\w+\s*\[[^\]]+\]\s*=\s*0/.test(after)
    ) {
      findings.push({
        id: "reentrancy-cei",
        detector: "reentrancy",
        severity: "Critical",
        title: "External call before state update (reentrancy heuristic)",
        line: lineNo(source, match.index),
        evidence: snippet(source, match.index),
        recommendation:
          "Follow checks-effects-interactions: update state before external calls, or use a reentrancy guard.",
      });
    }
  }
  return findings;
}

function detectSwapNoSlippage(source: string): Finding[] {
  const findings: Finding[] = [];
  const pattern = /function\s+swap\s*\(([^)]*)\)\s*(external|public)/gi;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(source))) {
    const params = match[1] ?? "";
    if (/\bminOut\b|\bamountOutMin\b|\bminAmountOut\b/i.test(params)) continue;
    findings.push({
      id: "swap-no-slippage",
      detector: "swap_slippage",
      severity: "High",
      title: "Swap function lacks slippage protection parameter",
      line: lineNo(source, match.index),
      evidence: snippet(source, match.index),
      recommendation:
        "Add a minOut / amountOutMin parameter and revert when output is below the bound.",
    });
  }
  return findings;
}

function detectUnsafeErc20(source: string): Finding[] {
  const findings: Finding[] = [];
  const approveRe = /\.approve\s*\([^;]*type\s*\(\s*uint256\s*\)\s*\.\s*max/g;
  let match: RegExpExecArray | null;
  while ((match = approveRe.exec(source))) {
    findings.push({
      id: "infinite-approve",
      detector: "unsafe_erc20",
      severity: "Medium",
      title: "Unlimited ERC-20 approval (type(uint256).max)",
      line: lineNo(source, match.index),
      evidence: snippet(source, match.index),
      recommendation:
        "Approve only the required amount, or use permit / allowance management carefully.",
    });
  }
  const transferRe = /\b(\w+)\.(transfer|transferFrom)\s*\(/g;
  while ((match = transferRe.exec(source))) {
    const line = snippet(source, match.index);
    const stripped = line.trimStart();
    if (stripped.startsWith("require")) continue;
    if (line.includes("function transfer") || line.includes("function transferFrom")) {
      continue;
    }
    const kind = match[2];
    const ln = lineNo(source, match.index);
    findings.push({
      id: `unchecked-erc20-${kind}-${ln}`,
      detector: "unsafe_erc20",
      severity: "Medium",
      title: `ERC-20 \`${kind}\` return value may be ignored`,
      line: ln,
      evidence: line,
      recommendation:
        "Check boolean return values (or use SafeERC20) for non-standard tokens.",
    });
  }
  return findings;
}

function detectDelegatecall(source: string): Finding[] {
  const findings: Finding[] = [];
  const re = /\.delegatecall\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(source))) {
    const evidence = snippet(source, match.index);
    if (evidence.trimStart().startsWith("//")) continue;
    const header = enclosingFunction(source, match.index);
    const guarded = isGuarded(source, header);
    const ln = lineNo(source, match.index);
    findings.push({
      id: `delegatecall-${ln}`,
      detector: "delegatecall",
      severity: guarded ? "High" : "Critical",
      title:
        "`delegatecall` runs external code against this contract's storage" +
        (guarded ? "" : " from an unrestricted function"),
      line: ln,
      evidence,
      recommendation:
        "Restrict the target to a trusted immutable address and gate the caller; never delegatecall an address supplied by the caller.",
    });
  }
  return findings;
}

function detectUnprotectedSelfdestruct(source: string): Finding[] {
  const findings: Finding[] = [];
  const re = /\bselfdestruct\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(source))) {
    const evidence = snippet(source, match.index);
    if (evidence.trimStart().startsWith("//")) continue;
    if (isGuarded(source, enclosingFunction(source, match.index))) continue;
    const ln = lineNo(source, match.index);
    findings.push({
      id: `unprotected-selfdestruct-${ln}`,
      detector: "unprotected_selfdestruct",
      severity: "Critical",
      title: "`selfdestruct` reachable from an unrestricted function",
      line: ln,
      evidence,
      recommendation: "Gate self-destruction behind an owner/role check, or remove it.",
    });
  }
  return findings;
}

function detectWeakRandomness(source: string): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<number>();
  const runs: Array<{ re: RegExp; needsHint: boolean }> = [
    { re: new RegExp(MANIPULABLE_RANDOM_RE.source, "g"), needsHint: false },
    { re: new RegExp(WEAK_RANDOM_RE.source, "g"), needsHint: true },
  ];
  for (const { re, needsHint } of runs) {
    let match: RegExpExecArray | null;
    while ((match = re.exec(source))) {
      const ln = lineNo(source, match.index);
      if (seen.has(ln)) continue;
      const evidence = snippet(source, match.index);
      if (evidence.trimStart().startsWith("//")) continue;
      if (needsHint && !RANDOM_HINT_RE.test(evidence)) continue;
      seen.add(ln);
      findings.push({
        id: `weak-randomness-${ln}`,
        detector: "weak_randomness",
        severity: "High",
        title: "Randomness derived from block data is manipulable",
        line: ln,
        evidence,
        recommendation:
          "Block values are influenced by validators and visible to callers; use a commit-reveal scheme or a VRF oracle instead.",
      });
    }
  }
  return findings;
}

const DETECTORS = [
  detectMissingAccessControl,
  detectReentrancy,
  detectSwapNoSlippage,
  detectUnsafeErc20,
  detectTxOrigin,
  detectDelegatecall,
  detectUnprotectedSelfdestruct,
  detectWeakRandomness,
];

export const DETECTOR_COUNT = DETECTORS.length;

const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Info: 3,
};

export function runDetectors(source: string): Finding[] {
  const findings = DETECTORS.flatMap((d) => d(source));
  findings.sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
      (a.line ?? 1e9) - (b.line ?? 1e9) ||
      a.id.localeCompare(b.id),
  );
  return findings;
}
