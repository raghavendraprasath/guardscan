# GuardScan

**AI-Assisted Smart Contract Vulnerability Scanner**

GuardScan pairs deterministic Solidity detectors with grounded LLM explanations to detect, rank, explain, and suggest fixes for smart-contract security issues — without free-form hallucination.

| Field | Detail |
|---|---|
| **Author** | Raghavendra Prasath Sridhar |
| **Course** | INFO7500 — Cryptocurrency and Smart Contracts (Summer 2026) |
| **Area** | Blockchain Security |
| **Status** | Final project proposal + working ≤5-hour MVP prototype |
| **Repository** | [github.com/raghavendraprasath/guardscan](https://github.com/raghavendraprasath/guardscan) |

---

## 1. Executive Summary

This repository is the home of **GuardScan**, an AI-assisted smart contract vulnerability scanner. The system combines:

1. **Deterministic detectors** that produce structured, evidence-backed findings from Solidity source
2. **A grounded LLM explanation layer** that ranks severity, explains risk in plain English, and suggests fixes — constrained to detector evidence only

GuardScan targets the practical gap between noisy expert static-analysis output and untrusted free-form “AI audit chatbots.” The initial scope focuses on patterns relevant to AMM / ERC-20 style contracts, building on prior coursework (`SimpleAMM` and LLM Text-to-SQL tooling).

---

## 2. Problem Statement

Smart contracts are immutable after deployment. Bugs such as reentrancy, missing access control, unsafe external calls, and broken automated market maker (AMM) invariants can cause irreversible loss of funds.

Manual audits remain valuable, but they are slow, expensive, and difficult to run continuously during development. Existing tooling leaves a usability and trust gap:

1. **Static analyzers** (for example, Slither) produce useful technical findings, but output can be noisy and hard for less experienced developers to interpret quickly.
2. **Pure LLM auditors** can sound confident while inventing vulnerabilities that are not present in the code.
3. Developers need a **fast, usable feedback loop**: paste or upload Solidity → structured findings → severity ranking → plain-English explanation and suggested fix, with evidence grounding.

---

## 3. Why This Problem Matters

1. **Real economic impact.** DeFi and token contracts secure substantial value. Historical exploits show that small coding mistakes can become catastrophic losses.
2. **Applied security skill.** Turning Solidity, AMM, and EVM security concepts into a working tool demonstrates applied mastery beyond conceptual understanding.
3. **Trustworthy AI for risk workflows.** AI is increasingly used in risk, compliance, and security contexts. The hard engineering problem is trustworthiness: reduce hallucination, cite evidence, and rank severity.
4. **Portfolio relevance.** The project extends experience in Python, LLMs, evaluation/guardrails, and risk-oriented systems into blockchain security tooling — a strong intersection for AI engineering, fintech, and security-adjacent roles.

---

## 4. Related Work

### 4.1 Academic papers and research lines

- **Oyente** — early symbolic execution research for Ethereum smart contracts
- **Securify** — semantic / compliance-pattern analysis approaches for Solidity
- **GPTScan (ICSE 2024)** and related LLM-for-vulnerability detection research — combine LLMs with program analysis and document false-positive / hallucination challenges
- **Vulnerability taxonomies and guidance:** SWC Registry, DASP Top 10, Consensys Smart Contract Best Practices

### 4.2 Open-source and industry systems

- **Slither (Trail of Bits)** — widely used static analysis with practical detectors
- **Mythril** — symbolic-execution-oriented analysis
- **Solhint / Aderyn** — linting and AST-oriented checking
- **OpenZeppelin Contracts** — secure building blocks that reduce common implementation risk
- **Professional audit report corpora** — qualitative reference for how findings are written, ranked, and explained

### 4.3 Gap this project targets

Most mature tools optimize for expert auditors. GuardScan optimizes for a **developer-facing loop**: structured detection first, then LLM explanation constrained to that evidence. The novelty is not “replace Slither,” but **usable, grounded explanation and prioritization** for educational and early-development workflows, with AMM-relevant checks tied to real contracts.

---

## 5. Proposed Solution

### 5.1 Product concept

**GuardScan** is a minimal AI-assisted Solidity vulnerability scanner. Initial scope focuses on patterns relevant to AMM / ERC-20 style contracts, using a SimpleAMM implementation and intentionally vulnerable variants as primary targets.

### 5.2 System architecture

```text
Solidity source
    |
    |-- Deterministic detectors (heuristics / optional Slither JSON)
    |-- Finding schema (id, severity, lines, evidence)
    `-- LLM explainer (OpenRouter)
            |   explain + suggest fix ONLY for listed findings
            v
     CLI + simple Web UI report
```

### 5.3 Core capabilities

1. Accept Solidity file(s) or pasted source
2. Run a focused detector set (start with 4–6 rules), including:
   - missing access control on sensitive functions
   - external call before state update (reentrancy heuristic)
   - swap without slippage protection (`minOut` or equivalent)
   - unsafe ERC-20 transfer / allowance patterns (simplified)
   - `tx.origin` authentication anti-pattern
3. Emit severity-ranked findings: `Critical` / `High` / `Medium` / `Info`
4. Use an LLM only to explain findings and propose fixes, following a guardrail philosophy similar to constrained Text-to-SQL systems (structured constraints; refuse unsupported claims)

### 5.4 Explicit mocks (scope control for the ≤5-hour prototype)

| Component | MVP treatment |
|---|---|
| Full formal verification / symbolic execution | Mocked via heuristics + fixture contracts |
| On-chain bytecode-only scanning | Out of scope (source-first) |
| Broad multi-chain support | Solidity local files only |
| Complete production Slither integration | Optional; may stub JSON findings |

### 5.5 Reuse from prior coursework

| Prior work | Reuse in GuardScan |
|---|---|
| [SimpleAMM](https://github.com/raghavendraprasath/automated-market-maker) (Solidity, Hardhat, tests/coverage) | Primary scan target + vulnerable variants |
| [Block Explorer AI / Text-to-SQL](https://github.com/raghavendraprasath/ai-generated-block-explorer) (OpenRouter, prompt constraints, Streamlit) | Prompt design, API wiring, UI/CLI delivery |
| Course security topics (reentrancy, access control) | Detector categories and evaluation fixtures |

---

## 6. Minimal Working Example (Maximum 5 Hours)

### 6.1 Objective

Demonstrate an end-to-end working path quickly, even if analysis depth is intentionally shallow.

### 6.2 Five-hour build plan

| Hour | Deliverable |
|---|---|
| 1 | Create 2–3 fixture contracts (safe-ish AMM snippet, reentrancy toy, missing owner check) |
| 2 | Build Python CLI with 3–5 detectors producing JSON findings |
| 3 | Implement OpenRouter prompt: explain only provided findings; do not invent new vulnerabilities |
| 4 | Add minimal Streamlit or HTML UI: paste code → render report |
| 5 | Write usage docs, capture screenshots, prepare one scripted demo run |

### 6.3 Prototype success criteria

1. Paste code and receive a report in approximately 30 seconds
2. Detect at least one true positive on a known-bad fixture
3. Ensure LLM narrative cites detector evidence rather than performing an unconstrained “full audit”

---

## 7. Weekly Plan

| Milestone | Target | Deliverable |
|---|---|---|
| **Proposal** | Week of Jul 24 | This repository README / proposal URL |
| **Progress update** | Jul 31 | 5–10 minute progress presentation: expanded detectors, finding schema, false-positive notes, live scan demo |
| **Parallel coursework** | Jul 31 | SimpleAMM Web3 UI (separate assignment); AMM remains GuardScan’s primary scan target |
| **Final delivery** | Aug 7 | Usable GuardScan system: CLI/UI, detector set, small labeled evaluation suite, README with limitations & related work, final presentation |

### Intended weekly accomplishments

1. **Proposal week:** Publish proposal; complete ≤5-hour mocked MVP; demo fixtures → findings → grounded LLM explanation
2. **Through Jul 31:** Expand detectors; harden finding schema; document false-positive notes; live-scan SimpleAMM and vulnerable variants
3. **Through Aug 7:** Polish CLI/UI; assemble a small labeled evaluation set (good/bad contracts); optionally ingest Slither JSON; finalize presentation materials

---

## 8. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| LLM hallucinated vulnerabilities | Detectors are the source of truth; LLM explains only listed findings |
| Scope creep into a full audit platform | Cap detector count; mock heavy analysis components |
| Workload collision with Web3 UI homework | Keep final project on Python/LLM track; isolate Web3 UI as a separate deliverable |
| Limited novelty versus existing tools | Emphasize grounded explanation UX, AMM-focused checks, and honest evaluation |

---

## 9. Definition of Done

A usable local or web-accessible system that:

1. Scans Solidity source for a focused vulnerability set
2. Returns severity-ranked, human-readable reports via a grounded LLM
3. Demonstrates clear results on AMM-style contracts
4. Documents related work, limitations, and future work honestly
5. Supports weekly progress updates and a final presentation

---

## 10. Prototype Usage (≤5-Hour MVP)

### 10.1 Layout

```text
guardscan/
  README.md                 # proposal + usage (this file)
  fixtures/                 # vulnerable + safer Solidity samples
  src/                      # detectors, finding schema, LLM explainer, scanner
  ui/app.py                 # Streamlit report surface
  tests/                    # detector tests
  cli.py                    # JSON CLI entrypoint
  requirements.txt
  .env.example
```

### 10.2 Setup

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate

pip install -r requirements.txt
copy .env.example .env   # or: cp .env.example .env
# Optional: set OPENROUTER_API_KEY in .env for live grounded explanations
```

### 10.3 CLI scan (JSON)

```bash
# Detectors + mock/live explanation
python cli.py fixtures/VulnerableVault.sol --pretty --mock-llm

# Detectors only
python cli.py fixtures/VulnerableAMM.sol --no-explain --pretty

# Safer contrast fixture
python cli.py fixtures/SaferAMM.sol --pretty --mock-llm
```

### 10.4 Streamlit UI

```bash
streamlit run ui/app.py
```

Paste Solidity or load a fixture, then click **Scan**. Without `OPENROUTER_API_KEY`, explanations run in mock mode (still grounded only to detector findings).

### 10.5 Tests

```bash
pytest -q
```

### 10.6 Prototype limitations (intentional)

- Heuristic detectors (not full Slither / symbolic execution)
- Source-first only (no bytecode-only scanning)
- LLM must explain listed findings only; it does not invent new issues
- Fixtures are educational demos — do not deploy them

---

## 11. Related Repositories

- [automated-market-maker](https://github.com/raghavendraprasath/automated-market-maker) — SimpleAMM smart contract (scan target)
- [ai-generated-block-explorer](https://github.com/raghavendraprasath/ai-generated-block-explorer) — Bitcoin Text-to-SQL / LLM tooling patterns reused here

---

## License

MIT License. See [LICENSE](LICENSE).
