# GuardScan

**AI-Assisted Smart Contract Vulnerability Scanner**

GuardScan pairs deterministic Solidity detectors with grounded LLM explanations to detect, rank, explain, and suggest fixes for smart-contract security issues — without free-form hallucination.

| Field | Detail |
|---|---|
| **Author** | Raghavendra Prasath Sridhar |
| **Course** | INFO7500 — Cryptocurrency and Smart Contracts (Summer 2026) |
| **Area** | Blockchain Security |
| **Status** | **Final delivery (Aug 2026)** — usable GuardScan system: 8 detectors, Next.js web UI (Vercel), Python CLI + eval suite (P=1.0 / R=1.0), grounded AI explanations, honest limitations |
| **Repository** | [github.com/raghavendraprasath/guardscan](https://github.com/raghavendraprasath/guardscan) |

---

## 1. Summary

This repository is the home of **GuardScan**, an AI-assisted smart contract vulnerability scanner. The system combines:

1. **Deterministic detectors** that produce structured, evidence-backed findings from Solidity source
2. **A grounded LLM explanation layer** that ranks severity, explains risk in plain English, and suggests fixes — constrained to detector evidence only

GuardScan targets the practical gap between noisy expert static-analysis output and untrusted free-form “AI audit chatbots.” The initial scope focuses on patterns relevant to AMM / ERC-20 style contracts, building on prior coursework (`SimpleAMM` and LLM Text-to-SQL tooling).

---

## 2. Background: Key Concepts for Beginners

This section defines the main terms used in the proposal so readers new to blockchain security can follow along.

| Term | Plain-English meaning |
|---|---|
| **Blockchain** | A shared, append-only ledger. Once data is confirmed, it is very hard to change, which is why deployed bugs are costly. |
| **Smart contract** | A program stored on a blockchain (commonly Ethereum) that automatically enforces rules for money, tokens, or other on-chain state. |
| **Solidity** | The most common programming language for writing Ethereum smart contracts. GuardScan scans Solidity source files. |
| **EVM** | The Ethereum Virtual Machine — the runtime that executes smart-contract bytecode on Ethereum-compatible chains. |
| **Transaction** | A signed action that calls a contract or moves value. Failed security assumptions here can move real funds. |
| **Token / ERC-20** | A common standard for fungible tokens (coin-like balances) on Ethereum. Many DeFi apps move ERC-20 tokens. |
| **AMM (Automated Market Maker)** | A smart-contract style exchange that prices trades from a liquidity pool formula instead of an order book (for example, Uniswap-style pools). |
| **Liquidity pool** | Token reserves locked in a contract so users can swap one asset for another. |
| **Immutability** | After deployment, contract code usually cannot be patched like a normal web app. Fixes often require a new deployment and migration. |
| **Vulnerability / exploit** | A weakness an attacker can use to steal funds, freeze assets, or take unauthorized control. |
| **Reentrancy** | A bug pattern where an external call lets an attacker re-enter a function before state is updated, often draining funds. |
| **Access control** | Rules for who may call sensitive functions (for example, only an owner may change critical settings). |
| **`tx.origin` vs `msg.sender`** | `msg.sender` is the immediate caller; `tx.origin` is the original externally owned account. Using `tx.origin` for authorization is a known anti-pattern. |
| **Slippage / `minOut`** | In a swap, price can move before the trade settles. A minimum-output (`minOut`) check protects users from getting far less than expected. |
| **Static analysis** | Checking source code with rules/heuristics without executing a full live attack. Tools like Slither do this; GuardScan’s detectors are a small educational version of that idea. |
| **Detector** | A deterministic check that flags a specific pattern and returns structured evidence (file/line/snippet). In GuardScan, detectors are the source of truth. |
| **LLM (Large Language Model)** | An AI model that can explain text/code in natural language. Useful for readability, but unsafe if allowed to invent vulnerabilities freely. |
| **Grounded explanation** | An LLM response constrained to evidence already produced by detectors — explain and suggest fixes, do not invent new findings. |
| **Severity** | A priority label for findings (for example Critical / High / Medium / Info) so developers fix the riskiest issues first. |
| **Audit** | A security review of a contract. GuardScan is not a replacement for a professional audit; it is a developer feedback tool. |

**How these pieces fit GuardScan:** Solidity smart contracts (often AMM / ERC-20 related) can contain high-impact bugs. Deterministic detectors find candidate issues; a grounded LLM explains them in plain English so beginners and busy developers can act on the results more quickly.

---

## 3. Problem Statement

Smart contracts are immutable after deployment. Bugs such as reentrancy, missing access control, unsafe external calls, and broken automated market maker (AMM) invariants can cause irreversible loss of funds.

Manual audits remain valuable, but they are slow, expensive, and difficult to run continuously during development. Existing tooling leaves a usability and trust gap:

1. **Static analyzers** (for example, Slither) produce useful technical findings, but output can be noisy and hard for less experienced developers to interpret quickly.
2. **Pure LLM auditors** can sound confident while inventing vulnerabilities that are not present in the code.
3. Developers need a **fast, usable feedback loop**: paste or upload Solidity → structured findings → severity ranking → plain-English explanation and suggested fix, with evidence grounding.

---

## 4. Why This Problem Matters

1. **Real economic impact.** DeFi and token contracts secure substantial value. Historical exploits show that small coding mistakes can become catastrophic losses.
2. **Applied security skill.** Turning Solidity, AMM, and EVM security concepts into a working tool demonstrates applied mastery beyond conceptual understanding.
3. **Trustworthy AI for risk workflows.** AI is increasingly used in risk, compliance, and security contexts. The hard engineering problem is trustworthiness: reduce hallucination, cite evidence, and rank severity.
4. **Portfolio relevance.** The project extends experience in Python, LLMs, evaluation/guardrails, and risk-oriented systems into blockchain security tooling — a strong intersection for AI engineering, fintech, and security-adjacent roles.

---

## 5. Related Work

### 5.1 Academic papers and research lines

- **Oyente** — early symbolic execution research for Ethereum smart contracts
- **Securify** — semantic / compliance-pattern analysis approaches for Solidity
- **GPTScan (ICSE 2024)** and related LLM-for-vulnerability detection research — combine LLMs with program analysis and document false-positive / hallucination challenges
- **Vulnerability taxonomies and guidance:** SWC Registry, DASP Top 10, Consensys Smart Contract Best Practices

### 5.2 Open-source and industry systems

- **Slither (Trail of Bits)** — widely used static analysis with practical detectors
- **Mythril** — symbolic-execution-oriented analysis
- **Solhint / Aderyn** — linting and AST-oriented checking
- **OpenZeppelin Contracts** — secure building blocks that reduce common implementation risk
- **Professional audit report corpora** — qualitative reference for how findings are written, ranked, and explained

### 5.3 Gap this project targets

Most mature tools optimize for expert auditors. GuardScan optimizes for a **developer-facing loop**: structured detection first, then LLM explanation constrained to that evidence. The novelty is not “replace Slither,” but **usable, grounded explanation and prioritization** for educational and early-development workflows, with AMM-relevant checks tied to real contracts.

---

## 6. Proposed Solution

### 6.1 Product concept

**GuardScan** is a minimal AI-assisted Solidity vulnerability scanner. Initial scope focuses on patterns relevant to AMM / ERC-20 style contracts, using a SimpleAMM implementation and intentionally vulnerable variants as primary targets.

### 6.2 System architecture

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

### 6.3 Core capabilities

1. Accept Solidity file(s) or pasted source
2. Run a focused detector set (currently 8 rules):
   - missing access control on sensitive functions (exact names at `Critical`, name heuristics at `High`)
   - external call before state update (reentrancy heuristic)
   - swap without slippage protection (`minOut` or equivalent)
   - unsafe ERC-20 transfer / allowance patterns (simplified)
   - `tx.origin` authentication anti-pattern
   - `delegatecall` into caller-influenced targets
   - `selfdestruct` reachable without an authorization check
   - randomness derived from manipulable block data
3. Emit severity-ranked findings: `Critical` / `High` / `Medium` / `Info`
4. Use an LLM only to explain findings and propose fixes, following a guardrail philosophy similar to constrained Text-to-SQL systems (structured constraints; refuse unsupported claims)

### 6.4 Explicit mocks (scope control for the ≤5-hour prototype)

| Component | MVP treatment |
|---|---|
| Full formal verification / symbolic execution | Mocked via heuristics + fixture contracts |
| On-chain bytecode-only scanning | Out of scope (source-first) |
| Broad multi-chain support | Solidity local files only |
| Complete production Slither integration | Optional; may stub JSON findings |

### 6.5 Reuse from prior coursework

| Prior work | Reuse in GuardScan |
|---|---|
| [SimpleAMM](https://github.com/raghavendraprasath/automated-market-maker) (Solidity, Hardhat, tests/coverage) | Primary scan target + vulnerable variants |
| [Block Explorer AI / Text-to-SQL](https://github.com/raghavendraprasath/ai-generated-block-explorer) (OpenRouter, prompt constraints, Streamlit) | Prompt design, API wiring, UI/CLI delivery |
| Course security topics (reentrancy, access control) | Detector categories and evaluation fixtures |

---

## 7. Minimal Working Example (Maximum 5 Hours)

### 7.1 Objective

Demonstrate an end-to-end working path quickly, even if analysis depth is intentionally shallow.

### 7.2 Five-hour build plan

| Hour | Deliverable |
|---|---|
| 1 | Create 2–3 fixture contracts (safe-ish AMM snippet, reentrancy toy, missing owner check) |
| 2 | Build Python CLI with 3–5 detectors producing JSON findings |
| 3 | Implement OpenRouter prompt: explain only provided findings; do not invent new vulnerabilities |
| 4 | Add minimal Streamlit or HTML UI: paste code → render report |
| 5 | Write usage docs, capture screenshots, prepare one scripted demo run |

### 7.3 Prototype success criteria

1. Paste code and receive a report in approximately 30 seconds
2. Detect at least one true positive on a known-bad fixture
3. Ensure LLM narrative cites detector evidence rather than performing an unconstrained “full audit”

---

## 8. Weekly Plan

| Milestone | Target | Deliverable |
|---|---|---|
| **Proposal** | Week of Jul 24 | This repository README / proposal URL |
| **Progress update** | Jul 31 | 5–10 minute progress presentation: expanded detectors, finding schema, false-positive notes, live scan demo |
| **Parallel coursework** | Jul 31 | SimpleAMM Web3 UI (separate assignment); AMM remains GuardScan’s primary scan target |
| **Final delivery** | Aug 7 | Usable GuardScan system: CLI/UI, detector set, small labeled evaluation suite, README with limitations & related work, final presentation |

### Delivered as of Jul 31 (progress update)

| Proposal commitment | Status |
|---|---|
| Expand detectors | 5 → 8: added `delegatecall`, unprotected `selfdestruct`, block-derived randomness |
| Harden finding schema | Explanations carry `explanation_mode` (`ai` / `template` / `none`) plus `template_reason`, so the provenance of every sentence is machine-readable |
| Document false-positive notes | Access control widened from 9 hardcoded names to name prefixes, reported at `High` instead of `Critical` to reflect weaker evidence; `onlyX` modifiers, inline `msg.sender` checks, and `view`/`pure` functions suppressed as guards |
| Live scan demo | CLI and Streamlit both run end-to-end; explanations degrade to template text on rate limit or network loss instead of failing |
| Regression coverage | 6 tests, including a control asserting a well-guarded contract yields zero findings |

### Delivered as of Aug 7 (final delivery)

| Proposal / DoD commitment | Status |
|---|---|
| Usable CLI + UI | Python `cli.py` + Next.js `web/` (Vercel) with AI toggle and automatic template fallback; Streamlit kept as optional legacy |
| Focused detector set | 8 deterministic detectors covering access control, reentrancy, slippage, unsafe ERC-20, `tx.origin`, `delegatecall`, unprotected `selfdestruct`, weak randomness |
| Grounded LLM explanations | OpenRouter (free-tier model); detectors remain source of truth; model cannot invent findings |
| Small labeled evaluation suite | `eval/` — 13 labeled cases, detector-level precision / recall / F1, one documented known false negative |
| Related work + limitations | README §§5 and 11.6; `fixtures/README.md` maps planted bugs to public references |
| Final presentation | Local outline + timed script PDFs for class (kept outside the repo) |
| Optional: Slither JSON ingest | Explicitly deferred — heuristics kept as the mock for heavy analysis (proposal §6.4) |

### Intended weekly accomplishments

1. **Proposal week:** Publish proposal; complete ≤5-hour mocked MVP; demo fixtures → findings → grounded LLM explanation
2. **Through Jul 31:** Expand detectors; harden finding schema; document false-positive notes; live-scan SimpleAMM and vulnerable variants
3. **Through Aug 7:** Polish CLI/UI; assemble a small labeled evaluation set (good/bad contracts); optionally ingest Slither JSON; finalize presentation materials

---

## 9. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| LLM hallucinated vulnerabilities | Detectors are the source of truth; LLM explains only listed findings |
| Scope creep into a full audit platform | Cap detector count; mock heavy analysis components |
| Workload collision with Web3 UI homework | Keep final project on Python/LLM track; isolate Web3 UI as a separate deliverable |
| Limited novelty versus existing tools | Emphasize grounded explanation UX, AMM-focused checks, and honest evaluation |

---

## 10. Definition of Done

A usable local or web-accessible system that:

1. Scans Solidity source for a focused vulnerability set — **done** (8 detectors)
2. Returns severity-ranked, human-readable reports via a grounded LLM — **done**
3. Demonstrates clear results on AMM-style contracts — **done** (`VulnerableAMM` / `SaferAMM`)
4. Documents related work, limitations, and future work honestly — **done**
5. Supports weekly progress updates and a final presentation — **done**
6. Includes a small labeled evaluation suite with measurable precision/recall — **done** (`eval/`)

---

## 11. Prototype Usage (≤5-Hour MVP)

### 11.1 Layout

```text
guardscan/
  README.md                 # proposal + final delivery + usage
  web/                      # Next.js UI (Vercel deploy target)
  fixtures/                 # vulnerable + safer Solidity demo samples
  eval/                     # labeled evaluation suite + metrics runner
  src/                      # Python detectors, finding schema, LLM explainer, scanner
  ui/app.py                 # Optional Streamlit surface (legacy)
  tests/                    # detector + eval-suite tests
  cli.py                    # JSON CLI entrypoint
  requirements.txt
  .env.example
```

### 11.2 Setup

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

### 11.3 CLI scan (JSON)

```bash
# Detectors + AI explanation (needs OPENROUTER_API_KEY)
python cli.py fixtures/VulnerableVault.sol --pretty

# Detectors + template explanation, no model call
python cli.py fixtures/VulnerableVault.sol --pretty --no-ai

# Detectors only
python cli.py fixtures/VulnerableAMM.sol --no-explain --pretty

# Safer contrast fixture
python cli.py fixtures/SaferAMM.sol --pretty --no-ai
```

Each report carries an `explanation.explanation_mode` of `ai`, `template`, or `none`, so the
provenance of every explanation is explicit in the JSON. When the mode is `template`,
`explanation.template_reason` records why the model was not used.

### 11.4 Web UI (Next.js — primary)

```bash
cd web
copy .env.example .env.local   # or: cp .env.example .env.local
# set OPENROUTER_API_KEY in .env.local for live AI explanations
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). Detectors run in the browser (instant /
offline). AI explanations call `/api/scan` on the server so the API key never ships to the client.

Stack: Next.js App Router, React 19, TypeScript, Tailwind CSS v4, Geist fonts, Recharts.

### 11.5 Streamlit UI (optional / legacy)

```bash
streamlit run ui/app.py
```

Still available for local demos. The polished public surface is the Next.js app above.

### 11.6 Tests

```bash
pytest -q
```

### 11.7 Labeled evaluation suite

```bash
python eval/run_eval.py
python eval/run_eval.py --fail-on-mismatch
```

The suite in `eval/` contains 13 hand-labeled cases (true positives, true negatives, and one
documented known false negative). Metrics are detector-level precision, recall, and F1.
See [`eval/README.md`](eval/README.md) for the case table and how to interpret the numbers.

Latest measured result on this suite: **precision 1.0 / recall 1.0 / F1 1.0**, with **1 known
false negative** (`configureParameters` ownership change — outside name heuristics).

### 11.8 Deploy on Vercel

The Next.js app in `web/` is the Vercel deployment target.

1. Push this repository to GitHub
2. Import the repo at [vercel.com/new](https://vercel.com/new)
3. Set **Root Directory** to `web`
4. Add environment variables:
   - `OPENROUTER_API_KEY` = your OpenRouter key
   - `OPENROUTER_MODEL` = `nvidia/nemotron-3-super-120b-a12b:free` (optional)
5. Deploy

Public URL will look like `https://guardscan-….vercel.app`.

Detectors always work without a key. Without `OPENROUTER_API_KEY`, AI explanations fall back to
template text.

CLI alternative:

```bash
cd web
npx vercel
npx vercel --prod
```

### 11.9 Prototype limitations (intentional)

- Heuristic detectors (not full Slither / symbolic execution)
- Source-first only (no bytecode-only scanning)
- LLM must explain listed findings only; it does not invent new issues
- Fixtures are educational demos — do not deploy them
- **Zero findings is not a safety claim.** GuardScan only reports the 8 patterns above.
  Bug classes it has no detector for (integer-overflow edge cases, signature replay,
  oracle manipulation, gas griefing, upgrade-storage collisions, and many more) are
  never examined, so a clean report means "none of these 8 patterns matched" and
  nothing stronger. Detectors are also name- and shape-sensitive: an unguarded setter
  called something unlike the patterns above can be missed (measured in `eval/` as a
  known false negative).

### 11.10 Future work

- Expand the labeled set beyond educational fixtures toward public vulnerability corpora
- Optional Slither JSON ingest as a second detector backend (mocked in the MVP)
- Richer severity ranking that combines detector confidence with LLM-assisted prioritization
  (still grounded — no new findings)
- Bytecode / compiled-artifact scanning for contracts without source

---

## 12. Related Repositories

- [automated-market-maker](https://github.com/raghavendraprasath/automated-market-maker) — SimpleAMM smart contract (scan target)
- [ai-generated-block-explorer](https://github.com/raghavendraprasath/ai-generated-block-explorer) — Bitcoin Text-to-SQL / LLM tooling patterns reused here

---

## License

MIT License. See [LICENSE](LICENSE).
