# GuardScan Test Fixtures

## Purpose

These Solidity files are **test inputs for the GuardScan scanner**, not deployable software.

Two of them are **intentionally unsafe** so the detectors have known true positives to find. One is a
hardened counterpart used to check that the scanner stays quiet on safer code (a false-positive control).

> **Do not deploy any contract in this folder.** The vulnerable files contain real, exploitable
> patterns and exist purely as scanner targets.

---

## Provenance

- **Original code written for this project** (INFO7500 final project, Summer 2026). Nothing here is
  copied from a production repository, an audit report, or a deployed contract.
- **The bug patterns are canonical and publicly documented** — reproduced deliberately from
  well-known vulnerability classes rather than invented (see mapping below).
- **The AMM structure** is a simplified constant-product swap, mirroring the `SimpleAMM` contract
  from Homework 4 ([automated-market-maker](https://github.com/raghavendraprasath/automated-market-maker)),
  so the scanner targets a contract family already covered in this course.
- **Authoring:** written by the project author with AI assistance (Cursor), then verified by running
  the detector suite and reviewing each finding by hand.
- The toy pricing math is illustrative only and is **not** a correct or safe AMM implementation.

---

## Files

| File | Role | Expected result |
|---|---|---|
| `VulnerableVault.sol` | Unsafe deposit/withdraw vault | 4 findings (3 Critical, 1 High) |
| `VulnerableAMM.sol` | Unsafe AMM-style token swap | 8 findings |
| `SaferAMM.sol` | Hardened version of the same swap | 0 findings |

`SaferAMM.sol` is the important one for evaluation: a scanner that flags everything is unusable, so a
clean run on reasonable code matters as much as catching the bad code.

---

## Bug-to-pattern mapping

| Fixture | Line(s) | Planted issue | Public reference |
|---|---|---|---|
| `VulnerableVault.sol` | 19 | `setOwner` callable by anyone | Missing access control — SWC Registry, DASP Top 10 |
| `VulnerableVault.sol` | 24 | `privilegedWithdraw` guarded only by `tx.origin`, which does not count as valid access control | Missing access control — SWC Registry, DASP Top 10 |
| `VulnerableVault.sol` | 25 | `tx.origin` used for authorization | `tx.origin` auth anti-pattern — SWC Registry |
| `VulnerableVault.sol` | 35–37 | Ether sent before balance zeroed | Reentrancy / checks-effects-interactions — Consensys Smart Contract Best Practices (classic DAO pattern) |
| `VulnerableAMM.sol` | 26 | `setReserves` has no owner check | Missing access control — SWC Registry, DASP Top 10 |
| `VulnerableAMM.sol` | 32 | `swap` accepts no `minOut` bound | Slippage / sandwich exposure — standard DeFi guidance |
| `VulnerableAMM.sol` | 40–48 | ERC-20 return values ignored | Unchecked return values — OpenZeppelin SafeERC20 rationale |
| `VulnerableAMM.sol` | 56–57 | `approve(router, type(uint256).max)` | Unlimited approval anti-pattern |

`SaferAMM.sol` addresses these by adding an `onlyOwner` modifier, requiring a `minOut` bound,
updating reserves before external calls, and wrapping token transfers in `require`.

---

## Reproducing the expected results

```bash
python cli.py fixtures/VulnerableVault.sol --no-explain --pretty
python cli.py fixtures/VulnerableAMM.sol  --no-explain --pretty
python cli.py fixtures/SaferAMM.sol       --no-explain --pretty
```

The same expectations are asserted in `tests/test_detectors.py`, so a regression in any detector
fails the test suite.

---

## Known limitations

The detectors are regex/heuristic checks, so results on these fixtures should be read as a
demonstration, not a security guarantee:

- **False positives** are possible on unusual formatting or naming.
- **False negatives** are likely for bugs hidden behind indirection, inheritance, or libraries.
- A clean GuardScan run means "no *tracked pattern* matched" — never "this contract is safe."
