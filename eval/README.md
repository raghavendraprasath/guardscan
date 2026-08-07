# GuardScan Labeled Evaluation Suite

Small, hand-labeled contract set used to measure GuardScan detector quality for the
INFO7500 final delivery. This is an **educational evaluation**, not a published
benchmark.

## What is labeled

Each case in `labels.json` lists the **detectors that should fire** on that file
(`expected_detectors`). Metrics are computed at the `(file, detector)` level:

| Symbol | Meaning |
|---|---|
| **TP** | Expected detector fired |
| **FP** | Unexpected detector fired |
| **FN** | Expected detector did not fire |
| **Known FN** | A real planted bug that GuardScan is documented *not* to catch |

True-negative cases (`GoodGuardedAdmin.sol`, `SaferAMM.sol`) expect an empty detector set.
Any finding on those files is a false positive.

## Run

From the repository root:

```bash
python eval/run_eval.py
python eval/run_eval.py --json
python eval/run_eval.py --fail-on-mismatch   # useful in CI / before a demo
```

## Cases

| ID | Role | Expected detectors |
|---|---|---|
| `bad-reentrancy` | true positive | `reentrancy` |
| `bad-access-control` | true positive | `missing_access_control` |
| `bad-tx-origin` | true positive | `tx_origin`, `missing_access_control` |
| `bad-swap-no-slippage` | true positive | `swap_slippage`, `unsafe_erc20` |
| `bad-unsafe-erc20` | true positive | `unsafe_erc20` |
| `bad-delegatecall` | true positive | `delegatecall` |
| `bad-selfdestruct` | true positive | `unprotected_selfdestruct` |
| `bad-weak-randomness` | true positive | `weak_randomness` |
| `good-guarded-admin` | true negative | _(none)_ |
| `fixture-safer-amm` | true negative | _(none)_ |
| `fixture-vulnerable-vault` | true positive | `missing_access_control`, `reentrancy`, `tx_origin` |
| `fixture-vulnerable-amm` | true positive | `missing_access_control`, `swap_slippage`, `unsafe_erc20` |
| `known-miss-odd-name` | known false negative | planted `missing_access_control` under `configureParameters` — intentionally undetected |

## How to read the numbers

- **Precision** answers: of the detectors that fired, how many were supposed to?
- **Recall** answers: of the detectors that were supposed to fire, how many did?
- **Known false negatives** are reported separately so the suite stays honest about
  name-sensitive access-control gaps without punishing the score for a documented limit.

A perfect score on this suite means GuardScan matches its own labels. It does **not**
mean the tool is production-ready or that unscanned bug classes are absent.
