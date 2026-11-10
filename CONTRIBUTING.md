# Contributing

## The most useful contribution is a review

This project is a research prototype whose weakest point is **unpriced parameters**, not
missing features. If you are a cryptographer, the highest-value hour you can spend is:

1. Run a lattice estimator against the current parameters and tell us the security
   level. Inputs are ready in `vault/Parameter Sheet.md`: `q = 4,294,966,337`,
   `d = 128`, `ℓ = 13`, `k = 4`, `κ = 10`, `λ = 10`, `μ = 5`, `β = 2^17.9`,
   `β′ = 2^16.6`.
2. Answer the questions in [`REVIEW-REQUEST.md`](REVIEW-REQUEST.md).
3. Look for the things two previous reviewers missed. They found four real defects; a
   fifth would be welcome.

## If you are writing code

- **Python:** `python -m pytest -q -m "not slow"` must stay green (603 tests, ~11 min).
- **Rust:** `cargo test` in `proof_rust/` must stay green (70 tests).
- **Cross-language:** if you touch the protocol, the Python proof → Rust verifier and
  Rust proof → Python verifier checks must still pass.
- **No new dependencies** without a reason in the pull request; the project runs
  offline-apart-from-PyPI by design.

### Style

- Comments say *why*, not *what*. A comment that restates the code is noise; a comment
  that explains a non-obvious constraint is worth reading.
- Every new protocol function needs a test with a **value from the other
  implementation**, not only a property test.
- If you fix a bug that a reviewer found, add the regression test in the same commit and
  record it in `REVIEW-FINDINGS.md`.

### What will be rejected

- Anything that adds a security claim without an estimator run or an audit.
- Anything that hides a known defect: weakening a test, deleting a failing case, or
  quietly changing a documented limitation.
- Anything that presents this as a currency.

## Where things live

| Path | What |
|---|---|
| `vault/` | Documentation, A-Level upwards |
| `radix_core/candidate_b/lattice/` | Reference implementation |
| `radix_testnet/` | The app |
| `proof_rust/` | The Rust port and its porting record |
| `experiments/` | Measurements and cross-checks |

## Reporting a security issue

See [`SECURITY.md`](SECURITY.md). Do not open a public issue for a vulnerability.

## Licence

By contributing you agree that your contribution is licensed under the MIT licence in
[`LICENSE`](LICENSE).
