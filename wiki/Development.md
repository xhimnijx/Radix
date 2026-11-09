# Development

## Tests

```powershell
python -m pytest -q -m "not slow"                       # 411 passed, ~75 s
python -m pytest -q tests/test_testnet_end_to_end.py    # real proofs, ~6 min
cd proof_rust && cargo test                             # 69 passed
```

## The cross-language check

The strongest test in the project:

```powershell
cd proof_rust && cargo test --test python_proof   # Python proof -> Rust verifier
python experiments/verify_rust_proof.py           # Rust proof -> Python verifier
```

## Layout

| Path | What |
|---|---|
| `vault/` | Documentation, A-Level upwards |
| `radix_core/candidate_b/lattice/` | Python reference |
| `radix_testnet/` | The app |
| `proof_rust/` | Rust port; `PORTING.md` records the layer table and the bugs |
| `experiments/` | Measurements, cross-checks, modulus search |

## Rules that are actually enforced

- A new protocol function needs a test with a value **from the other implementation**,
  not only a property test.
- Fixing a reviewer's finding means adding the regression test in the same commit and
  recording it in `REVIEW-FINDINGS.md`.
- Nothing may hide a known defect: weakening a test is rejected.

## Reporting a vulnerability

See `SECURITY.md`. Do not open a public issue.
