# Status — 2026-11-08

**One line:** the tree builds, the suite is green, the verified safety defects are
fixed, and the mainnet launch gate exists and ships **closed**. The proof side is
still a component prototype: no complete transaction proof exists, and the
flagship RDXL profile is fail-closed by design.

## Verify it

```powershell
python -m pytest -q                                  # 225 passed
python Radix-Serialization-Test-Vectors.py           # passes
python .\Radix-Gate-1-Reference-Model.py             # passes
python -m examples.wallet_note_demo                  # real ML-KEM/AES round trip
python -m examples.launch_gate_check                 # prints why mainnet is locked
python -m experiments.lean_relation_sizing           # corrected cost model

# Rust: builds and runs locally through the self-contained MinGW set
& .\scripts\rust.ps1 test --locked                   # 46 passed, 7 ignored, 0 failed
& .\scripts\rust.ps1 check --locked --all-targets    # exit 0

# Measured prover peaks (prebuilt 2026-11-01 binary; see MEASUREMENTS.md)
& .\experiments\measure_rust_test.ps1 `
  -Binary "proof_harness\target\release\deps\radix_proof_harness-a6743722e416b94c.exe" `
  -TestName "depth64_path_opening::tests::proves_and_verifies_private_depth64_path"
```

**Toolchain note (2026-11-08).** The Rust suite now runs on this machine. The GNU
toolchain is self-sufficient once `rust-mingw`'s `self-contained` directory is on
PATH (it provides `gcc`, `ld`, `dlltool`, and `rust-lld`). `scripts/rust.ps1`
wraps that. This is a real build and a real test run, not a type-check.

## What is implemented and verified

| Area | State |
|---|---|
| Canonical codecs (`Frame`/`Bytes`/`Vec`, address/output/statement) | implemented, round-trip and mutation tested |
| SHAKE256 Candidate-A hashes | implemented, known-answer vectors |
| ML-KEM-768 + AES-256-GCM adapters (`cryptography==50.0.2`) | real providers, round-trip and negative tests |
| Wallet keygen, note create/recover, bounded and authenticated scan | implemented; scan containment fixed and regression-tested |
| Sparse depth-64 tree, anchors, integer balance, atomic `apply_block` | implemented; **quadratic replay** (see `Radix-Workspace-Review.md` §3.I1) |
| Nonce registries (process-local + SQLite) | implemented; default is now unbounded |
| Pruned-storage arithmetic model | implemented as an unenforced planning model |
| Launch gate (`radix_core/launch.py`) | implemented, 13 tests; **closed by default** |
| Rust component proofs (`RDXZ*`, `RDXT/S/I/J/K`) | type-check clean; proof tests are `#[ignore]`d |
| Rust `RDXL64P1` (full transaction) | **cannot run**: resource preflight fails closed by design |

## Measured / derived numbers after the layout revert

The half-landed key-schedule overlay was reverted to a contiguous 1,920-bit bank
(the split was not consistent and the overlay's column lifetime was unproven).
That costs 1,152 trace columns and makes the fail-closed preflight worse, not
better — recorded honestly rather than hidden:

| Quantity | Value |
|---|---|
| RDXL trace | 8,192 × 15,629 BabyBear values (512,131,072 B) |
| Randomized matrix | 16,384 × 15,633 (1,024,524,288 B) |
| PCS LDE payload | 4,098,097,152 B (3.82 GiB) |
| Randomized + LDE coexistence | 5,122,621,440 B (4.77 GiB) |
| Cross-target process cap used by the guard | 1,073,741,824 B (1 GiB) |
| Best measured input-half profile | `RDXJ64P1`, 9,518 MiB peak working set |
| Component proof sizes | 175,252–327,502 B |

## Decision: the M3 lean-relation experiment (executed 2026-11-08)

`python -m experiments.lean_relation_sizing` and `LEAN-RELATION.md` record a
decision-grade result:

| Profile | Peak @4x (single proof) | Peak @9.5x (planning) | Desktop 4 GiB | Phone 1 GiB |
|---|---:|---:|---|---|
| R-fat (RDXL64P1 today, 14,173 cols) | 27.7 GiB | 65.7 GiB | 16x over | 28x over |
| R-lean (drop in-circuit KDF/AEAD) | 8.5 GiB | 20.1 GiB | 5.0x over | 8.5x over |
| R-lean + packed sibling | 8.0 GiB | 19.0 GiB | 4.8x over | 8.0x over |
| R-lean + packed + algebraic hash (counterfactual) | 5.2 GiB | 12.3 GiB | 3.1x over | 5.2x over |
| RDXZ64P1 path-only floor | 4.9 GiB | 11.7 GiB | 2.9x over | 4.9x over |

All at production blowup (log_blowup=3); at the test blowup of 2 every figure halves.
Measured on this host (`MEASUREMENTS.md`): a single focused path-only proof peaks at
**2.49 GiB / 17.9 s** at blowup 2 (LDE 0.62 GiB, ratio 4.04x); a composed multi-proof
test peaks at **8.61 GiB / 60.0 s** (LDE 0.92 GiB, ratio 9.39x).

- The measured path-only floor fits the desktop gate **only at the test blowup**;
  at production parameters it is already 4.9 GiB.
- Dropping in-circuit KEM/AEAD is justified by the soundness note (Part A of
  `LEAN-RELATION.md`), but it is not sufficient: 8.5 GiB at production.
- **Correction (2026-11-08, after the suite ran):** an earlier version of this table
  claimed packing the path witness would bring the relation to 1.0-2.4 GiB. That was
  wrong on two inputs - the real width is 14,173 (not 15,629) and the path witness is
  1,024 bits (not 8,192), so packing saves 480 columns, not ~7,800. The corrected
  model is above; the conclusion changes from "packing is the lever" to "a single
  monolithic AIR cannot meet the phone budget in any configuration tested".
- Mobile is **not reachable** by this architecture: the phone ceiling is about 1,020
  columns at 4,096 rows, and the smallest relation (path-only) is 5,043.

## Not implemented (unchanged blockers)

- A complete transaction proof, an ML-KEM relation, GCM/GHASH authentication.
- Recipient key privacy (P0), proof of key possession, seed/mnemonic recovery.
- Node, P2P, PoW, mempool, genesis, block wire format, block resource caps.
- Any external cryptographic or consensus review.
- Production FRI parameters in the shipped provers (they use a 2-query test config).

## Skipped checks and re-enable conditions

| Skipped | Reason | Re-enable when |
|---|---|---|
| 7 Rust proof tests (`#[ignore]`) | peak RSS is unbounded and exceeds the provisional device budgets | a profile is measured under a 4 GiB desktop cap |
| `RDXL64P1` proving | preflight returns `ResourceBudgetExceeded` before allocation | the lean-relation experiment (§ M3) produces a fitting profile |

## Launch posture

`MAINNET_SWITCH.is_open == False`. The reasons are machine-readable:

```powershell
python -m examples.launch_gate_check
```

No flag, environment variable, or runtime path opens it. See
`MAINNET-SWITCHOVER.md`.
