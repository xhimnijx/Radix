# Status — 2026-11-08

**One line:** the tree builds, the suite is green, the verified safety defects are
fixed, and the mainnet launch gate exists and ships **closed**. The proof side is
still a component prototype: no complete transaction proof exists, and the
flagship RDXL profile is fail-closed by design.

## Verify it

```powershell
python -m pytest -q                                  # 219 passed
python Radix-Serialization-Test-Vectors.py           # passes
python Radix-Gate-1-Reference-Model.py               # passes
python -m examples.wallet_note_demo                  # real ML-KEM/AES round trip
python -m examples.launch_gate_check                 # prints why mainnet is locked

cd proof_harness
cargo +stable-x86_64-pc-windows-gnu check --locked --tests   # exit 0
```

**Local toolchain caveat.** This machine has no MSVC linker and no MinGW linker,
so Rust *binaries cannot be linked or executed here*. `cargo check` / `cargo check
--tests` type-check the whole crate and are the local gate; CI runs the actual
`cargo test` on Linux. Do not claim a Rust test "passed" on this host unless it
ran in CI.

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
