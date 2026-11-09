---
title: The Rust Port
tags: [engineering, rust]
---

# The Rust port

`proof_rust/`. A second implementation of the whole prover and verifier, written to make
the system fast and to check the first implementation.

## Modules

| Module | Mirrors | What it adds |
|---|---|---|
| `sha3.rs` | `hashlib.shake_256` | Keccak-f1600 + SHAKE256, no crates |
| `transcript.rs` | `transcript.py` | Same framing, byte-identical output |
| `codec.rs` | `ring.encode`, `Proof.encode` | Adds a decoder the Python had nowhere |
| `sample.rs` | — | The shared generator that lets both sides build identical fixtures |
| `bdlop.rs` | `bdlop.py` | — |
| `tensor.rs` | `tensor.py` | — |
| `quadratic.rs` | `quadratic.py` | — |
| `recursion.rs` | `recursion.py` | — |
| `statement.rs` | `setmembership.Keys/Statement` | `draw`, `draw_ternary`, `head`, `masking_width` |
| `proof.rs` | setmembership helpers | `paper_to_slot`, `e1`, `b_transpose`, `set_matrix`, `final_x` |
| `verifier.rs` | `setmembership.verify` | Plus `verify_traced` for debugging |
| `prover.rs` | `setmembership._prove_once` | Own RNG, rejection sampling |

Everything in `lib.rs` at the root: `R_q` arithmetic, slots, CRT, norms.

## Design choices that are not translations

- **Own RNG (xoshiro256++).** Python uses Mersenne Twister. Proofs therefore differ
  byte-for-byte, which is *fine*: proofs are checked mathematically. If reproducible
  proofs were ever needed, the RNG would have to be specified rather than implemented.
- **`verify_traced`.** Records the name of each stage; the last name is where it
  stopped. Twenty lines that turned blind debugging into one run.
- **Errors are `Result`, not panics.** A malformed proof is rejected, never a crash —
  the input is attacker-controlled.

## Binaries

| Binary | Purpose |
|---|---|
| `bench` | Ring multiplication benchmark |
| `prove_bench` | The dominant prover work, measured |
| `bench_proof` | End-to-end prove/verify timing |
| `emit_proof` | Writes a Rust proof fixture for Python to check |
| `prove_request` | **The seam**: request file in, proof file out |

## Tests

70 tests: 13 module groups plus two integration tests (`python_proof.rs`,
`round_trip.rs`). [[Test Inventory]] has the table.

## What is not ported

- Keygen (the seam receives the secret).
- The tag itself (computed in Python; a tag is four extra matrix rows).
- Aggregation (Fig. 5).
- The verifier inside the node — the seam is shaped for it but not pointed at it yet.

## Next

[[How the Port Was Verified]] for the evidence, [[Performance Measurements]] for the
numbers, [[The Rust Backend Seam]] for the integration.
