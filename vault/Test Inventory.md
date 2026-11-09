---
title: Test Inventory
tags: [lecturers, evidence, tests]
---

# Test inventory

What is tested, how many tests, and what each group actually establishes.

Counts are from the last full run recorded in this repository. The suite is split by
speed because a real proof costs minutes in CPython, so the fast loop is
`pytest -m "not slow"`.

## Python suite

| Group | Count | What it establishes |
|---|---|---|
| `test_candidate_b_lattice.py` | 18 | Parameter manifest, sizes, the §6 table, modulus criterion (`ord_256 = 4`, no NTT) |
| `test_candidate_b_ntt.py` | 11 | The NTT itself, against direct evaluation, at the split reference modulus |
| `test_candidate_b_subring.py` | 16 | Slots, glue, the CRT idempotents, `glue_crt == glue_ntt` |
| `test_candidate_b_bdlop_vector.py` | 6 | Vector commitments |
| `test_candidate_b_setmembership.py` | 8 | **Real proofs**: prove/verify, tampered proofs rejected, tag paths |
| `test_candidate_b_ring_signature.py` | 6 | Ring signature wrapper, sizes |
| `test_candidate_b_tagged_ring.py` | 6 | The same-witness tag: verifies, deterministic in the secret, tampering rejected |
| `test_candidate_b_tag.py` | 8 | The **withdrawn** construction; one strict `xfail` reproduces the forgery |
| `test_candidate_b_unit_checks.py` | 4 | `_is_unit` in both modulus regimes, including that the residue test is **wrong** in the split regime |
| `test_candidate_b_aggregation.py` | 14 | Fig. 5 aggregation |
| `test_candidate_b_quadratic.py`, `tensor`, `recursion` | ~20 | Coefficient maps, index vectors, the descent |
| `test_candidate_b_spend*.py` | ~10 | Spend construction and verification |
| `test_testnet_chain.py` | 9 | Genesis, submission, mining, tag rejection, balance, anchoring |
| `test_testnet_node.py` | 21 | The HTTP API over a real socket: status, accounts, history, address book, settings, QR, 404/400 paths, a full submit→mine cycle, **state surviving a restart**, auto-miner |
| `test_testnet_end_to_end.py` | 7 | **Real crypto**: a real tagged proof through the node, recipient's note, sender's change, double-spend refusal |
| `test_testnet_rust_backend.py` | 3 | The Rust prover behind the seam, checked by the Python verifier |
| `test_wallet.py`, `test_rules.py`, `test_state.py`, `test_wire.py`, … | ~200 | Candidate-A era codecs, rules and state (archived track) |

Aggregate from the last recorded run: **411 passed, 1 xfailed** for
`pytest -m "not slow"`, and **+~40 slow** including the real proofs.

## Rust suite

| Group | Count | What it establishes |
|---|---|---|
| `lib.rs` arithmetic | 6 | Modulus criterion, roots, slots/glue, CRT multiplication == naive, idempotents |
| `sha3.rs` | 4 | SHAKE256 against `hashlib` on 4 inputs |
| `transcript.rs` | 4 | Two squeezes + ternary challenge match Python |
| `codec.rs` | 5 | Polynomial digest, ternary encoding, truncated input rejected without panic |
| `sample.rs` | 5 | The cross-language generator |
| `bdlop.rs` | 5 | Commitment digest matches Python; homomorphism; binding failure |
| `tensor.rs` | 5 | Flat index 2083 matches |
| `quadratic.rs` | 6 | Coefficient and expected-value digests; the masked-response identity |
| `recursion.rs` | 6 | Pairing digest; shapes; linearity |
| `statement.rs` | 5 | `masking_width`, `draw`, `draw_ternary` |
| `proof.rs` | 7 | `paper_to_slot` (11 positions), `e1`, `b_transpose`, `gamma_elements`, `set_matrix` (128×1024 digest) |
| `verifier.rs` | 5 | Unit checks in the field regime; wrong-sized proof rejected |
| `prover.rs` | 2 | RNG determinism and range; Gaussian centred |
| **integration** `python_proof.rs` | 1 | **Python proof accepted by Rust** |
| **integration** `round_trip.rs` | 3 | Rust proves → Rust verifies; tampered rejected; wire round-trip |

Aggregate: **69 Rust tests**, all passing.

## The tests that matter most

If only three could be kept:

1. `python_proof.rs` — a Python proof is accepted by Rust.
2. `experiments/verify_rust_proof.py` — a Rust proof is accepted by Python.
3. `test_candidate_b_setmembership.py` — real proofs verify and tampered ones do not.

Everything else supports these three.

## Known flake

`test_nonce_multiprocess.py::test_sqlite_nonce_reservation_is_unique_across_processes`
failed once in a full run and passed immediately when re-run in isolation. It is a
multiprocess timing test from the archived Candidate-A track and is unrelated to the
lattice work. Recorded here rather than hidden.

## Android app

No unit tests. `android/` is ~400 lines of UI glue around HTTP calls; the logic worth
testing is in the node, which has 21 HTTP tests. The APK was verified with `aapt`
(manifest, permissions, launchable activity) and `apksigner` (signature) rather than by
trusting the build, and the published release asset matches the local build byte count.
See [[The Android App]].
