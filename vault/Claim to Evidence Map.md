---
title: Claim to Evidence Map
tags: [lecturers, evidence]
---

# Claim to evidence map

Every substantive claim in this project, the evidence for it, and where to look. If a
claim is not in this table, it is not claimed.

## Cryptography

| # | Claim | Evidence | Where |
|---|---|---|---|
| 1 | The Fig. 7–9 prover/verifier implements SMILE ePrint 2021/564 | Line-by-line transcription, reviewed by two independent cryptographers who confirmed the transcription held | `REVIEW-FINDINGS.md`, `setmembership.py` |
| 2 | `R_q` arithmetic is correct | NTT path == quartic-CRT path == naive convolution on random inputs | `ring.py`, `subring.py`, tests |
| 3 | The slot decomposition is correct | `glue_crt(slots(x)) == x`; CRT glue equals the NTT glue at the split modulus | `test_candidate_b_subring.py` |
| 4 | BDLOP commitments are correct | Commitment digest matches across languages (`8ef836b5…`); homomorphism and binding tests | `bdlop.py`, `bdlop.rs` |
| 5 | The quadratic coefficient extraction is correct | Digest `cf184ee9…` matches; property test that `(F(2)−2F(1)+F(0))/2` returns `k` for `F(c)=c²k` | `quadratic.py`, `quadratic.rs` |
| 6 | The recursion is correct | Pairing digest `3a917ee9…`; `set_matrix` digest `7fdce86f…`; `paper_to_slot` pinned for 11 positions | `recursion.py`, `recursion.rs`, `proof.rs` |
| 7 | The transcript is byte-identical across implementations | `draw` and `draw_ternary` match Python; SHAKE256 matches `hashlib` on 4 vectors | `transcript.py`, `transcript.rs`, `sha3.rs` |
| 8 | The prover and verifier are correct | **Both directions**: Python proof accepted by Rust, Rust proof accepted by Python | `tests/python_proof.rs`, `experiments/verify_rust_proof.py` |
| 9 | Ring signatures hide the signer | The verifier never learns `ι`; tested that two spends of one note produce different proofs | `test_candidate_b_tagged_ring.py` |
| 10 | Double spends are detectable | Tag is a deterministic function of the secret; reused tag refused by both mempool and chain | `chain.py`, `test_testnet_chain.py` |

## Engineering

| # | Claim | Evidence | Where |
|---|---|---|---|
| 11 | The system runs end to end | Wallet → node → mempool → block, with a real proof, tested | `tests/test_testnet_end_to_end.py` |
| 12 | The Rust port is faster | Measured: 496 ms prove, 110 ms verify vs Python's 1–2 min / 20–38 s | `PERFORMANCE.md` |
| 13 | The app is packaged and runs | `RadixTestnet.exe` built, launched, API queried, screenshots of all views | `packaging/`, screenshots in the session record |
| 14 | State survives restart | Chain serialised, reloaded, height/UTXO/tags compared | `test_testnet_node.py::test_state_survives_a_restart` |
| 15 | The node rejects malformed input with the right status code | 404/400 tests over a real socket | `test_testnet_node.py` |

## Negative claims (things deliberately *not* claimed)

| # | Not claimed | Why |
|---|---|---|
| N1 | 128-bit security | No estimator run; see [[Status and Honest Limitations]] |
| N2 | The composition is proven | The paper's lemmas are used; the composition is reviewed, not proved |
| N3 | The Gaussian sampler is discrete | It is continuous-then-rounded; `O(1/s)` difference, documented |
| N4 | Verification meets the 100 ms target on a phone | Measured 110 ms on desktop, which is already over |
| N5 | The tag supports arbitrary notes | Tag is per-key; one spend per account without one-time addressing |
| N6 | It is a cryptocurrency | No value, no network, no consensus, no audit |

## How the "both directions" claim was actually established

1. `experiments/produce_python_proof.py` writes a real 32,512-byte Python proof plus
   the honest public key to `proof_rust/tests/fixtures/python_proof.bin`.
2. `proof_rust/tests/python_proof.rs` rebuilds the keys and ring **from the same
   sampling convention** and asserts the Rust verifier accepts it.
3. `proof_rust/src/bin/emit_proof.rs` writes a Rust proof to
   `proof_rust/tests/fixtures/rust_proof.bin`.
4. `experiments/verify_rust_proof.py` rebuilds the same statement and asserts the
   **Python** verifier accepts it, and rejects it under a different message.

Steps 2 and 4 are the evidence. The fixtures are committed, so this can be re-run.

## What a sceptical reader should check first

`tests/python_proof.rs` and `experiments/verify_rust_proof.py`. If those two pass, the
cryptographic claims are as solid as this project can make them without an audit. If
they fail, nothing else matters.
