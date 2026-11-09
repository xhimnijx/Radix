---
title: How the Port Was Verified
tags: [rust, verification, evidence]
---

# How the port was verified

The Rust prover and verifier are a second implementation of the same protocol. This
note records how they were checked, and the three bugs that checking found.

## The layered method

Each module was ported and given a **known-answer test taken from Python before the
next module started**. The rule was: a layer is not done because it compiles.

| Layer | Cross-language value |
|---|---|
| SHAKE256 | 4 `hashlib` vectors (empty, `abc`, 200-byte, 500-byte) |
| Transcript | two squeezes + ternary challenge, byte for byte |
| Codec | polynomial digest `1e86594e…` |
| Sampling | shared generator (`domain ‖ len(label) ‖ label ‖ counter`) |
| BDLOP | commitment digest `8ef836b5…` |
| Tensor | `flat_index((2,1,3),32) = 2083` |
| Quadratic | `cf184ee9…` and `e512cc05…` |
| Recursion | pairing `3a917ee9…` |
| Statement | `masking_width` 29/33/31; `draw` `d35674e8…`; `draw_ternary` |
| Indices | `paper_to_slot` for 11 positions; `e1`, `b_transpose`, `gamma_elements` |
| Set matrix | 128 × 1024 digest `7fdce86f…` |
| Prover/verifier | **both directions accept** |

## Why layer-by-layer, and not "run the proof and see"

If the only test is "the proof verifies", a wrong transcript byte and a wrong recursion
coefficient are indistinguishable: both produce a proof that fails. The layered
approach localises an error to the layer that introduced it.

It worked. Three bugs, three different layers, all found quickly:

### Bug 1 — commitment arity (found by a length mismatch)

Expected 34,560 bytes, got 32,512. The formula was `κ + λ + m + 1`; the truth is
`κ + rows + 2m + 1`. The two agree when `rows = 8`, which is the **tagged** shape, so
the wrong formula passed every test that used tags — and the **same bug was in
`radix_testnet/codec.py`**, invisible because the harness only used tagged parameters.

### Bug 2 — a sign error (found by the stage trace)

`verify_traced` records the name of every stage; the last name is where it stopped. One
run showed all 18 stages passing except `omega` — so the transcript, the descent and
`final_x` were already right, and the defect was that the final `lhs` term was
subtracted rather than added.

### Bug 3 — `g`'s prefix (found by the same trace)

Python zeroes the first `d/l` **coefficients** of `g`; the port zeroed the first `d/l`
**slots** and lifted. Every other stage still passed — commitments, both challenges,
the whole descent are consistent because none of them constrains `g`. Only the
`h`-prefix check catches it.

## The decisive test

Self-consistency is weak: a prover and verifier wrong in the same way agree happily.
The strong test is cross-implementation.

| direction | result |
|---|---|
| Python proof → Rust verifier | passes (`tests/python_proof.rs`) |
| Rust proof → Python verifier | passes (`experiments/verify_rust_proof.py`) |
| Rust proof, different message | rejected by both |
| tampered response | rejected by Rust |

A matching challenge `c` is the strongest single signal: the verifier recomputes it
from the proof's own commitments, so agreement means the transcript is byte-identical
across ten absorbs and three label families.

## What is still unverified

The Rust port has **not** been audited by a third party. It is verified *against the
Python reference*, which itself is verified against the paper by two reviewers. That
chain of evidence is strong but it is not the same as an independent audit.

## Next

[[Performance Measurements]] for the numbers, [[The Rust Port]] for the structure.
