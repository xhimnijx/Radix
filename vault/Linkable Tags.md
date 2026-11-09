---
title: Linkable Tags
tags: [protocol, double-spend, reviews]
---

# Linkable tags

A ring signature hides *which* key it opens. That creates a problem: a node cannot
tell a second spend of the same coin from a spend of a different coin. The **tag** is
the fix.

## The idea

The tag is a deterministic function of the **secret**:

$$T = A' \cdot s$$

- The same coin always produces the same `T`, so a second spend is detectable.
- `T` is a lattice point, so it looks random and reveals nothing about which key it
  came from (it is not linked to the public key without `s`).
- The node stores spent tags and refuses a repeat.

## The first attempt was broken, and that matters

The first implementation proved the tag with a **separate** sigma protocol. An
independent reviewer showed it could be forged: the tag proof bound only a *derived*
row `u_der`, not the individual components, so a cheater could supply an unrelated
witness. `experiments/tag_forgery_repro.py` reproduces the forgery, and
`tag.py` carries a `KNOWN BROKEN` banner with a strict `xfail` test guarding it.

> [!danger] Do not use `tag.py`
> It is kept only as a record. The sound construction replaced it.

## The sound construction: a same-witness extension

Instead of a second proof, extend the proved matrix:

$$A_{\text{ext}} = \begin{bmatrix} A \\ A' \end{bmatrix}, \qquad T = A' s$$

and extend every ring member with the **same** `T`:

$$\text{ring} = \{(pk_1, T), (pk_2, T), \ldots, (pk_{1024}, T)\}$$

Now the *existing* proof over `A_ext` forces `A_ext·s* = c*·(pk_ι, T)`, so the same
witness produces both the public key and the tag. There is no second proof to forge
and no free response.

This is implemented as `ring_signature.sign_tagged` / `verify_tagged`, and it is what
the testnet uses.

## Why `k′ = 4` rows

The tag matrix `A'` has `k′` rows. Two things depend on `k′`:

- **collision resistance between distinct notes.** With `k′ = 1` the kernel is large
  enough that two different secrets could produce the same tag; with `k′ = 4` the
  kernel's shortest vector is ≈ `2^17.3`, far above the `≈ 2^8.7` collision target, and
  it reuses the paper's `M-SIS_{4,13}` assumption rather than adding a weaker one.
- **cost**: `k′ = 4` makes the matrix 8 rows tall, so the proof grows by 4 polynomials
  and the computation roughly doubles on the set-matrix side.

Measured: untagged 32,512 B; tagged with `k′ = 4` **36,608 B** proof + 2,048 B tag =
38,656 B total.

## What the tag does *not* do

It links **one key**. Radix's testnet wallet therefore has four **accounts**, each a
separate keypair, and each spendable once, with change going to the next account. A
real wallet gives every *output* its own key via one-time addressing; that is B2 work
and is not built. See [[The Wallet and Its Accounts]].

## Verification

- `test_candidate_b_tagged_ring.py`: 6 tests — verifies, tag equals `A's`, two spends
  of one note carry the same tag while proofs differ, tampered tag rejected, untagged
  API refuses tagged parameters, size matches.
- `test_testnet_rust_backend.py`: the Rust prover produces a tagged proof the **Python**
  `verify_tagged` accepts.

## Next

[[The Wire Format]] — how a proof becomes bytes on the wire.
