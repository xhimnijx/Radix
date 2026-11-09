---
title: The Recursion
tags: [protocol, core]
---

# The recursion

A ring of 1024 keys would give a 1024-column matrix, which is expensive. SMILE handles
it with `m` levels: at each level, 32 columns are collapsed into 1 using a challenge
`γ`, so `m` levels address `32^m` keys for the cost of roughly `m` small matrices.

## The tensor structure

The index is written in base 32 and encoded as a tensor of one-hot blocks:

$$v = e_{i_1}\otimes e_{i_2}, \qquad \iota = 32\,i_1 + i_2 \quad (m=2)$$

`v` has `32^m` entries with exactly one 1. The reason this helps is that the matrix
`P` can be split into 32 column blocks `P = [P_1 | … | P_32]`, and the product `P·v`
decomposes:

$$P\,v = \sum_{j} P_j \,(e_j\text{-part}) = P_{i_1}\,(\text{inner tensor})$$

so only one block matters, and the prover/verifier can compute the answer by
processing 32 columns at a time.

## The descent

At level `ℓ`:

1. draw a challenge `γ_ℓ` from the transcript (32 coefficients);
2. compute `P' = [γᵀP_1 ; … ; γᵀP_32]` — the next level's matrix (`reduce_matrix`);
3. compute `x_next = P' · (tensor of the remaining one-hot blocks)`;
4. record a commitment to `x_next` and absorb it into the transcript.

After `m−1` levels there is a single block left; `final_x` computes the final
`x_{m+1}` using `γ_m`.

## The `B^Tγ` trick

`B` (the commitment's first row) is all ones. So `(Bᵀγ)_i = γ_0` for every slot — a
*constant* vector. That is what encodes `⟨1, v_i⟩ = 1`: paired with a one-hot `v_i` it
selects `γ_0`, which cancels the `⟨e₁, γ⟩` term it must cancel.

`proof.b_transpose` implements this, and it is checked twice in the Rust port: against
the Python digest `10f028d8…` *and* against the property "every slot equals `γ`'s first
slot", because the property is the reason the function exists.

## The `y` values

At each level the prover forms `y = v · x_next − (corrections)`, and finally

$$h = g + \sum y_i$$

The verifier cannot see any `y`, but it can check that `h` satisfies an equation with
`ω`, and the `h`-prefix check ensures `g` had the right zero prefix.

## Why depths below 2 are refused

`m = 1` has no `B` block, so `⟨1, v_i⟩ = 1` is never proved — the scheme is unsound,
not merely differently shaped. Both the Python and the Rust code refuse `m = 1`.
This was one of the review findings ([[What Reviewers Found]], Q5).

## Cost

At `m = 2` the matrix is `rows·32 = 128` by `32² = 1024` quartic entries —
`set_matrix` in both implementations. It is the single largest computation in the
verifier, and it is why measured verify time is 110 ms rather than 20 ms.

## Verification

- `recursion.py` ↔ `recursion.rs`, with the pairing digest `3a917ee9…` matching.
- `set_matrix` digest `7fdce86f…` matches (128 × 1024 quartics).
- `reduce_matrix` and `split` shapes tested at `m = 2`.

## Next

[[Fiat-Shamir and the Transcript]] — how the challenges are derived so the prover
cannot choose them.
