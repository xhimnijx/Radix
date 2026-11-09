---
title: The Set Membership Proof
tags: [protocol, core]
---

# The set membership proof

This is the heart of Radix: a proof that

> "I know `s` such that `A·s = pk_ι` for some `ι ∈ {0, …, 1023}`"

without revealing `ι` or `s`.

The implementation is `radix_core/candidate_b/lattice/setmembership.py`, following
SMILE (ePrint 2021/564), Figures 7–9.

## The shape of the argument

1. Commitment to a vector `v` that encodes the index as a **one-hot** vector
   (`v` has a single 1, at position `ι`).
2. A **linear relation** linking `v` to the public keys: `vᵀ · (matrix of keys)` gives
   the selected key.
3. A **quadratic relation** forcing `v` to be one-hot: `v(v−1) = 0` and `Σ v_j = 1`.
4. Masking so none of it reveals `v`.

The clever part is that a single polynomial equation, evaluated as a function of the
challenge `c`, carries the linear part at order `c`, the quadratic part at order `c²`,
and the verifier checks the coefficients.

## The polynomial view

Define a polynomial in the challenge `c`:

$$F(c) = \text{(products of masked responses)}$$

- `F(0)` — the commitments alone;
- `F(1)` — the linear relations;
- `F(2) − 2F(1) + F(0)` divided by 2 — the **second divided difference**, which
  extracts the `c²` coefficient.

The verifier never sees `F`; it checks that a linear combination of the prover's
responses equals `ω`, and the soundness proof shows that a cheating prover would have
to produce a short solution to SIS.

This coefficient extraction is `quadratic.quadratic_coefficient`, and its Rust port is
checked against Python (`cf184ee9…`) plus the property test that it really returns
`k` for `F(c) = c²k`.

## The binaryness constraint

Requiring `v(v−1) = 0` in `R_q` forces each slot residue to be 0 or 1 **in the field
regime** — that is, at the modulus Radix uses. This is the "slot constancy" issue:
under a split modulus the same equation allows arbitrary 128-bit idempotents and the
conclusion "exactly one 1" is meaningless. See
[[The NTT and the Quartic Decomposition]] and [[What Reviewers Found]] (Q6).

## The index vector and `g`

`v` is built as a tensor of one-hot blocks:

$$v = e_{i_1} \otimes e_{i_2} \otimes \cdots \otimes e_{i_m}, \qquad \iota = \sum i_j \cdot 32^{\,m-j}$$

For `m = 2` and `ι = 34`, that is `e₁ ⊗ e₂`, a 1024-entry vector with a single 1 at
position 34. `tensor.flat_index((1,2), 32) = 34` and the Rust port returns the same.

`g` is a random polynomial with its first `d/l = 4` **coefficients** zero. That prefix
is checked by the verifier (lines 14–15); it is what makes `h`'s first coefficients
zero. A port that zeroed the first 4 *slots* instead would produce a proof that fails
only that check — and that is exactly the bug the Rust port hit
([[How the Port Was Verified]]).

## The verifier's checks, in order

The full sequence is in `setmembership.verify` and mirrored in `verifier.rs`:

| step | check |
|---|---|
| 1 | ℓ₂ bounds on `z` and `z′` |
| 2 | both challenges are units |
| 3 | recompute `w = B₀z − c·t₀`, derive `c′` from the transcript |
| 4 | absorb `z′`, subtract `A z′` from the `t` values |
| 5 | compute all `f_i = ⟨b_i, z⟩ − c·t_i` |
| 6 | build the set matrix `P` from `c′`, descend with `γ`s |
| 7 | accumulate lines 10–13 into `inner` |
| 8 | derive `c` from the transcript; check it matches |
| 9 | check the `ω` equation |
| 10 | check `h`'s prefix is zero |

The Rust verifier records the name of each stage (`verify_traced`), which is how the
port's last two bugs were found in one run.

## Where the parameters appear

- `W = κ + λ + rows + 2m + 1` — width of `r`, `y`, `z`
- `κ = 10` commitment rows for `t₀`
- `λ = 10` extra mask components
- `rows = k = 4` (or `k + k′ = 8` with tags)
- `m = 2` recursion depth, ring size `32² = 1024`

## Next

[[The Recursion]] — how the 1024 columns are handled in `m` steps rather than one
enormous matrix.
