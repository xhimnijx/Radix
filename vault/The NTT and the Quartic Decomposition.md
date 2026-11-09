---
title: The NTT and the Quartic Decomposition
tags: [mathematics, implementation, modulus]
---

# The NTT and the quartic decomposition

This note explains the single most consequential engineering decision in the whole
project: **the choice of `q`**, and why it is `4,294,966,337`.

## Splitting `X^{128}+1`

Over the complex numbers, `X^{128}+1` factors into 128 linear pieces:

$$X^{128}+1 = \prod_{k=0}^{127}(X - \zeta^{2k+1})$$

where `ζ` is a primitive 256th root of unity. Over `Z_q` the same thing happens **if
and only if** `q ≡ 1 (mod 256)`, because then `Z_q` contains such a `ζ`.

When it splits, `R_q` becomes a product of 128 copies of `Z_q` — you can evaluate a
polynomial at each root and multiply pointwise. That is the **Number Theoretic
Transform (NTT)**, the finite-field analogue of the Fourier transform, and it turns
a 128×128 convolution into 128 pointwise multiplications plus two transforms.

## The two-level view: 32 quartics

Radix uses a coarser decomposition. Group the 128 roots into 32 groups of 4:

$$X^{128}+1 = \prod_{i=0}^{31}(X^4 - r_i), \qquad r_i = \zeta^{8i+4}$$

Each `X⁴ − r_i` is a **quartic slot**, and a polynomial is represented by its 32
residues, each a quartic (4 coefficients). Multiplication in `R_q` becomes 32
independent multiplications in `Z_q[X]/(X⁴ − r_i)` — about 32 × 16 = 512 coefficient
products instead of 16,384.

This is `subring.slot`, `subring.slots`, `subring.quartic_multiply` and
`subring.glue_crt` in the Python reference.

## The decision

> How does `X^4 − r_i` factor *within* each slot?

Two regimes:

| `ord_256(q)` | Factorisation | Each slot is | Idempotents per slot |
|---|---|---|---|
| 1 | 128 linear factors | `Z_q⁴` | 16 |
| 2 | 64 quadratics | `(Z_q²)²` | 4 |
| **4** | **32 irreducible quartics** | **`F_{q⁴}`, a field** | **2 (only 0 and 1)** |

`ord_256(q)` is the multiplicative order of `q` modulo 256. Radix uses
`q = 4,294,966,337`, which satisfies `q ≡ 1 (mod 64)` but `q ≢ 1 (mod 128)`, so
`ord_256(q) = 4` and every slot is a **field extension**.

## Why the field regime matters — two separate reasons

### 1. Invertibility of a challenge difference

The security proof extracts a witness by dividing by `c − c̃` (the difference of two
challenge polynomials). That division only works if `c − c̃` is a **unit** — invertible
in `R_q`.

- In the **split** regime (`q ≡ 1 mod 256`), `R_q ≅ Z_q^{128}` and a unit requires all
  128 coordinates non-zero. Two random ternary challenges agree in some coordinate
  with probability ≈ `128/q ≈ 2^-24.4`. So soundness is capped at about **24 bits**.
- In the **field** regime, each slot is a field, so a nonzero quartic residue is
  automatically a unit. The difference vanishes in one of 32 slots with probability
  `q^-4 ≈ 2^-128`, so the failure probability is about `32·q^-4 ≈ 2^-123`.

That is the difference between a scheme that is secure and one that is not.

### 2. The extracted index must be a real index

The proof's conclusion is "I know a vector `v` with exactly one 1". If `v` lives in
`Z_q^{128}` split, the constraint `v(v−1) = 0` only forces each of 128 scalar
coordinates to be 0 or 1 — there are `2^128` such idempotents, and "exactly one 1" has
no meaning until you also know the 1s are slot-constant.

In the field regime, `v(v−1) = 0` in `F_{q⁴}` forces each of the **32 slot residues**
to be 0 or 1. So `v` genuinely is a 32-entry binary vector, the sum condition
`Σ v_j = 1` makes it one-hot, and the extracted index selects a column of the
1024-column matrix. See [[The Set Membership Proof]] and
[[What Reviewers Found]] (item Q6).

## The cost, stated plainly

With `ord_256(q) = 4` there is **no 256th root of unity**, so the full 128-point NTT
does not exist. Multiplication uses the quartic CRT instead:

- 2 slot decompositions (128 multiply-adds each),
- 32 quartic products,
- 1 CRT recombination.

Measured at **20.1 µs** per ring multiplication in Rust (`PERFORMANCE.md`). The old
split modulus with an NTT was ~1 ms in Python; the comparison that matters is
Rust-vs-Rust, where the quartic CRT beat a naive convolution (22.2 µs) once Barrett
reduction and slot accumulation were applied.

## Verification

`experiments/slot_constancy_probe.py` checks the classification on one prime per
regime and prints the factorisation, the idempotent count and whether `r_i` is a
square. `tests/test_candidate_b_subring.py` checks that `glue_crt` agrees with the
NTT-based `glue` at the split modulus, where both exist — that equality is what makes
the migration mechanical rather than trusting.

## Next

[[Hard Problems on Lattices]] — the two problems whose difficulty is the only reason
any of this is secure.
