---
title: Modular Arithmetic and the Ring R_q
tags: [mathematics, foundations]
---

# Modular arithmetic and the ring `R_q`

You already know modular arithmetic: `17 mod 5 = 2`, and you can add and multiply
mod 5 because the result never depends on which representative you picked. That is
the *integers modulo 5*, written `Z_5`, and it is a field because 5 is prime.

Everything in Radix happens inside a bigger, stranger object:

$$R_q = \mathbb{Z}_q[X]/(X^{128}+1)$$

Read it in three pieces:

1. **`Z_q`** — integers modulo `q`, where
   `q = 4,294,966,337`, a prime just under `2^32`.
2. **`Z_q[X]`** — polynomials with coefficients in `Z_q`, e.g.
   `3 + 5X + 0X² + (q−1)X³ + …`
3. **`/(X^{128}+1)`** — "two polynomials are equal if they differ by a multiple of
   `X^{128}+1`".

## What the last part actually does

This is exactly like working modulo 5, except the thing you divide by is a
polynomial. The consequence you need is:

$$X^{128} \equiv -1$$

So whenever a multiplication produces `X^{128}` or higher, you replace `X^{128}` with
`-1`, `X^{129}` with `-X`, and so on. This is called **negacyclic reduction**.

**A-Level parallel.** In Further Maths you met roots of unity: `ω = e^{2πi/3}`
satisfies `1 + ω + ω² = 0`, so `ω³ = 1`, and any polynomial in `ω` collapses to a
quadratic. Here `X` plays the role of a formal symbol with the rule `X^{128} = -1`,
so any polynomial collapses to 128 coefficients. Same idea, different relation.

## Why a ring and not a field

`Z_q` is a field: every nonzero element has an inverse. `R_q` is **not** — the
polynomial `X - α` is a nonzero element with no inverse whenever `α` is a root of
`X^{128}+1`. Elements like that are called **zero divisors**, and they are the source
of one of the two serious bugs found in review ([[What Reviewers Found]], item Q3′).

Whether `R_q` has zero divisors depends on how `X^{128}+1` factorises over `Z_q`. That
single fact drives the choice of `q` and is the subject of
[[The NTT and the Quartic Decomposition]].

## An element is a vector of 128 numbers

A member of `R_q` is just 128 numbers in `[0, q)`:

```
a = (a₀, a₁, …, a₁₂₇),   representing   a₀ + a₁X + … + a₁₂₇X¹²⁷
```

Addition is componentwise: `(a + b)_i = (a_i + b_i) mod q`.

Multiplication is the interesting one:

$$(a \cdot b)_k = \sum_{i+j=k} a_i b_j \;-\; \sum_{i+j=k+128} a_i b_j \pmod q$$

The first sum is an ordinary convolution; the minus sign on the wrapped terms is the
`X^{128} = -1` rule. This is `radix_core/candidate_b/lattice/ring.py`, function
`mul_naive`.

## The "why does a minus sign matter" intuition

Because it makes multiplication *non-commutative in structure* — no, it stays
commutative — but it makes `X^{128}+1` **irreducible over the rationals**, which is
why there is no factorisation into 128 nice linear pieces unless you deliberately
choose `q` so that `X^{128}+1` splits. Choosing whether to split is a real design
decision with security consequences ([[The NTT and the Quartic Decomposition]]).

## Cost model

Multiplication naively is `128² = 16,384` coefficient products. Radix computes it in
about 512 products using a decomposition, which is why the Rust prover can do ~20 µs
per multiplication instead of milliseconds. See
[[The NTT and the Quartic Decomposition]].

## Worked micro-example (small analogue)

Take the same construction with degree 4 instead of 128 and `q = 17`, so
`R = Z_17[X]/(X⁴+1)`. Let `a = 1 + 2X` and `b = 3 + X³`.

- `a·b = 3 + X³ + 6X + 2X⁴`
- `X⁴ = -1`, so `2X⁴ = -2 ≡ 15`
- Result: `(3 + 15) + 6X + 0X² + 1X³ = 1 + 6X + X³`

Every multiplication in Radix is this, 128 coefficients wide.

## Next

[[Polynomials as Vectors]] — why these 128 numbers get treated as a point in space.
