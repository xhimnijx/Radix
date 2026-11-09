---
title: Hard Problems on Lattices
tags: [mathematics, security]
---

# Hard problems on lattices

This note states the two problems precisely enough to read the security argument, and
explains why the *module* versions (`M-SIS`, `M-LWE`) are what Radix actually relies
on.

## SIS, precisely

**SIS** (Short Integer Solution), parameters `(n, m, q, β)`:

> Given a uniformly random `A ∈ Z_q^{n×m}`, find `s ∈ Z^m`, `s ≠ 0`, with
> `A s ≡ 0 (mod q)` and `‖s‖₂ ≤ β`.

The **inhomogeneous** version gives a target `t` and asks for `A s = t`.

Radix's version is over the ring `R_q` rather than `Z_q`, which is why it is called
**M-SIS** ("module SIS"): the matrix `A` has polynomial entries instead of integer
entries. The hardness carries over; the sizes change by a factor of `d`.

The relevant instance in the signature is:

$$\text{M-SIS}_{k,\; 2\beta'} \quad\text{with}\quad k = 4,\ \ell = 13,\ d = 128$$

and the target is `2β′` rather than `β′` because the extractor takes a **difference**
of two responses, and the triangle inequality doubles the bound.

## LWE, precisely

**M-LWE**: distinguish `(A, A s + e)` from uniform, where `s` and `e` are short.

This protects the commitments: a commitment `t = B r` looks uniform to anyone who does
not know `r`, and the opening reveals only a masked version of it.

## What "128-bit security" means here

A security level of `λ` bits means the best known attack costs about `2^λ`
operations. Nobody proves a lower bound; instead:

1. estimate the cost of the best known lattice attack as a function of the
   parameters,
2. check that cost exceeds `2^λ`.

The standard yardstick is the **root-Hermite factor** `δ` and the **Core-SVP** cost
model:

- find `δ` such that the lattice reduction reaches the target norm,
- map `δ` to a block size `β_BKZ`,
- cost ≈ `2^{0.292 β_BKZ}` (classical Core-SVP).

The relevant quantity is the **reachable norm**: how short a vector lattice reduction
can find with a given `δ`.

## The numbers Radix actually has

At `δ = 1.0042` and `q ≈ 2^32`:

| relation | dimension `n` | `det^{1/n}` | reachable norm | target | margin |
|---|---|---|---|---|---|
| `A` (4×13) | 1664 | `2^12.30` | `2^21.19` | `2β′ ≈ 2^17.6` | ~3.6 bits |
| `B₀` (10 rows) | 2944 | `2^13.91` | `2^31.71` | `8dβ ≈ 2^27.9` | ~3.8 bits |

> [!warning] This is not a 128-bit claim
> These margins come from a root-Hermite heuristic, not from a lattice estimator run.
> `PERFORMANCE.md` and [[Status and Honest Limitations]] say the same thing: **the
> estimator has not been run**, and until it is, no security level may be claimed.
> The numbers above are the inputs a reviewer would use.

## Why the target is `2β′` and `8dβ`

Both come from the extraction argument:

- For the `A` relation the extractor produces **two** short preimages and subtracts
  them, so the target norm is `2β′`.
- For the commitment rows the opening proof's bound is `8dβ`, because it is a sum of
  `κ` masked responses each bounded by `β` (four such terms in the worst case give
  `8`), multiplied by the degree `d`.

Both are the paper's own accounting (`Lemma C.1`, `Theorem C.4`), and both were
re-derived during review — see [[What Reviewers Found]], item Q5′.

## The modulus change and these numbers

Every number above depends on `q`. Switching from the split prototype to
`q = 4,294,966,337` keeps `q ≈ 2^32` so the sizes are essentially unchanged, but the
**hardness estimates must be re-run** for the new modulus and the new mask widths.
That re-run is the outstanding work item.

## Why quantum computers do not break this

Shor's algorithm solves factoring and discrete log because those problems have
algebraic structure (period finding in a group). SIS and LWE have no such structure
known; the best known quantum algorithms are the same generic lattice attacks with a
small square-root speedup for search.

## Next

[[Challenge Spaces and Ternary Secrets]] — where the small numbers come from, and why
the challenge distribution is not a detail.
