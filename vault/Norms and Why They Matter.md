---
title: Norms and Why They Matter
tags: [mathematics, masking, rejection]
---

# Norms and why they matter

The prover reveals `z = y + c·s`. If `y` is small, `z` leaks `s`; if `y` is enormous,
the proof is huge and the verifier's bound is loose. This note is the whole
trade-off, with the actual measured numbers.

## The requirement: statistical hiding

`y` must be drawn from a distribution wide enough that, for any two candidate secrets
`s₁, s₂`, the distributions of `y + c·s₁` and `y + c·s₂` are close. The standard
choice is a **discrete Gaussian** with standard deviation `s` (the paper's symbol), and
the masking is sound when

$$s \approx 11\,\|c\cdot s\|_2$$

The factor 11 comes from the paper's `Rej0`/`Rej1` lemmas: with `s = 11‖v‖` the
rejection rate is `M ≈ 3`.

## The measured quantities

`experiments/mask_calibration.py` measures, on the code's own distributions (ternary
`½/¼/¼` challenge, uniform `[−5,5]` secret, `d = 128`):

| quantity | model | measured |
|---|---|---|
| variance of one coefficient of `c·s` | `128 · E[c²] · E[s²] = 640` | **627** |
| `T = ‖c·s‖₂` 99th percentile, `W = 33` components | ~1.7k | **1701** (`2^10.7`) |
| `T′` for `z′` (`ℓ = 13` components) | ~1.1k | **1081** (`2^10.1`) |

From these, the calibrated mask width is

$$s = 1.567\,T \qquad(\text{so that } M = \sqrt{3/2},\ 2M^2 \approx 3)$$

giving `s = 2666 (2^11.4)` for `z` and `s′ = 1673 (2^10.7)` for `z′`, and the bounds

$$\beta = s\sqrt{2Wd} \approx 2^{17.9}, \qquad \beta' = s'\sqrt{2\ell d} \approx 2^{16.6}$$

## Why `Rej1` and not plain Gaussian

A plain Gaussian mask with `s = 11‖v‖` is needlessly wide. **Rejection sampling** lets
the prover use a mask only `1.57·‖v‖` wide while keeping the output distribution
correct:

```
Rej1(z, v, s):
    if ⟨z, v⟩ < 0: reject              # bimodal: keep only the positive half
    accept with probability (1/M)·exp((−2⟨z,v⟩ + ‖v‖²)/(2s²))
```

The bimodality is what halves the width. `M = √(3/2)` means the prover retries on
average `2M² ≈ 3` times.

## What the verifier checks

Not the infinity norm — the **ℓ₂ norm**, exactly as the paper states:

$$\|z\|_2 \le \beta, \qquad \|z'\|_2 \le \beta'$$

> [!important] This was a real fix
> The original code checked `‖z‖∞ ≤ 2^20 + 8192`. With an infinity bound the *response*
> bound, not the secret bound, becomes the security parameter — and `2^20` against
> `μ = 5` puts the core at about `2^50` rather than `2^128`. The ℓ₂ check with the
> calibrated `β` is what fixes it. See [[What Reviewers Found]], item Q3/Q5′.

## The measured effect

Before: maximum coefficient of `z` was ~`10⁶`.
After: **9,733**, and `‖z‖₂ = 150,419` against a bound of `215,296`.

So the responses are ~100× smaller and the bound has ~2.2× slack, which is the
designed safety margin — not waste.

## Attempts and cost

Two rejection points:

- `z′` — checked **early**, before the expensive set matrix, so a rejection is cheap;
- `z` — checked at the very end, so a rejection costs a whole proof.

Each accepts with probability ≥ `1/(2M²) = 1/3`, so about 9 attempts in total, of
which ~3 reach the expensive part. Measured: **9.75 attempts per proof**, 496 ms mean
in Rust. [[Performance Measurements]] has the table.

## The caveat that must not be glossed

`setmembership._gaussian` draws a **continuous** Gaussian and rounds to integers.
Lemma A.6 of the paper is stated for a **discrete** Gaussian; rounding differs by
`O(1/s)`, negligible at `s ~ 2^11`, but it is not the same object. A discrete sampler
is required before any security claim, and both the code and
[[Status and Honest Limitations]] say so.

## Next

[[Commitments and Zero Knowledge]] — how a value is hidden but still provable.
