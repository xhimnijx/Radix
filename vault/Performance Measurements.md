---
title: Performance Measurements
tags: [performance, measurements]
---

# Performance measurements

All numbers are from one laptop, release builds, depth 2 (ring 1024). They are
measurements, not projections — an earlier projection of this project was wrong by
about 30% and in an unexpected direction, which is why this note leads with the
measured table.

## The headline

| | Rust | Python (reference) |
|---|---|---|
| **prove** | **496 ms** | 1–2 min |
| **verify** | **110 ms** | 20–38 s |
| proof size | 32,512 B | 32,512 B |
| attempts per proof | 9.75 | ~same |

## Why ~10 attempts

There are two rejection points:

- `z′`, checked **early** (before the expensive set matrix) — cheap to reject;
- `z`, checked at the very **end** — a rejection costs a whole proof.

Each accepts with probability ≥ `1/(2M²) = 1/3`. So ~9 attempts total, of which ~3
reach the set matrix. That is why the mean is 496 ms rather than ~150 ms: most
attempts are cheap, and a few are expensive.

## Where the time goes

From profiling the Python prover:

| Component | Share |
|---|---|
| `_set_matrix` (128 × 1024 quartics) | ~58% |
| `ring.dot` and friends | ~35% |
| hashing, sampling, glue | ~7% |

The Rust port follows the same shape, which is why porting the set matrix and the dot
products first was the right order.

## Getting to 20 µs per multiplication

The Rust ring multiplication went through three measurements:

| Version | Time | Fix |
|---|---|---|
| first | 71.2 µs | slower than the naive convolution! `mul_mod` used a `u128` division |
| Barrett reduction | 34.2 µs | no division in the inner loop |
| accumulate slots in `u128` | **20.1 µs** | one reduction per residue instead of 128 |

The first version being *slower than naive* is the useful lesson: the arithmetic was
right, the implementation was not, and only a benchmark said so.

## Against the B2 bar

| phase | measured | phone ×3–5 | bar | verdict |
|---|---|---|---|---|
| prove | 496 ms | 1.5–2.5 s | ≤ 60 s | **passes** |
| verify | 110 ms | 330–550 ms | ≤ 100 ms | **fails on a phone** |

Verify is over the line on the machine that measured it. Batch verification
(amortising the set matrix) is the likely fix and is **unmeasured**.

## The projection that was wrong

Earlier versions of this project quoted `0.36 s` to prove and `0.13 s` to verify,
derived as "operation count × measured per-operation cost". The measurements are
`0.50 s` and `0.11 s`. Same order, both wrong, and the verify error went the opposite
way from the prediction. The model was good enough to plan with and not good enough to
quote.

## Reproducing

```powershell
cd proof_rust
cargo run --release --bin bench_proof
```

Expected: about 496 ms, 110 ms, 9.75 attempts. See [[Reproducing Everything]].
