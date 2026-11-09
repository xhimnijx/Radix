---
title: The Parameters and Where Every Number Comes From
tags: [parameters, reference]
---

# The parameters, and where every number comes from

Every constant in the system, its value, its source, and what would change if it were
different. This note exists so that no number in the project is unexplained.

## The manifest

| Symbol | Name | Value | Source |
|---|---|---|---|
| `q` | modulus | **4,294,966,337** | Chosen by this project, not the paper. `q ≡ 1 (mod 64)`, `q ≢ 1 (mod 128)`, prime. |
| `d` | ring degree | 128 | SMILE |
| `l` | subring dimension | 32 | SMILE |
| `k` | matrix rows | 4 | SMILE |
| `ℓ` | matrix columns | 13 | SMILE |
| `κ` | challenge/commitment rows | 10 | SMILE |
| `λ` | extra mask components | 10 | SMILE |
| `μ` | secret bound | 5 | SMILE |
| `k′` | tag rows | 4 | This project (see [[Linkable Tags]]) |
| `m` | recursion depth | 2 | Minimum allowed; ring `32² = 1024` |

## Derived quantities

| Quantity | Formula | Value |
|---|---|---|
| width `W` | `κ + λ + rows + 2m + 1` | **29** untagged, **33** tagged (`rows = 8`) |
| ring size | `l^m` | 1024 |
| commitment polynomials | `κ + rows + 2m + 1` | **19** untagged, **23** tagged |
| proof size | `(commitment + 2 + ℓ + W)·d·4 + 2d` | 32,512 B untagged; 36,608 B tagged |
| total on the wire | proof + tag | 38,656 B tagged |

> [!note] The commitment arity bug
> The formula is `κ + rows + 2m + 1`, **not** `κ + λ + m + 1`. Both give 23 when
> `rows = 8`, which is the tagged shape — so a wrong formula passed every test that
> used tags. The Rust port exposed it. See [[How the Port Was Verified]].

## The masking parameters

Not design choices — **measurements**. From `experiments/mask_calibration.py`:

| Quantity | Value | How |
|---|---|---|
| coefficient variance of `c·s` | 627 (model: 640) | sampled |
| `T` for `z` (`W = 33`) | 1701 (`2^10.7`) | 99th percentile |
| `T′` for `z′` (`ℓ = 13`) | 1081 (`2^10.1`) | 99th percentile |
| mask width `s` | `1.567·T` | so `M = √(3/2)` |
| `s` for `z` | 2666 (`2^11.4`) | derived |
| `s′` for `z′` | 1673 (`2^10.7`) | derived |
| `β` | `s·√(2Wd)` ≈ 244,992 (`2^17.9`) | verifier bound |
| `β′` | `s′·√(2ℓd)` ≈ 96,512 (`2^16.56`) | verifier bound |

## Why `q` is what it is

The one parameter chosen by this project rather than taken from the paper. The
requirement is `ord_256(q) = 4`, which happens exactly when `q ≡ 1 (mod 64)` and
`q ≢ 1 (mod 128)`. Candidates were found by scanning downward from `2^32` and checking
the order criterion (`experiments/irreducible_modulus_search.py`):

| `q` | `q − 2^32` | `ord_256` | quartics |
|---|---|---|---|
| 4,294,966,337 | −959 | 4 | irreducible |
| 4,294,965,313 | −1,983 | 4 | irreducible |
| 4,294,964,929 | −2,367 | 4 | irreducible |
| **4,294,962,689** (prototype) | −4,607 | **1** | **splits into linears** |

The prototype was the split case, which is why its soundness was capped at ~24 bits.

## What each parameter would cost to change

| Change | Effect |
|---|---|
| `q` → larger | More security per bit of noise, larger proofs (4 bytes/coefficient either way until `q > 2^32`) |
| `d` = 64 or 256 | Changes everything; the quartic structure needs `4 ∣ d` |
| `m` = 3 | Ring 32,768; proof grows by roughly one level of commitments |
| `κ`, `λ` | Directly change `W` and therefore the proof size |
| `k′` = 1 | Cheaper tag, but distinct-note collision resistance is not 128-bit |
| `μ` = 3 | Smaller responses, lower security margin on the secret |

## The honest gap

None of these parameters has been run through a lattice estimator. The margins in
[[Hard Problems on Lattices]] are heuristic. `STATUS.md` says: *nothing in this
repository may claim 128-bit security*, and that stands until an estimator run
exists.
