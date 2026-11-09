---
title: The Python Reference
tags: [engineering, python]
---

# The Python reference

`radix_core/candidate_b/lattice/`. The implementation that the paper was transcribed
into, and the reference that the Rust port is checked against.

## The modules, in dependency order

| Module | Role | Lines |
|---|---|---|
| `params.py` | The manifest: `q`, `d`, `l`, `k`, `ℓ`, `κ`, `λ`, `μ` | small |
| `ntt.py` | The full 128-point NTT, used only at the split reference modulus | ~120 |
| `ring.py` | `R_q`: add, sub, mul, dot, norms, sampling, codec | ~200 |
| `subring.py` | Slots, quartic multiplication, CRT glue | ~280 |
| `transcript.py` | Absorb/squeeze over SHAKE256 | ~110 |
| `bdlop.py` | Commitments | ~190 |
| `quadratic.py` | The product form and coefficient extraction | ~120 |
| `tensor.py` | Index vectors, Kronecker products | ~100 |
| `recursion.py` | The Fig. 8 descent over `M_q` | ~255 |
| `sigma.py` | Fig. 5 opening proof (used by aggregation) | ~150 |
| `aggregation.py` | Commitment aggregation | ~200 |
| `setmembership.py` | **The protocol**: prove, verify, keys, statements | ~830 |
| `ring_signature.py` | Wrapper, plus the tagged extension | ~250 |
| `spend.py` | Outputs and spends | ~240 |
| `tag.py` | The **withdrawn** tag — do not use | ~260 |

## Why Python first

1. **Transcription fidelity.** Reading a paper and writing Rust simultaneously invites
   translating an assumption you have not checked.
2. **Testability.** A 20-second proof is slow but acceptable when you run it a handful
   of times; a 20-minute compile-debug loop is not.
3. **It is the oracle.** Every Rust layer is checked against a value Python produced.

The cost: real proofs take 1–2 minutes, which is why the test suite is split into fast
and slow, and why the Rust port exists at all.

## The two prototype scars, kept visible

- `tag.py` carries a `KNOWN BROKEN` banner and a strict `xfail` test.
- `setmembership._is_unit` has a long docstring explaining that the residue test is
  **wrong** in the split regime, because that is a trap a future reader would fall into.

## Running it

```powershell
python -m pytest -q -m "not slow"          # ~75 s
python -m pytest -q tests/test_candidate_b_setmembership.py   # real proofs, minutes
```
