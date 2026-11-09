# Review request: third pass

For the cryptographer. Round one found the tag forgeable and the parameters
unpriced; round two settled the modulus. This brief says what changed, what is now
implemented, and the five questions that remain. It is one page by design.

**Status:** research prototype. No audit, no security claim, no value. The
Candidate-A track is archived in `archive/` and is not part of this review.

## What changed since the second pass

| Item | Then | Now |
|---|---|---|
| Modulus | `q = 4,294,962,681`-era prototype, `ord_256 = 1`, slots `Z_q^4` | **`q = 4,294,966,337`, `ord_256 = 4`**, 32 irreducible quartics |
| Ring multiplication | 128-point NTT | quartic CRT (32 slotwise 4x4 products), NTT kept as the reference |
| `_is_unit` | 128 NTT coordinates | regime-aware: 128 coordinates at a split `q`, 32 residues at an irreducible one |
| Extraction cap | ~2^-24 from `c - c~` | ~2^-123, by the modulus |
| Slot-constancy | open hole; `v` a 128-coordinate idempotent | **closed by the same change**; `v` is a 32-entry binary vector |
| Masks | uniform `2^20`, l-infinity verifier bound | **Gaussian `s = 464 sqrt(W)`**, `Rej1`, **l2** bound `beta = s sqrt(2Wd)` |
| Tag | forgeable; withdrawn | same-witness extension `A_ext = [A; A']`, `k' = 4`, 38,656 B |
| Proof | 32,512 B, ~21 s / 20 s | 32,512 B, **~2 min** (rejection) / 21 s in Python |
| Prover cost in Rust | unknown | **measured ~0.47 s to prove, 37 ms to verify** (`PERFORMANCE.md`) |

The modulus migration is arithmetic-only: `slot`, `slots`, `g`, `pairing`,
`quartic_multiply` and the whole recursion layer are untouched, and the CRT path
is equality-tested against the NTT path at the split modulus where both exist.

## Live questions

### Q-A. The estimator run (the only thing standing between this and a claim)

The mask is now calibrated, not guessed: `experiments/mask_calibration.py` measures
`T(W) = 296 sqrt(W)` as the 99th percentile of `||c r||_2` on the code's own
distributions, and `s = 1.567 T` sets `M = sqrt(3/2)`.

| mask | `T` (measured) | `s` | `beta` | target | reachable at `delta = 1.0042` | margin |
|---|---|---|---|---|---|---|
| `z` (W = 33) | 1701 | 2670 (`2^11.4`) | `2^17.9` | `2^27.9` | `2^31.7` | 3.8 bits |
| `z'` (ell = 13) | 1081 | 1684 (`2^10.7`) | `2^16.6` | `2^17.6` | `2^21.2` | 3.6 bits |

**Question:** with `(q, d, l, k, ell, kappa, lambda, mu) = (2^32, 128, 32, 4, 13,
10, 10, 5)` and `(beta, beta') = (2^17.9, 2^16.6)`, do `M-SIS_{k, 2 sqrt(beta'^2+d)}`
and `M-SIS_{kappa, 8 d beta}` clear 128 bits? Please quote `beta` and `beta'`
together — the two conventions C2 identified differ by ~150 bits.

### Q-B. Continuous versus discrete Gaussian

`setmembership._gaussian` draws a **continuous** Gaussian and rounds to integers.
Lemma A.6 is stated for a discrete Gaussian, and rounding differs by `O(1/s)`. At
`s ~ 2^11` that is far below any security threshold, but it is not the same
object.

**Question:** is the rounding acceptable with that caveat recorded, or must the
sampler be discrete before the rejection argument may be invoked at all?

### Q-C. The Theorem B.1 restatement

The three edits C2 specified are not yet written into a document: `p` redefined
over `F_{q^4}`, `c-bar` invertibility as an explicit hypothesis, and the
slot-constant property attributed to the modulus. The induction is expected to get
shorter, not longer.

**Question:** does the restatement need a reviewer's signature, and would you sign
the version with those three edits?

### Q-D. `k' = 1` or `k' = 4`

C2: under `A_ext` the instance is `(4+k') x 13`, so even `k' = 1` has a Gaussian
shortest vector two orders of magnitude above the collision target; `k' = 4` is
insurance, not necessity. C1 recommended 4. It costs 1 KB.

**Question:** which do you want the implementation to default to?

### Q-E. The paper's errata

The `e_1` double count in Fig. 9 line 12 / eq. (27) and the sum index in eq. (24)
should be checked against the later ePrint revisions (up to 2022-05-20) before the
paper is recorded as wrong.

## Performance

`PERFORMANCE.md`. The arithmetic layer is ported to Rust (`proof_rust`) and
cross-checked against Python bit for bit by
`experiments/rust_crosscheck.py`. Measured on the same machine: one prover attempt
0.156 s (set matrix and dot products, which are 93% of the Python profile), so
~0.47 s per proof at the expected three attempts; verification 37 ms. Verify is
the phase without margin: it passes 100 ms on desktop and probably not on a phone.

## What a reviewer should check first

1. `setmembership._reject` against Fig. 10's `Rej1` and Lemma A.6 — in particular
   that the verifier's `beta` is derived from the same `s` the prover used.
2. That the response bound is an **l2** bound. The old code checked l-infinity,
   which is what made the response bound the security parameter.
3. `subring.multiply` and `glue_crt` against the NTT path at the split modulus —
   the equality tests are in `tests/test_candidate_b_subring.py`.
4. `_is_unit`'s two regimes. The residue test is exact at an irreducible `q` and
   **wrong** at a split one, where it admits zero divisors.

## Reproducing

```powershell
python -m pytest -q -m "not slow"     # arithmetic and unit checks, seconds
python -m pytest -q                   # everything, ~1-2 h with rejection sampling
python experiments/mask_calibration.py
python experiments/slot_constancy_probe.py
```

## What we are not asking

Consensus, networking, economics, or the archived Candidate-A work. There is no
network, no wallet and no value; `radix_core/launch.py` is closed by design.
