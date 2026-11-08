# Candidate-B lattice parameters (B1)

**Status:** manifest pinned from the primary source; first components implemented.
**Source:** `studies/2021-564.pdf` — the full version of *SMILE: Set Membership
from Ideal Lattices with Applications to Ring Signatures and Confidential
Transactions* (Lyubashevsky, Nguyen, Seiler; CRYPTO 2021, ePrint 2021/564).
**Date:** 2026-11-08.

Page references are to that PDF. Nothing here is inferred from an abstract or a
secondary source.

---

## 1. The manifest

| Symbol | Value | Source |
|---|---|---|
| `q` | ≈ 2³² | p. 48, caption of Fig. 11: "(q, d, l) = (≈2³², 128, 32)" |
| `d` (ring degree) | 128 | same |
| `l` (subring dimension, `d/l` zero-coefficient trick) | 32 | same |
| `k` (BDLOP matrix rows) | 4 | p. 48, Fig. 11 column `k` |
| `ℓ` (BDLOP matrix columns) | 13 | p. 48, Fig. 11 column `ℓ` |
| `κ` (challenge/commitment dimension) | 10 | p. 48, Fig. 11 column `κ` |
| `λ` (masking dimension) | 10 | p. 48, Fig. 11 column `λ` |
| `µ` (secret coefficient bound) | 5 | p. 48, Fig. 11 column `µ` |
| `m` (tensor factors / ring-size bits per dimension) | 1..5 | p. 48, Fig. 11 column `m` |
| Target security | ≈ 128-bit (paper's claim) | p. 1 abstract; p. 48 analysis |

These are encoded in `radix_core/candidate_b/lattice/params.py` as
`SMILE = SmileParameters(...)`, with a test that pins every value and a test that
pins the size tables below.

## 2. Sizes reported by the paper

Ring signatures (Fig. 11, p. 48; also Fig. 2, p. 9):

| Ring size | This work | Falafl | Esgin et al. |
|---|---:|---:|---:|
| 2⁵ = 32 | 15.96 KB | 30 KB | 19 KB |
| 2¹⁰ = 1,024 | 17.27 KB | 32 KB | 31 KB |
| 2¹⁵ = 32,768 | 18.73 KB | 35 KB | 59 KB |
| 2²⁰ | 20.15 KB | 39 KB | 148 KB |
| 2²⁵ | 21.53 KB | — | — |

Transaction proofs (Fig. 3, p. 12), `(M, S)` = input/output accounts:

| Ring size | (1,2) this work | (2,2) this work | (2,2) Esgin et al. |
|---|---:|---:|---:|
| 2⁵ | 22 KB | 24 KB | 110 KB |
| 2¹⁵ | 25 KB | **30 KB** | 300 KB |
| 2²⁵ | 28 KB | 36 KB | 660 KB |

That 30 KB figure is the number this project has been chasing: it is the size of a
complete 2-in/2-out confidential transaction with each input hidden among 2¹⁵
accounts, at an approximately 128-bit lattice security level, with **no FRI and no
large prover workspace**.

## 3. What is implemented here

| Component | State | Notes |
|---|---|---|
| Parameter manifest | done, tested | values above, with provenance |
| Negacyclic ring `R_q = Z_q[X]/(X^d+1)` | done, tested | naive O(d²) multiplication; identity, distributivity, `X^d = -1`, encoding, centered norms |
| Negacyclic NTT | done, tested | `lattice/ntt.py`: twist + radix-2, exact integer arithmetic; `ring.mul` uses it and `mul_naive` stays as the audited reference; 10 tests; 1.97 ms -> 1.00 ms per multiplication, suite 9.97 s -> 5.79 s |
| BDLOP commitment `(t;u) = (B;b)·s + (0;m)` | done, tested | setup, commit, verify, additive homomorphism, k×ℓ shape enforced |
| Proof of knowledge of a BDLOP opening (Sigma) | done, tested | `lattice/sigma.py`: ternary challenge, 2^20 masking, no rejection, 6.8 KB proof, 10 tests. This is the `pi` of SMILE Fig. 5 |
| Tensor / one-hot indexing | done, tested | `lattice/tensor.py`: one-hot, Kronecker product, base-`l` flat index (`n = l^m`), column selection; 9 tests |
| Aggregation of `k` commitments (Fig. 5, p. 14) | done, tested | `lattice/aggregation.py`: `omega`, sparse ternary challenges, `z`, `a*`, `g*`, `pi`; 14 tests; 19,072 B at `k=2`, 20,096 B at `k=4` |
| Set-membership proof (the actual SMILE contribution) | **not implemented** | Fig. 6, p. 15 and the protocol figures that follow |
| Ring-signature transformation | **not implemented** | p. 9 "ring signature from set membership" |
| Fiat-Shamir with rejection sampling | **not implemented** | distribution and bounds are in the paper's parameter derivation, p. 48 |
| Amount commitments / range proofs | **not implemented** | Candidate B milestone B5 |

The two implemented components are the foundation the rest is built on, and they
are pure arithmetic with exact tests — not a proof system, and not claimed as one.

## 4. Deviation that must be resolved before B2

The paper specifies only `q ≈ 2³²`. This prototype uses an exact prime of that
size, `q = 4,294,962,689` (= 2³² − 4,607, prime, `q ≡ 1 mod 256`, so a 2d-th root
of unity exists if NTT is added). It is marked:

```python
MODULUS_FROM_PAPER = False
```

A reviewer or the authors' reference implementation must pin the exact modulus
before any security claim, and before the set-membership proof is implemented:
the challenge space, rejection bounds and SIS/MLWE estimates all depend on `q`.
The prototype is therefore an **arithmetic scaffold**, not a SMILE instantiation.

## 5. B2 checklist (what "lattice backend" actually requires)

Transcribed from the paper so the work is scoped rather than hand-waved:

1. **Set membership** (Fig. 6, p. 15): commit to the `k` messages, the binary
   vectors `V^(j)`, `w̃` and `−w`; challenge; compute `z = y + Σ c^(j)s^(j)` with
   rejection sampling; prove `(Bz − w, g*)` opens to `Σ P^(j)(v^(j) ⊗ …)`.
   *Status:* the `omega` / challenge / `z` / `a*` / `g*` / `pi` half is implemented
   and tested in `lattice/aggregation.py` (Fig. 5, with the selected member public).
   Committing to `V^(j)` and proving the tensor relation is what remains, and it
   needs item 2 before it can be sound.
2. **Tensor/`l`-coefficient trick** (p. 23): prove the first `d/l` coefficients
   of each `y_j` are zero and that the `v` vectors are binary, using the masked
   polynomial `h = g + y_1 + … + y_m` and the multiplicative-relation proof.
3. **Ring transformation** (p. 9): make the verifier see only commitments, not
   `w`, and add the bimodal-Gaussian sign bit `b` as a committed value.
4. **Fiat-Shamir** over the full transcript, with a domain-separated challenge.
5. **Conformance**: the 30 protocol tests in `tests/test_candidate_b_*.py` must
   pass with the lattice backend swapped in behind the same seam.

Each item is days of careful work with the paper open, not hours, and none of it
can be validated by the tests that exist today until item 5 is reachable.

## 6. The transform convention, resolved (2026-11-08)

An earlier revision of this section recorded a blocker: the sum of this
implementation's NTT coefficients is `d * y_0`, while p. 7 states
`g(y) = 32(y_0 + y_1 X + y_2 X^2 + y_3 X^3)`.

p. 6 resolves it. SMILE's `M_q` is **not** `Z_q^d` under a scalar NTT. It is

    R_q = prod_{i=1}^{32} Z_q[X] / (X^4 - r_i)

the CRT splitting of `X^128 + 1` into 32 *quartic* factors, whose constant terms
`r_i` are the roots of `Y^32 = -1`; each slot is `Z_q^4`. The paper's pairing is

    <w, w'> = g( NTT^-1(w) * NTT^-1(w') ),

"the sum of the NTT's" being the sum of the 32 quartic residues. That sum is
`32 * (y_0 + y_1 X + y_2 X^2 + y_3 X^3)` because the power sums of the 32 roots of
`Y^32 + 1` vanish in degrees 1..31 (Vandermonde). So both the "first `d/l`
coefficients" condition and the `q^-4` soundness error are statements about this
decomposition, not about a normalisation choice.

`lattice/subring.py` implements it, and 12 tests assert the properties that make
the recursion meaningful:

| Property | Test |
|---|---|
| 32 distinct `r_i` with `r_i^32 = -1` | `test_there_are_thirty_two_distinct_quartic_factors` |
| `g(y) = 32(y_0 .. y_3)` | `test_g_is_thirty_two_times_the_first_four_coefficients` |
| the slot map is a ring homomorphism | `test_slot_map_is_a_ring_homomorphism` |
| `glue` inverts `slots` (so `NTT^-1` is exact CRT) | `test_slots_and_glue_are_inverse` |
| `<w, w'>` of constant vectors is their scalar dot product | `test_inner_product_of_constant_vectors_is_their_scalar_dot_product` |

**The frontier is now the recursion itself, not a convention.** What remains for
Fig. 6: the `j = 1..m` recursion (`x_{j+1} = P'^T gamma_j`, then `y_j`), the
binary and one-hot constraints on the committed `v_j` ("`v * (1 - v) = 0` and the
NTT coefficients of each polynomial in `v` sum to 1", p. 6, via [1, 15]), and the
quadratic-relation proofs that carry both. That is protocol work against a known
target rather than guesswork.
