---
title: Glossary
tags: [reference]
---

# Glossary

Every symbol and term used in this vault, with a one-line definition and where it is
explained properly.

## Algebraic objects

| Term | Meaning |
|---|---|
| `Z_q` | Integers modulo the prime `q`; a field |
| `R_q` | `Z_q[X]/(X^128 + 1)`; polynomials reduced negacyclically |
| **negacyclic** | Reduction rule `X^128 = -1`, so high powers wrap with a sign flip |
| **slot** | One of the 32 residues `y mod (X^4 − r_i)` of a polynomial |
| **quartic CRT** | Reconstructing a polynomial from its 32 slot residues |
| **NTT** | Number Theoretic Transform; evaluation at roots of unity, exists only at split moduli |
| `ord_256(q)` | Multiplicative order of `q` mod 256; decides the factorisation regime |
| **idempotent** | An element with `e² = e`; in a field there are only 0 and 1 |
| **unit** | An invertible element; in a field every nonzero element is one |
| **zero divisor** | A nonzero element that cannot be inverted |

## Protocol

| Term | Meaning |
|---|---|
| **witness** | The secret the prover knows (`s`, the index) |
| **statement** | What is being proven (`A·s = pk_ι` for some `ι`) |
| **commitment** | A sealed envelope to a value; hiding + binding |
| **BDLOP** | The commitment scheme used: `(B r, ⟨b,r⟩ + m)` |
| **challenge** | The verifier's random value; here derived by hashing |
| **Fiat–Shamir** | Replacing an interactive challenge with a hash of the transcript |
| **transcript** | The ordered log of everything absorbed before a challenge |
| **masking** | Adding a large random `y` so the response hides the secret |
| **rejection sampling** | Retrying until the masked response passes a test, to keep its distribution correct |
| **`Rej1`** | The bimodal rejection rule that halves the needed mask width |
| **`β`, `β′`** | The ℓ₂ bounds the verifier checks on the two responses |
| **tag** | `T = A'·s`; a per-key value that makes a double spend detectable |
| **same-witness extension** | Proving the tag inside the existing proof by adding rows, not a second proof |
| **`k′`** | Number of tag rows; 4 in this project |
| **ring** | The 1024 public keys one spend hides among |
| **anchor** | The block hash a spend was built against; prevents replay |

## Lattice

| Term | Meaning |
|---|---|
| **lattice** | All integer combinations of a set of basis vectors |
| **SIS** | Short Integer Solution: find a short vector in the kernel |
| **LWE** | Learning With Errors: recover `s` from `As + e` |
| **M-SIS / M-LWE** | The module versions, over `R_q` instead of `Z_q` |
| **ℓ₂ norm** | `sqrt(Σ v_i²)`; the length used for bounds |
| **infinity norm** | `max(|v_i|)`; the wrong choice for this verifier |
| **centred representative** | The representative in `(-q/2, q/2]`; `q−1` means `−1` |
| **root-Hermite factor `δ`** | A measure of lattice-reduction quality |
| **Core-SVP** | A model converting block size to an attack cost |
| **estimator** | Software that computes those costs; **not yet run here** |

## Testnet

| Term | Meaning |
|---|---|
| **output** | Money addressed to a public key (key + value) |
| **spend** | Inputs, outputs, fee, signatures, tags |
| **ring pool** | The set of keys a ring can be drawn from |
| **decoy** | A pool key that is not the signer's |
| **account** | One keypair in the wallet; spendable once because its tag is per key |
| **backend** | `python` (reference, slow) or `rust` (ported, fast) |
| **seam** | `prover.py`, the only place the backend choice is made |

## Notation used in this vault

| Symbol | Meaning |
|---|---|
| `k, ℓ` | Matrix height and width: 4 and 13 |
| `κ, λ, μ` | 10, 10, 5 (commitment rows, extra masks, secret bound) |
| `m` | Recursion depth; ring size `32^m` |
| `W` | Width of `r`, `y`, `z`: `κ + λ + rows + 2m + 1` |
| `d` | Ring degree, 128 |
| `l` | Subring dimension, 32 |
