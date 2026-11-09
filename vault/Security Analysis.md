---
title: Security Analysis
tags: [security, mathematics]
---

# Security analysis

What is being claimed, what each property requires, and the exact size of every number.
This note is a map of the argument, **not** a proof — the proof is in the paper and in
`REVIEW-FINDINGS.md`.

## The three properties

### Completeness

An honest prover with a valid witness is always accepted. Evidence: the real-proof
tests (`test_candidate_b_setmembership.py`), and the fact that both implementations
accept each other's proofs ([[How the Port Was Verified]]).

### Soundness

A prover without a witness cannot produce an accepted proof, except with negligible
probability.

The argument is **special soundness**: if a prover answers two different challenges
`c₁ ≠ c₂` to the same commitment, the answer is extractable:

$$z_1 - z_2 = (c_1 - c_2)\,r \;\Rightarrow\; r = (z_1 - z_2)(c_1 - c_2)^{-1}$$

Two things must hold for this:

1. **`c₁ − c₂` must be a unit in `R_q`.** At the chosen modulus every slot is a field,
   so this fails with probability `~2^-123` rather than `~2^-24.4`
   ([[The NTT and the Quartic Decomposition]]).
2. **The extracted witness must be the right shape.** `v(v−1) = 0` must force a 32-entry
   binary vector. It does, because slots are fields ([[The Set Membership Proof]]).

The extraction is then bounded by **M-SIS** at the target `2β′` (and `8dβ` for the
commitment rows). Those are the numbers in [[Hard Problems on Lattices]].

### Zero knowledge

The transcript is simulatable: given only the statement, a simulator can produce
anything the honest prover produces. The masking is the engine:

- masks are Gaussian with width `s ≈ 1.57·‖c·s‖`, calibrated so that `z` is
  statistically independent of `s`;
- rejection sampling (`Rej1`) keeps the output distribution correct at that width;
- the verifier's only check on `z` is the ℓ₂ bound `‖z‖₂ ≤ β`.

> [!warning] The known gap
> The Gaussian is **continuous-then-rounded**, not discrete. Lemma A.6 is stated for a
> discrete Gaussian; the difference is `O(1/s) ≈ 2^-11`. Negligible, but not the same
> object. [[Status and Honest Limitations]].

## The numbers, in one table

| Quantity | Value | Notes |
|---|---|---|
| challenge-difference failure | `~2^-123` | field regime; was `~2^-24.4` split |
| unit-check failure (both challenges) | `~2^-123` | two checks per proof |
| `β` (response bound, `z`) | `2^17.9` | measured calibration |
| `β′` (response bound, `z′`) | `2^16.6` | measured calibration |
| M-SIS target, `A` relation | `2β′ ≈ 2^17.6` | extractor subtracts two responses |
| M-SIS target, commitment rows | `8dβ ≈ 2^27.9` | paper's Lemma C.1 bound |
| reachable norm at `δ = 1.0042` | `2^21.2` / `2^31.7` | heuristic |
| margin | ~3.6 bits / ~3.8 bits | **root-Hermite slack, not a security level** |
| proof size | 32,512 B | 38,656 B tagged |

## What is *not* established

- **No estimator run.** The margins are heuristic inputs, not a conclusion.
- **No composition theorem.** The pieces are the paper's lemmas; their combination in
  this code is reviewed, not proved.
- **No audit.** Two informal reviews; see [[What Reviewers Found]].

## The honest sentence

Soundness rests on M-SIS being hard at the stated targets, and zero knowledge rests on
the mask being wide enough. Both are engineered correctly *for the parameters chosen*;
neither has been priced by an estimator, so neither can be called a security level yet.

## Next

[[Status and Honest Limitations]] for the summary a supervisor should read.
