---
title: Commitments and Zero Knowledge
tags: [protocol, foundations]
---

# Commitments and zero knowledge

A commitment is a sealed envelope: you lock a value in, publish the envelope, and
later open it. It must be **binding** (you cannot change the value) and **hiding**
(nobody learns it early).

## BDLOP commitments

Radix uses the BDLOP construction. With a public matrix `B` and a public row `b`:

$$\text{commit}(m;\, r) = \big(t,\; u\big) = \big(B r,\; \langle b, r\rangle + m\big)$$

where `r` is a short random vector (the *opening*).

- **Hiding:** `B r` and `⟨b,r⟩` look uniform because `r` is unknown (M-LWE).
- **Binding:** two openings of the same `m` would give `B(r − r') = 0` with a short
  difference — a short solution to SIS. So binding reduces to SIS.

Implemented in `bdlop.py`; the Rust port `bdlop.rs` matches its commitment digest
exactly (`8ef836b5…`).

## Additive homomorphism

Commitments add:

$$\text{commit}(m_1; r_1) + \text{commit}(m_2; r_2) = \text{commit}(m_1 + m_2;\, r_1 + r_2)$$

This is what lets one commitment cover many messages at once, which is how a single
randomness `r` commits to the 20+ values in the set-membership proof. Verified in
`bdlop.rs::commitments_are_additively_homomorphic`.

## The masked opening

You cannot reveal `r` (it opens the commitment), but you can reveal `z = y + c·r`:
a masked version. The verifier checks

$$\langle b, z\rangle - c\,u = \langle b, y\rangle - c\,m$$

The commitment's `r` cancels, leaving only the message and the mask — and the mask is
what hides `r`. This is the identity tested symbolically in
`quadratic.rs::a_masked_response_equals_dot_minus_challenge_times_commitment`.

## Why zero knowledge needs a challenge

Without a challenge, the prover could choose `z` first and invent a matching
"commitment". The challenge `c` is chosen by the verifier **after** the commitments are
fixed, so the prover cannot work backwards.

Since there is no interactive verifier, the challenge is derived from a hash of the
transcript — [[Fiat-Shamir and the Transcript]].

## Soundness intuition

If a prover could answer two *different* challenges `c₁ ≠ c₂` for the same commitment,
then subtracting the two answers extracts the witness:

$$z_1 - z_2 = (c_1 - c_2)\,r \;\Longrightarrow\; r = (z_1 - z_2)(c_1 - c_2)^{-1}$$

That division is exactly why `c₁ − c₂` must be a unit — [[Challenge Spaces and Ternary
Secrets]] and the modulus decision in [[The NTT and the Quartic Decomposition]].

This is the **special soundness** property, and it is the engine of the whole security
proof.

## The vector version used in the proof

The proof commits to many things at once under one randomness `r` of width
`W = κ + λ + rows + 2m + 1 = 29` (or `33` with tags). One row of `B` per message.
That is `VectorCommitment` in `bdlop.py` and the commitment vector in the proof.

## Next

[[The Set Membership Proof]] — commitments put to work on "I own one of 1024 keys".
