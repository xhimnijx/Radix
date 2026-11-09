---
title: The Problem
tags: [concept, introduction]
---

# The problem

A normal cryptocurrency transaction says: *this money moves from address A to
address B*. That is easy to verify and terrible for privacy — the entire history of
who paid whom is public forever.

A private cryptocurrency wants a transaction to say something much weaker:

> "I know the secret behind **one** of these 1024 public keys, and I am spending it
> exactly once, and the money balances."

while revealing **none** of: which key, how much each input held, or who is
involved.

That is a *zero-knowledge proof of a statement*, and the rest of this vault is about
how to construct one that is also:

| Requirement | Why | How Radix does it |
|---|---|---|
| **Quantum-resistant** | Shor's algorithm breaks elliptic-curve and RSA cryptography | Lattice problems, which have no known efficient quantum algorithm |
| **Private** | Sender, receiver, amount and link between transactions hidden | Ring signature + commitments |
| **Unlinkable but double-spend-proof** | Two spends of one coin must be detectable, without revealing which coin | A *linkable tag* derived from the secret |
| **Runs on commodity devices** | A phone, not a server | ~500 ms to prove, ~110 ms to verify, 32 KB proofs |

## Why this is genuinely hard

Three separate problems collide:

**1. Quantum resistance rules out the easy tools.** Elliptic curves give you compact
signatures and Diffie–Hellman key exchange; Shor's algorithm destroys both. Lattice
schemes replace them, but a lattice public key is ~2 kB rather than 32 bytes, and a
lattice signature is ~32 kB rather than ~2 kB. Everything gets bigger, so every
inefficiency costs real bytes and real milliseconds.

**2. Anonymity fights double-spend detection.** If a signature hides which key it
opens, a node cannot tell a second spend of the same coin from a different coin being
spent. You need something that identifies the *coin* without identifying the *spender
or the link to its history*. The answer is a tag `T` that is a deterministic function
of the secret and nothing else — so the same coin always produces the same `T`, but
`T` reveals nothing about which key it came from.

**3. Zero knowledge is not free.** Every value the prover reveals (masks, responses,
commitments) is a chance to leak information. The standard tool is a *masked
response*: add a large random value, then convince the verifier the result is still
correct. Get the mask too small and the response leaks the secret; get it too large
and the proof becomes big and slow. Chapter [[Norms and Why They Matter]] is entirely
about this trade.

## The specific thing Radix implements

It implements **SMILE** (ePrint 2021/564), a lattice ring signature with set
membership: you prove membership in a set of `l^m` keys using `m` levels of a
tensor-recursion, so a 1024-key ring costs about the same as a 32-key one rather than
1024 proofs.

On top of that, this project adds:

- a **linkable tag** built as a same-witness extension ([[Linkable Tags]]);
- a complete **testnet**: chain, node, miner, wallet, CLI, GUI, packaging;
- a **Rust port** of the entire prover and verifier, cross-verified against the
  Python reference in both directions ([[How the Port Was Verified]]).

## What makes this honest

The interesting part of the project is not that it works — it does — but that every
claim is tied to evidence and every gap is named. See
[[Claim to Evidence Map]] and [[What Reviewers Found]].

## Next

[[Modular Arithmetic and the Ring R_q]] — the one algebraic object everything is
built on.
