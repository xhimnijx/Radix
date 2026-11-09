---
title: What This Is Not
tags: [honesty, scope]
---

# What this is not

A list of things a reader might reasonably assume, and which are false.

## It is not a cryptocurrency

No token, no network, no peers, no consensus, no economics. The testnet runs one node on
localhost. `radix_core/launch.py` contains the mainnet gate and it is **closed** — it
requires a signed audit manifest that does not exist.

## It is not audited

Two independent cryptographers reviewed the cryptography informally. That is not an
audit. Neither the Rust port, the testnet, nor the app has been reviewed at all.
[[What Reviewers Found]] lists what they did and did not do.

## It is not 128-bit secure

No lattice estimator has been run. The measured margins (~3.6–3.8 bits of root-Hermite
slack) are inputs to that analysis, not its conclusion. `STATUS.md` says: *nothing in
this repository may claim 128-bit security.*

## It is not anonymous in the way Monero is

- The ring is drawn from a pool that, on a fresh chain, is mostly **deterministic
  decoys**.
- Amounts are **visible** and unproven ([[Transactions Outputs and Spends]]).
- One keypair can be spent once, so activity clusters by account
  ([[The Wallet and Its Accounts]]).

The *cryptographic* anonymity of a single spend is real — the verifier learns nothing
about the index — but the system around it is a harness.

## It is not fast enough everywhere

Proving is fast (0.5 s). **Verification is 110 ms on desktop against a 100 ms target**
and has no margin on a phone ([[Performance Measurements]]).

## It is not complete

Missing: amount commitments, range proofs, conservation proofs, one-time addressing, a
fee market, consensus, and networking. [[Status and Honest Limitations]] is the list.

## It is not the first or the best

SMILE is someone else's protocol. This project's contributions are a faithful
implementation, a sound tag extension, a verified Rust port, and an honest evidence
trail. The interesting claim is not "new cryptography" but "verified implementation".

## What it *is*

A working, cross-verified implementation of a published post-quantum private payment
protocol, with a testnet attached, whose parameters have not yet been priced. That
sentence is deliberately narrow because it is the one that survives scrutiny.
