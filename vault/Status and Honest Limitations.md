---
title: Status and Honest Limitations
tags: [honesty, status]
---

# Status and honest limitations

The one-page summary a supervisor should read. Everything here is also stated in the
repository's `STATUS.md`, and none of it is softened for presentation.

## What this is

A **research prototype** of a post-quantum, privacy-preserving cryptocurrency:

- a Python reference implementation of SMILE (ePrint 2021/564) with a same-witness
  linkable tag;
- a complete local testnet (chain, node, miner, wallet, CLI, GUI);
- a Rust port of the entire prover and verifier, cross-verified in both directions;
- a packaged desktop app.

## What this is not

> [!danger] Not a cryptocurrency
> No value. No consensus. No peer-to-peer network. No audit. The mainnet gate in
> `radix_core/launch.py` is closed by design and requires a signed audit manifest that
> does not exist.

> [!danger] No security claim
> Not "128-bit secure". Not "secure". The parameters have **not** been priced by a
> lattice estimator, and until they are, no security level may be asserted. The
> measured margins (~3.7 bits of root-Hermite slack) are inputs to that analysis, not
> its conclusion.

## The open items, in order of importance

| # | Item | Why it blocks a claim |
|---|---|---|
| 1 | **Lattice estimator run** | The only thing between "the proof verifies" and "the parameters are secure". Needs `(q, d, ℓ, k, κ, λ, μ, β, β′)` fed to an estimator such as `lattice-estimator`, with the results interpreted by someone qualified. |
| 2 | **Discrete Gaussian sampler** | The mask rounding is `O(1/s)` from the paper's distribution. Negligible at `s ~ 2^11`, but not the same object. |
| 3 | **Theorem B.1 restatement** | The paper's own analysis is written for the split modulus. Adopting the irreducible modulus moves outside it; the analysis must be redone with field residues. Expected to come out better, but it is unproven. |
| 4 | **Verification performance** | 110 ms on desktop against a 100 ms target. Batch verification is the likely fix and is unmeasured. |
| 5 | **One-time addressing (B2)** | Without it a wallet can spend each key once, so change moves between accounts rather than to fresh keys. |

## Deliberate simplifications in the testnet

These are stated in `TESTNET.md` too:

- **No persistence of trust.** The chain file is trusted on load and not re-verified.
- **The faucet seed is a public constant.** Anyone running the harness can spend the
  same units. This is why there is no encrypted keystore: encrypting a seed printed in
  the source would imply a property the harness does not have.
- **Trivial proof of work** (`POW_BITS = 10`) for block shape, not security.
- **Deterministic parameters** so node, wallet and tests agree; a real deployment takes
  a reviewed manifest.
- **No one-time addresses**, so outputs are addressed directly to a public key.

## What *is* solidly established

To balance the list above, these are not hedged:

- The cryptographic transcription is correct and was confirmed by two reviewers.
- The Python and Rust implementations agree on **actual proofs**, in both directions.
- Every layer of the port has a known-answer test from the reference.
- The real defects found in review are fixed, with regression tests.
- The performance numbers are measured on a named machine with the build settings
  recorded.

## The one-sentence version

*"A faithful, cross-verified implementation of a published lattice protocol, with a
working testnet attached, whose parameters have not yet been priced."*

That sentence is the whole project. Anything beyond it would be an overclaim.
