# Radix wiki

**A post-quantum, privacy-preserving payment protocol — research prototype.**

> **Not a cryptocurrency. No value. No security claim. Not audited.**
> The mainnet gate is closed by design.

Radix implements [SMILE (ePrint 2021/564)](https://eprint.iacr.org/2021/564) — a
lattice-based ring signature with set membership — and builds a complete local testnet
around it. The prover and verifier exist twice, in Python and in Rust, and **each
verifies the other's proofs**.

## Pages

- **[Getting Started](Getting-Started)** — install, run, send a transaction
- **[Architecture](Architecture)** — what each component does
- **[FAQ](FAQ)** — the questions people actually ask
- **[Roadmap](Roadmap)** — what mainnet would require
- **[Development](Development)** — contributing, tests, where to look

## The claim that matters

> A proof produced by the Rust prover is accepted by the Python verifier, and a proof
> produced by the Python prover is accepted by the Rust verifier.

Both directions are tested; fixtures are committed.

## Where the real documentation is

The **[vault](../vault/)** in the main repository: 38 notes taking a reader with A-Level
Maths and Further Maths up to the protocol internals. The wiki is an entry point, not a
replacement.
