---
title: Radix — Start Here
tags: [moc, index]
---

# Radix: a privacy-preserving, quantum-resistant cryptocurrency

This vault explains, from A-Level mathematics upwards, how Radix works: what each
piece does, why it is built that way, and **what has actually been verified versus
what is only claimed**.

> [!warning] Read this first
> Radix is a **research prototype**. It has no value, is not deployed, and makes no
> security claim. Two independent cryptographers reviewed it and found real defects;
> those are documented in [[What Reviewers Found]] rather than hidden. The honest
> summary is in [[Status and Honest Limitations]].

## Where to start

If you have A-Level Maths and Further Maths, read in this order:

1. [[The Problem]] — what a privacy cryptocurrency has to do, and why it is hard.
2. [[Modular Arithmetic and the Ring R_q]] — the one algebraic object everything
   else is built on.
3. [[Polynomials as Vectors]] — how a 128-coefficient polynomial becomes a lattice
   point, and why that is useful.
4. [[Hard Problems on Lattices]] — the two problems whose difficulty is the entire
   security argument.
5. [[Commitments and Zero Knowledge]] — how to prove a statement without revealing
   the witness.
6. [[The Set Membership Proof]] — the heart of the system: proving "I own one of
   1024 keys" without saying which.
7. [[The Recursion]] — how 1024 keys are handled without 1024 separate proofs.
8. [[Transactions Outputs and Spends]] — how the proof becomes money.
9. [[The Chain]] — blocks, state, the node, the miner.
10. [[Security Analysis]] — soundness, zero knowledge, and the exact size of every
    number involved.

## The map

### The idea
- [[The Problem]]
- [[Design Decisions and Why]]
- [[What This Is Not]]

### Mathematics
- [[Modular Arithmetic and the Ring R_q]]
- [[Polynomials as Vectors]]
- [[The NTT and the Quartic Decomposition]]
- [[Hard Problems on Lattices]]
- [[Challenge Spaces and Ternary Secrets]]
- [[Norms and Why They Matter]]

### The protocol
- [[Commitments and Zero Knowledge]]
- [[The Set Membership Proof]]
- [[The Recursion]]
- [[Fiat-Shamir and the Transcript]]
- [[Linkable Tags]]
- [[The Wire Format]]

### The money
- [[Transactions Outputs and Spends]]
- [[The Chain]]
- [[The Node and Miner]]
- [[The Wallet and Its Accounts]]

### Security
- [[Security Analysis]]
- [[What Reviewers Found]]
- [[Status and Honest Limitations]]
- [[The Parameters and Where Every Number Comes From]]

### Engineering
- [[The Python Reference]]
- [[The Rust Port]]
- [[The Rust Backend Seam]]
- [[How the Port Was Verified]]
- [[Performance Measurements]]
- [[Packaging and Distribution]]

### For lecturers
- [[Evidence Pack - Overview]]
- [[Claim to Evidence Map]]
- [[Test Inventory]]
- [[Reproducing Everything]]
- [[Reading List]]

### Reference
- [[Glossary]]
- [[Parameter Sheet]]
- [[File and Commit Index]]

---

*Every note states its sources: either a file in this repository, a measurement
recorded in it, or a published paper. Where a number is a projection rather than a
measurement, the note says so.*
