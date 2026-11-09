---
title: Reading List
tags: [lecturers, references]
---

# Reading list

What to read to check this work, in order of usefulness.

## Primary

**SMILE: Set Membership from Ideal Lattices with Applications to Ring Signatures and
Confidential Transactions** — ePrint 2021/564.
The protocol this project implements. Figures 7–9 are the prover, recursion and
verifier; the parameter table is §6; the security argument is in the appendices.

Read it with one correction: the `e₁` term in Fig. 9 line 12 is printed at order `c`
but must be at order `c²` for the honest prover's check to pass ([[What Reviewers
Found]], Q2). The code follows the correct version.

## Background, if lattices are new

- **Regev, "On lattices, learning with errors, random linear codes, and
  cryptography"** — the original LWE paper; the hardness assumption behind the
  commitments.
- **Ajtai, "Generating hard instances of lattice problems"** — the original SIS
  problem.
- **BDLOP** (Baum, Damgård, Lyubashevsky, Oechsner, Peikert) — the commitment scheme
  used here, and the source of the quadratic-relation technique.
- **Lyubashevsky, "Lattice signatures without trapdoors"** — rejection sampling and the
  Fiat–Shamir-with-aborts paradigm, which is why the prover retries.

## Practical cryptography

- **"CRYSTALS-Dilithium"** and **"CRYSTALS-Kyber"** specifications — the NIST
  post-quantum standards; useful for comparing parameter choices and code sizes.
- **Albrecht et al., "Estimate all the LWE, NTRU schemes!"** and the
  `lattice-estimator` tool — what would be needed to price these parameters.

## Context

- **Monero's ring signature and key-image design** — the closest deployed system
  conceptually, and the source of the "who is the double spend detected without
  revealing the spender" problem.
- **Zcash's Sprout/Sapling** — the other major privacy design; useful contrast between
  transparent-circuit proofs and the algebraic approach taken here.

## What is *not* required reading

The archived Candidate-A material (`archive/candidate-a/`) is a STARK-based design that
was abandoned; it is kept for the record and is not part of this work.

## How to read this project alongside the paper

| Paper | This vault | Code |
|---|---|---|
| Fig. 7 (prover) | [[The Set Membership Proof]] | `setmembership.prove` |
| Fig. 8 (recursion) | [[The Recursion]] | `recursion.py` |
| Fig. 9 (verifier) | [[The Set Membership Proof]] | `setmembership.verify` |
| §6 (parameters) | [[The Parameters and Where Every Number Comes From]] | `params.py` |
| Appendix B (soundness) | [[Security Analysis]] | `REVIEW-FINDINGS.md` |
| Appendix C (masking) | [[Norms and Why They Matter]] | `experiments/mask_calibration.py` |
