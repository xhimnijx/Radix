---
title: Evidence Pack — Overview
tags: [lecturers, evidence]
---

# Evidence pack — overview

This section exists for one purpose: to let an academic check the claims in this
project without taking any of them on trust.

The project is a **research prototype of a post-quantum private cryptocurrency**,
written from a published protocol (SMILE, ePrint 2021/564), plus a complete local
testnet and a cross-verified Rust implementation.

## The four things a lecturer should ask, and where each is answered

| Question | Answer |
|---|---|
| Is the cryptography real or hand-waved? | [[Claim to Evidence Map]] maps every claim to a file, a test or a measurement. |
| Is the code actually tested? | [[Test Inventory]] lists every test and what it verifies. |
| Can I reproduce it? | [[Reproducing Everything]] gives exact commands and expected output. |
| Is the author overselling? | [[Status and Honest Limitations]] and [[What Reviewers Found]] document the defects, including ones an independent reviewer found and the author missed. |

## The shape of the evidence

There are four kinds of evidence in this project, and they are deliberately kept
distinct:

1. **Known-answer tests.** A value produced by one implementation is reproduced by
   another. Example: the BDLOP commitment digest `8ef836b5977e51188c10faf77e096625`
   matches between Python and Rust.
2. **Property tests.** A claimed property is checked symbolically rather than for one
   input. Example: the masked response identity `⟨b,z⟩ − c·u = ⟨b,y⟩ − c·m` is verified
   for arbitrary inputs.
3. **Cross-implementation acceptance.** A proof produced by one implementation is
   accepted by the other. This is the strongest check, because two implementations
   cannot agree by accident on a 32 KB object.
4. **Measurements.** Timings and sizes, recorded with the machine and build settings.

## The strongest single result

> A proof produced by the **Rust** prover is accepted by the **Python** verifier, and a
> proof produced by the **Python** prover is accepted by the **Rust** verifier.

Both directions pass. The fixtures and scripts are committed:
`experiments/produce_python_proof.py`, `proof_rust/src/bin/emit_proof.rs`,
`experiments/verify_rust_proof.py`, `proof_rust/tests/python_proof.rs`.

This is the check that distinguishes "the port compiles" from "the port is correct".

## What is *not* evidence, and is not claimed

- **No security proof of the composition.** The individual lemmas are from the paper;
  the composition is `REVIEW-FINDINGS.md`, not a theorem.
- **No estimator run.** The parameters have not been priced by a lattice estimator.
  See [[Status and Honest Limitations]].
- **No audit.** Two cryptographers reviewed this informally and found real bugs; that
  is not an audit and is not presented as one.
- **No deployment.** There is no network, no value, and `radix_core/launch.py` refuses
  to open the mainnet gate by design.

## How to read the honesty

The most convincing part of this pack is not the list of things that work. It is
[[What Reviewers Found]]: a list of defects **found by independent reviewers**, one of
which the author had reproduced *before* the reviewer did, and two of which were found
in the author's own reasoning by the reviewer who had originally proposed them.

A project that shows you its bugs is more trustworthy than one that shows you only its
tests.
