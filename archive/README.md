# Archive

Material from the two tracks that are **not** the active design. Nothing here is
deleted, because the measurements it contains are what justified the current
direction, and a project that hides its dead ends cannot be trusted about its live
ones.

## `candidate-a/`

The original design: a global depth-64 Merkle tree over notes plus a transparent
STARK (Plonky3, BabyBear, FRI) proving a custom transaction relation, with
ML-KEM-768 and AES-256-GCM for the notes.

It was parked after measurement, not after argument. `candidate-a/MEASUREMENTS.md`
and `candidate-a/LEAN-RELATION.md` record the numbers: a path-only proof peaks at
2.49 GiB / 17.9 s at the *test* blowup, and the composed transaction at 8.61 GiB /
60 s; at production blowup the floor is 4.9 GiB and the lean variant 8.5 GiB,
against a 4 GiB desktop budget and a 1 GiB phone budget. The relation is simply too
large to prove on the hardware the project promised.

What still lives in the main tree from that era, because Candidate B needs it:

- the canonical codecs, hashes, providers, wallet keystore and Merkle machinery in
  `radix_core/`;
- the mainnet launch gate in `radix_core/launch.py`, which is closed and stays
  closed;
- the audit and security records at the repository root.

Contents: the Candidate-A specification and review documents, the protocol draft,
the gate records, the measurement logs, the standalone reference scripts, and the
Rust `proof_harness/` that produced the numbers. The harness still builds and its
non-ignored tests still run in CI — archived code that nobody checks is archived
code that lies.

## `candidate-c/`

`AKITA-ASSESSMENT.md`: the 2026 lattice polynomial commitment scheme (Akita),
evaluated as a way to remove the FRI blowup. It cannot be dropped into Candidate A
(a univariate FRI PCS versus a multilinear one), so using it would mean Candidate
C: the Candidate-A relation as a Rust guest under the Jolt zkVM, with Akita as the
PCS.

It was archived as the designated fallback. `ROADMAP.md` states the three
conditions that would re-open it.

## Reading order, if you are new

1. `../PLAIN-ENGLISH.md` — what the project actually has.
2. `../ROADMAP.md` — where it is going.
3. `candidate-a/MEASUREMENTS.md` and `candidate-a/LEAN-RELATION.md` — why the first
   design was abandoned.
4. `candidate-c/AKITA-ASSESSMENT.md` — why the fallback exists.

## A note on the references inside these documents

They cite each other, and files at the repository root, by bare name - which is
where they lived when they were written. Resolve those names against the
repository root as it was, not against this folder.
