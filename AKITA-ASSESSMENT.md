# Akita integration assessment

**Status:** assessment complete; **decision: Candidate C is archived as the primary
fallback, and Candidate B remains the active path.** **Date:** 2026-11-08.
**Source:** `studies/2026-1983.pdf` - *Akita: A High-Performance Lattice-Based
Polynomial Commitment Scheme* (Dao, Bodaghi, Khajehpour, Vitto et al., 2026).
Page references are to that PDF.

---

## 1. What Akita is - and what it is not

Akita is a **polynomial commitment scheme (PCS)**, not a proof system for a
transaction. It commits multilinear polynomials over a prime field, with proofs of
58-68 KB, verification under 20 ms even at 2^35 bits committed (p. 6, p. 117), and
the smallest measured prover memory of the lattice PCSs compared (4.37 GiB at the
largest input, versus 92.6 GiB for Greyhound, p. 117). Security rests on standard
Module-SIS, so it is post-quantum.

A transaction proof still needs everything above the PCS: an arithmetisation of the
relation and a multilinear PIOP (sumcheck-based). The paper's own deployment answer
is **Jolt**, a RISC-V zkVM, where Akita replaces Dory as the commitment backend.

## 2. Does it integrate with the current Candidate A?

**No, not as a component swap.** Candidate A's proof harness is a Plonky3
*univariate* STARK over BabyBear with `TwoAdicFriPcs` and a FRI low-degree test.
Akita is a *multilinear* PCS with a different commitment interface and no FRI. The
RDXL AIR and its `Pcs`/`FriParameters` plumbing cannot be pointed at Akita; using
Akita means replacing the proof system underneath, i.e. rebuilding the relation.

So the only realistic integration is the paper's: **write the relation as a RISC-V
guest program and prove it with Jolt + Akita.** That is a different architecture,
not a Candidate-A patch - which is exactly the situation in which the brief says to
consider labelling it Candidate C.

## 3. Candidate C, defined

> **Candidate C** = the Candidate-A *relation* (global note tree, hash commitments,
> nullifiers, integer balance) written as a Rust guest program, proved by a
> Jolt-style zkVM with the Akita PCS.

What it keeps: post-quantum security (Module-SIS plus hash commitments, no
elliptic curves), zero knowledge, and the **global anonymity set** rather than a
16-member ring.
What it adds: a dependency on Jolt and on a 2026 PCS implementation, and the
zkVM's cycle cost instead of a bespoke circuit.

## 4. The numbers that decide it

From the paper's Jolt end-to-end table (p. 119, Table 7, Apple M4 Max, SHA-256
chains), Jolt-with-Akita:

| Padded trace | Prove | Verify | Proof | Peak RAM |
|---:|---:|---:|---:|---:|
| 2^17 | 0.33 s | 8.3 ms | 81.8 KB | 0.30 GiB |
| 2^19 | 0.59 s | 11.5 ms | 84.4 KB | 0.45 GiB |
| 2^21 | 1.73 s | 13.3 ms | 88.7 KB | **1.06 GiB** |
| 2^23 | 5.55 s | 19.3 ms | 90.0 KB | 1.97 GiB |
| 2^25 | 20.7 s | 23.3 ms | 91.5 KB | 6.43 GiB |
| 2^27 | 75.1 s | 24.9 ms | 93.6 KB | 24.37 GiB |

Memory is roughly linear in trace length: **about 1 GiB at 2^21 cycles**, 6.4 GiB at
2^25. That is the whole argument in one table: for a zkVM, prover memory is set by
the **trace**, not by the PCS.

Estimated trace length for one shielded transfer (assumption, flagged as such):
a depth-64 path is ~128 Keccak-f permutations; a note commitment, nullifier, output
leaf and KDF add a handful more, so ~140 permutations. At an optimistic
2,000-4,000 RISC-V cycles per permutation (the paper's benchmark is SHA-256, which
Jolt may accelerate; Keccak is not precompiled), that is **0.3-0.6 M cycles**, i.e.
padded T ~2^19-2^20, so **0.5-1.0 GiB and 0.6-1.7 s on a fast desktop**, and several
times that on a phone.

## 5. Scorecard against the stated requirements

Weights reflect the brief: PQ and ZK are non-negotiable; "runs on most devices" is
the binding constraint; Monero-like anonymity is the goal.

| | A (monolithic STARK) | B (SMILE ring signature) | C (Jolt + Akita) |
|---|---|---|---|
| Post-quantum | yes (hash/FRI) | yes (Module-LWE/SIS) | yes (Module-SIS) |
| Zero knowledge | unproven | lattice ZK | zkVM + PCS |
| Anonymity model | global set, formally strongest | ring (2^15 achievable) | **global set** |
| Proof size | ~300 KB | **30 KB** (paper, 2-in/2-out) | 82-94 KB |
| Prover RAM | 4.9-36 GiB | **kilobytes-megabytes** | ~1 GiB at 2^21, 6.4 GiB at 2^25 |
| Prover time | minutes, measured | milliseconds-seconds | 0.6-1.7 s at 2^20 (desktop) |
| Verification | 25-71 ms | ~100 ms target | 8-25 ms |
| Custom crypto to build | large AIR | **large bespoke protocol** | smaller: a Rust program |
| Dependency maturity | Plonky3, mature | SMILE paper, no code | **Jolt + 2026 PCS, research** |
| Fits the 1 GiB phone cap | no | **yes, by orders of magnitude** | marginal-to-no once the trace grows |

## 6. Verdict

**C is clearly better than A** - it fixes exactly what A failed on (FRI's 4 GiB LDE
floor) while keeping PQ, ZK and the stronger global anonymity set.

**C versus B is a real trade-off, not a rout:**

- C wins on anonymity model (global set versus a 16-member ring) and on how much
  *custom cryptography* must be written: a Rust guest program is far easier to audit
  than a bespoke lattice sigma-protocol.
- B wins decisively on the binding constraint. Its prover works in a ring of
  dimension 128 and needs kilobytes to megabytes; C needs ~1 GiB at 2^21 cycles and
  grows linearly. A phone at 1 GiB is right at C's cliff, and any 4x underestimate in
  cycle count moves C to 2-6 GiB.

Given that "easy to run on most devices" is the requirement that killed Candidate A,
choosing the architecture that is *marginal on that requirement* over one that is
**comfortable by three orders of magnitude** would repeat the mistake. Therefore:

**D-C-1. Continue with Candidate B.**
**D-C-2. Candidate C is the designated fallback**, ahead of the algebraic-hash and
split-recursion options, and is the better home for the global-tree relation if B's
global-tag or parameter review fails.
**D-C-3. Re-open C if either** (a) a measured Jolt guest for one transfer lands under
2^20 cycles with peak RSS < 512 MiB, or (b) SMILE review fails. Both are concrete
triggers, not vibes.
**D-C-4. Do not run B and C in parallel.** The repository has one maintainer-shaped
budget; parallel tracks are how the first half of this project became unbuildable.

## 7. What this assessment does *not* claim

- That Akita is production-ready: it is a 2026 research PCS with a Rust
  implementation; the Jolt numbers are on an M4 Max, not a phone.
- That the cycle estimate is measured: it is an assumption (2,000-4,000 cycles per
  Keccak permutation, ~140 permutations), and it is the single number most worth
  falsifying early.
- That C would pass the launch gate: it still needs a ZK argument, a review, and a
  device measurement under the gate's declared 1 GiB budget.
