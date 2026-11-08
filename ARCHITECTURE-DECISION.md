# Architecture decision: how to reach a Monero-class, post-quantum, device-runnable coin

**Status:** decision record (ADR-001). **Date:** 2026-11-08.
**Supersedes:** the implicit assumption in `PLAN.md` M3 that Candidate A's
monolithic STARK is the route to the goal.

---

## 1. Requirements, in the owner's terms

| ID | Requirement | Test it must pass |
|---|---|---|
| R1 | Anonymity comparable to Monero: hidden sender, hidden recipient, hidden amount, view-key scanning, unlinkability across payments | A written game set (see `PRIVACY-MODEL.md`) that the construction satisfies |
| R2 | Quantum safety against Shor: no elliptic curves, no factoring, no discrete log anywhere in authorization, commitments, nullifiers, encryption, or proofs | Assumption ledger with no ECDLP/RSA dependency |
| R3 | Zero knowledge: the proof hides the witness | A hiding proof system in the shipped configuration, with a stated ZK argument |
| R4 | Runs on ordinary devices: laptop <= 4 GiB peak, phone <= 1 GiB peak, proving in tens of seconds | A measured single-proof peak, not a model |
| R5 | Nodes verify cheaply | Measured verification time |
| R6 | No trusted setup | Transparent proof system |

R2 and R3 are non-negotiable per the owner. R4 is the constraint that decides the
architecture.

## 2. The measured facts that constrain the choice

From `MEASUREMENTS.md` (blowup 2, the pinned *test* FRI configuration):

| Profile | Peak | Time |
|---|---:|---:|
| Path-only proof (`RDXZ64P1`), single proof | 2.49 GiB | 17.9 s |
| Composed spend-side proof (`RDXK64P1`), multi-proof test | 8.61 GiB | 60.0 s |
| Predicted full relation (`RDXL64P1`), 4.0x / 9.5x | 15.3 / 36.3 GiB | not run |

Model predictions for the two optimisations, **corrected 2026-11-08** after the Rust
suite finally ran (`LEAN-RELATION.md` Part B): the real trace width is 14,173, not
14,477/15,629, and the path witness is 1,024 bits, not 8,192. Packing the sibling
saves 480 columns, not ~7,800. The corrected production-blowup predictions are:

| Profile | Peak at production blowup (4x / 9.5x) | Phone 1 GiB | Laptop 4 GiB |
|---|---:|---|---|
| R-fat (RDXL64P1 today) | 27.7 / 65.7 GiB | fails | fails |
| R-lean (no KDF/AEAD) | 8.5 / 20.1 GiB | fails | fails |
| R-lean + packed sibling | 8.0 / 19.0 GiB | fails | fails |
| R-lean + packed + algebraic hash (counterfactual) | 5.2 / 12.3 GiB | fails | fails |
| Path-only floor (measured 2.49 GiB at blowup 2) | 4.9 / 11.7 GiB | fails | fails |

The test blowup of 2 halves every figure; that is how the measured 2.49 GiB floor
fits a 4 GiB laptop. At production parameters it does not.

So: **no single monolithic AIR configuration priced here meets the phone budget, and
none meets the laptop budget at production soundness parameters.** That is not a
tuning problem; it is the row-domain x width x blowup product, with width dominated
by Keccak (2,937 columns) plus the KDF/AEAD banks (5,500).

## 3. Options

| Option | Width direction | Expected phone fit | PQ? | ZK? | Transparent? | Main risk |
|---|---|---|---|---|---|---|
| **A. Monolithic SHAKE STARK** | lean 8,673 / algebraic 5,284 | No (4.9-8.5 GiB at production) | Yes (hash) | Yes (FRI hiding, unproven) | Yes | Fails both device caps at production parameters |
| **B. Lattice linkable ring signature (SMILE-class)** | n/a (no FRI) | **Plausibly yes**: prover is polynomial arithmetic, published ~30 KB proofs for 2-in/2-out | Yes (Module-LWE/SIS) | Yes (lattice ZK) | Yes | Immature; global cross-ring tag uninstantiated; range/conservation proof composition unproven; needs a PQ stealth address |
| **C. Split AIRs + recursive aggregation** | max sub-relation only | Plausible (largest subproof < 1 GiB) | Yes | Yes | Yes (recursive STARK) | No recursion in Plonky3; new stack; composition/soundness work |
| **D. zkVM (RISC Zero/SP1)-style** | program, not AIR | Unlikely on phone (prover ~4-8 GiB) | Yes if STARK-only (Groth16 wrap is not PQ) | Yes | Yes | Phone memory; proof size; dependency risk |
| **E. Algebraic in-circuit hash (Poseidon2/Monolith)** | 5,284 with lean | No (5.2 GiB at production) | Yes (no Shor; Grover only) | Yes | Yes | Changes the consensus hash; younger cryptanalysis; re-vectorises everything |

Verification cost is not the constraint anywhere: measured verification is 25-71 ms,
so full nodes are fine under every option. The constraint is the **spender's device**.

## 4. Decision

**D-ADR-1. The monolithic SHAKE STARK is rejected as the product architecture.**
At production parameters it misses the laptop cap (lean 8.5 GiB) as well as the phone
cap (4.9 GiB for a path-only proof), and the measured floor only fits a laptop at the
test blowup of 2. It remains the credibility baseline (transparent, hash-based,
standard primitives) and the only route with a fully written relation. Rejecting it
as the *product* architecture is not rejecting it as *research*.

**D-ADR-2. Candidate B (lattice linkable ring signature) becomes the primary
architecture for a Monero-class coin**, because it is the only option whose published
economics (tens-of-KB proofs, prover memory dominated by small polynomial
arithmetic) can plausibly reach 1 GiB on a phone while remaining PQ and ZK. It also
matches Monero's actual anonymity model (ring + one-time keys + amount commitments)
rather than replacing it with a global-tree model that needs enormous usage to
provide a large anonymity set.

**D-ADR-3. Option E is the fallback**, not the primary: it is less risky than C or D
but still predicts 5.2 GiB at production parameters, which is over the laptop cap and
far over the phone cap, and it changes the consensus hash. It is only worth doing as
one input to a split/recursive design.

**D-ADR-4. Option C is the escape hatch** if B fails its global-tag requirement and
E cannot fit: split plus recursion keeps hash-based PQ soundness but is a multi-month
build.

**D-ADR-5. No value-bearing launch on any option until the launch gate opens**, and
the gate now refuses a profile that does not declare ZK, transparency, PQ
assumptions, and a <= 1 GiB prover budget (`radix_core/launch.py`).

## 5. What "matches Monero" means, precisely

Monero's privacy is *ring ambiguity + stealth addresses + RingCT*, with a **view key
that can identify your own outputs**. Any claim that an observer holding a view key
must not be able to test outputs is stronger than Monero and is unsatisfiable by any
scan-based design. `PRIVACY-MODEL.md` restates the games in Monero's terms and
re-scopes the project's "recipient key privacy P0" accordingly. Until that review
happens, the honest claim is "Monero-equivalent anonymity *design target*", not
"audited anonymity".

## 6. The experiment that decides B

Before writing a protocol, run the same discipline that produced `LEAN-RELATION.md`:

| Step | Deliverable | Pass rule (pre-registered) |
|---|---|---|
| B1 | SMILE-class parameter sheet transcribed from a pinned paper revision | Every dimension, modulus, noise bound, challenge space and rejection parameter recorded |
| B2 | Prototype 2-in/2-out transaction: OOM/LRS + amount commitments + range + conservation | Proof <= 100 KB, verification <= 100 ms, prover peak <= 1 GiB, proving <= 60 s on phone-class |
| B3 | Global cross-ring tag construction and a written linkability game | Same tag for the same note across arbitrary rings; distinct notes never collide |
| B4 | PQ stealth address for discovery | Recipient indistinguishable from a random address without the view key (Monero-equivalent game G2/G5) |
| B5 | Composition argument: shared witness across tag, ring, amount, range, discovery | One joint proof, no independently-witnessed sub-proofs |

If B2 or B3 fails, fall back to E then C. Do **not** proceed to a protocol spec on a
paper headline; the project already made that mistake once with STARK knobs.

## 7. Honest expectation

- B is a research bet: SMILE-class constructions are not standardized, their
  parameters need independent transcription and review, and the global tag is the
  known open problem.
- Even if B works, a Monero-class coin needs years of node, wallet, P2P, mining,
  audit, and legal work (see `TESTNET-SCOPE.md`).
- "Quantum safe" here means "no known Shor-vulnerable primitive and explicit PQ
  assumptions for every layer". It is not a proof of future safety, and no one can
  honestly claim that.

The next concrete action is B1: transcribe a pinned SMILE revision into a parameter
manifest, then price B2 with the same model used here. That is a paper-and-spreadsheet
task, which is why it can proceed before any linker or prover exists.
