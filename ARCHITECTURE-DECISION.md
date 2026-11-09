# Architecture decision: how to reach a Monero-class, post-quantum, device-runnable coin

**Status:** decision record (ADR-001). **Date:** 2026-11-08.
**Supersedes:** the implicit assumption in `archive/candidate-a/PLAN.md` M3 that Candidate A's
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

From `archive/candidate-a/MEASUREMENTS.md` (blowup 2, the pinned *test* FRI configuration):

| Profile | Peak | Time |
|---|---:|---:|
| Path-only proof (`RDXZ64P1`), single proof | 2.49 GiB | 17.9 s |
| Composed spend-side proof (`RDXK64P1`), multi-proof test | 8.61 GiB | 60.0 s |
| Predicted full relation (`RDXL64P1`), 4.0x / 9.5x | 15.3 / 36.3 GiB | not run |

Model predictions for the two optimisations, **corrected 2026-11-08** after the Rust
suite finally ran (`archive/candidate-a/LEAN-RELATION.md` Part B): the real trace width is 14,173, not
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
| **F. Candidate C: lattice PCS (Akita) + zkVM** | hash-circuit no longer dominates | **Plausible but marginal**: 82-94 KB Jolt proofs, ~1 GiB at 2^21 cycles, 6.4 GiB at 2^25 | Yes (Module-SIS) | Yes | Yes | Akita is a PCS, not a transaction proof; Jolt + 2026 PCS maturity; trace memory is the binding cost |

**Option F, added 2026-11-08 after reading `studies/2026-1983.pdf`.** Akita is a
lattice polynomial commitment scheme reporting 58-68 KB proofs, 22-109x faster
verification than Greyhound at matched security, and prover memory that grows
sublinearly in the committed polynomial. If a Candidate-A-style global-tree
relation were proved with such a PCS instead of FRI, the two blockers measured in
`archive/candidate-a/MEASUREMENTS.md` (a 3.5 GiB LDE floor and a 4.9 GiB path-only peak) would no
longer apply, because the FRI LDE is the dominant term. This does not make it
easy: Akita commits polynomials; a transaction proof still needs a PIOP and an
integration (the paper describes a Jolt zkVM integration). It is worth pricing
before committing another year to SMILE, because it keeps the stronger global
anonymity set rather than a 16-member ring.

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

**D-ADR-6. Candidate C has been priced and is archived as the primary fallback.**
`archive/candidate-c/AKITA-ASSESSMENT.md` evaluated the Akita PCS (58-68 KB PCS proofs, sublinear prover
memory) as a Jolt zkVM backend. It cannot be dropped into Candidate A - Plonky3's
univariate FRI PCS and Akita's multilinear PCS are different interfaces - so it is a
new architecture, Candidate C. Measured Jolt numbers (p. 119) put peak RAM at about
1 GiB for 2^21 cycles and 6.4 GiB at 2^25, so the zkVM **trace**, not the PCS,
becomes the device constraint. That is marginal on the 1 GiB phone cap, whereas
Candidate B's prover is kilobytes-to-megabytes. **Continue with B; C is the
designated fallback** and re-opens only if a Jolt guest measures under 2^20 cycles
with peak RSS below 512 MiB, or if SMILE review fails (D-C-1..4).

## 5. What "matches Monero" means, precisely

Monero's privacy is *ring ambiguity + stealth addresses + RingCT*, with a **view key
that can identify your own outputs**. Any claim that an observer holding a view key
must not be able to test outputs is stronger than Monero and is unsatisfiable by any
scan-based design. `PRIVACY-MODEL.md` restates the games in Monero's terms and
re-scopes the project's "recipient key privacy P0" accordingly. Until that review
happens, the honest claim is "Monero-equivalent anonymity *design target*", not
"audited anonymity".

## 6. The experiment that decides B

Before writing a protocol, run the same discipline that produced `archive/candidate-a/LEAN-RELATION.md`:

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

## 8. Where B actually stands after implementing it (2026-11-08)

**B1 is done.** The SMILE manifest is transcribed with page citations, and every
dimension is in `CANDIDATE-B-PARAMETERS.md`.

**B2 is partially done, and the half that exists is measured.** The set-membership
proof of Figs. 7-9 is implemented and tested end to end
(`lattice/setmembership.py`), behind a ring-signature API and a spend layer.
At a 1024-member ring: proof **32,512 B**, prove **21 s**, verify **20 s**,
single-threaded CPython. That is inside the 100 KB pre-registered pass rule for
size; the time is a Python artifact and says nothing about a Rust build.
Amount commitments, range proofs and conservation are **not** implemented, so B2
is not passed.

**B3 is the critical path, and it is exactly as hard as section 7 guessed.**
Implementing Figs. 7-9 confirmed the hard way: the construction produces **no
tag**. The signature proves "one of these `l^m` keys is mine" and nothing more,
so the same key can sign without limit and two signatures are unlinkable. A
transaction layer cannot be built on that: double spending is undetectable.

The route the algebra suggests -- and the one lattice linkable ring signatures
use -- is a linear tag `T = A' s` for a second public matrix `A'`, revealed
through the same masking as `z'`. The prover sends `tau = A' y'`; the verifier
computes `A' z' - tau = c' * T` and recovers `T`, since `c'` is invertible with
overwhelming probability. Two accepting transcripts then give `A s* = c* pk` and
`A' s* = c* T`, so `s*/c*` is a preimage of both claims -- the standard
key-image argument.

That is a **sketch, not a proof**, and it is recorded as such. Open questions
before any of it may be claimed:

1. Invertibility of `c'` in `R_q` with the challenge distribution actually used
   here (dense ternary), not the paper's sparse one.
2. Whether the extraction survives the *relaxed* relation `A s* = c* pk` when the
   tag is only known through `c' * T`.
3. Linkability across arbitrary rings: the same note must give the same `T` even
   when the ring, the index and `c'` change.
4. Composition with the set-membership proof: one shared witness, not two
   independently witnessed statements.

Until those four are settled, B has a ring signature and **no transaction layer**,
and the distance between the two is a research result rather than an engineering
task.

### 8.1 The naive tag fails, and `experiments/linear_tag_soundness.py` shows it

The sketch above is **not sound as stated**, and the failure is worth recording
before anyone builds on it. `tau = A' y'` is not committed to anything, so a
prover can choose any tag `T` it likes and set `tau = A' z' - c' T`; the equation
`c' T = A' z' - tau` then holds by construction. The experiment demonstrates it:
the forged tag passes the same check as the honest one, and two spends of the
same note can carry unrelated tags. Linkability, which is the entire purpose of
the tag, evaporates.

The fix is not another check. It is a commitment: the mask `y'` is ephemeral and
appears nowhere in the commitment, so no linear relation can tie `tau` to it.
A sound construction has to either

* commit to the mask `y'` and prove `tau = A' y'` as a linear relation between
  committed values, or
* commit to the tag `T` itself and prove `c' T = A' z' - w_tau` with `w_tau`
  committed, which is the same problem one step removed.

Both raise the proof size by roughly `ell` full elements (about 6.6 KB) and both
need a linear-consistency argument of the kind Fig. 5 provides for `k` inputs.
That is the real content of B3, and it is why B3 is a research milestone rather
than a missing `if` statement.

### 8.2 The fix, implemented: `lattice/tag.py` (2026-11-08)

The commitment route works. With the mask committed under its own key
`(B_0^m ; b^m_1..b^m_ell)`, the prover sends `u_j = <b^m_j, r_m> + y'_j` and the
tag `T = <A', s>`; the verifier derives

    u_der = <A', u> - (<A', z'> - c' T) = <b'_j, r_m> + c' (T - <A', s>)

and checks a BDLOP opening proof that `(t_m ; u_der)` opens to **zero** under the
derived key `(B_0^m ; b')`, with `b' = sum_j A'_j * b^m_j`. That forces
`c' (T - <A', s>) = 0`, and the verifier separately checks that `c'` is a unit of
`R_q` (every NTT coordinate non-zero, which for this modulus is exactly
invertibility). So `T = <A', s>` is forced: two spends of one note carry the same
tag, and the attack that broke the naive version is dead.

Measured: the tagged ring signature is **51,584 B** at a 1024-member ring
(+19,072 B for the mask commitment, the tag, and its opening proof), 20 s to
prove and 20 s to verify in Python. Tests: 7 for the tag alone, 5 for the tagged
signature, including a forged tag being rejected and a tagged proof being
*refused* by a verifier that does not ask for the tag.

**Withdrawn on review and rebuilt the same day, 2026-11-08.** The replacement
is C1's same-witness extension: `A_ext = [A; A']`, the verifier forms the extended
ring `{(pk_j, T)}` with the *same* `T` in every member, and one Fig. 7-9 proof
over `A_ext` forces `T = A' s` from the witness that already proves ring
membership. No separate proof, no free response. Implemented as
`ring_signature.sign_tagged` / `verify_tagged`; 33,536 B at `k' = 1`, six tests.
The withdrawn construction is described below for the record.

**The original withdrawal.** Two independent reviews found the
construction above forgeable and the finding was reproduced here
(`experiments/tag_forgery_repro.py`): the proof binds only the *derived* row
`u_der = <A', u> - message`, never the individual `u_j`, so a forger chooses any
tag, any short `r_m`, sets `t = B_0^m r_m` and solves for `u`. `tag.py` now opens
with `KNOWN BROKEN - DO NOT USE` and a strict-`xfail` test holds the property we
want. A sound tag must commit the individual `u_j` and prove `<A', u>` against
them. The same review found the parameters do not achieve 128 bits (`beta`,
`beta'` are the real security parameters and this implementation's masks are
2^20); see `REVIEW-FINDINGS.md`.

Still open, and now sharply defined:

1. **Tag collision hardness.** `T = <A', s>` is a single polynomial, so the map
   from `s` to `T` has a huge kernel; two distinct notes colliding needs a short
   kernel vector, i.e. Module-SIS. That assumption has to be priced, not assumed.
2. **Composition.** The tag is a second proof bound to the signature by `c'` and
   `t_0`, not one witness shared with the set-membership proof. One joint proof
   is B5.
3. **Cost.** 19 KB for linkability is 59% of the base signature; a Dimithium-style
   compression of `t_0` and a smaller mask commitment are the obvious next cuts.

