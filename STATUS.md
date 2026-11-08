# Status â€” 2026-11-08

**One line:** the tree builds, the suite is green, the verified safety defects are
fixed, and the mainnet launch gate exists and ships **closed**. The proof side is
still a component prototype: no complete transaction proof exists, and the
flagship RDXL profile is fail-closed by design.

## Verify it

```powershell
python -m pytest -q                                  # 372 passed (~97 s)
python Radix-Serialization-Test-Vectors.py           # passes
python .\Radix-Gate-1-Reference-Model.py             # passes
python -m examples.wallet_note_demo                  # real ML-KEM/AES round trip
python -m examples.launch_gate_check                 # prints why mainnet is locked
python -m experiments.lean_relation_sizing           # corrected cost model

# Rust: builds and runs locally through the self-contained MinGW set
& .\scripts\rust.ps1 test --locked                   # 46 passed, 7 ignored, 0 failed
& .\scripts\rust.ps1 check --locked --all-targets    # exit 0

# Measured prover peaks (prebuilt 2026-11-01 binary; see MEASUREMENTS.md)
& .\experiments\measure_rust_test.ps1 `
  -Binary "proof_harness\target\release\deps\radix_proof_harness-a6743722e416b94c.exe" `
  -TestName "depth64_path_opening::tests::proves_and_verifies_private_depth64_path"
```

**Toolchain note (2026-11-08).** The Rust suite now runs on this machine. The GNU
toolchain is self-sufficient once `rust-mingw`'s `self-contained` directory is on
PATH (it provides `gcc`, `ld`, `dlltool`, and `rust-lld`). `scripts/rust.ps1`
wraps that. This is a real build and a real test run, not a type-check.

## What is implemented and verified

| Area | State |
|---|---|
| Canonical codecs (`Frame`/`Bytes`/`Vec`, address/output/statement) | implemented, round-trip and mutation tested |
| SHAKE256 Candidate-A hashes | implemented, known-answer vectors |
| ML-KEM-768 + AES-256-GCM adapters (`cryptography==50.0.2`) | real providers, round-trip and negative tests |
| Wallet keygen, note create/recover, bounded and authenticated scan | implemented; scan containment fixed and regression-tested |
| Sparse depth-64 tree, anchors, integer balance, atomic `apply_block` | implemented; **quadratic replay** (see `Radix-Workspace-Review.md` Â§3.I1) |
| Nonce registries (process-local + SQLite) | implemented; default is now unbounded |
| Pruned-storage arithmetic model | implemented as an unenforced planning model |
| Launch gate (`radix_core/launch.py`) | implemented, 20 tests; **closed by default** |
| Candidate-B prototype (`radix_core/candidate_b/`) | **working**: notes, anchored rings, linkable ring signature, tag set, atomic blocks. Classical crypto only. |
| Candidate-B lattice layer (`candidate_b/lattice/`) | **B1+B2 complete**: SMILE manifest, negacyclic ring and NTT, quartic slots (`M_q`), BDLOP commitment, Fig. 5 opening proof and aggregation, the Fig. 8 recursion, and **the Fig. 7/9 set-membership proof itself** (m >= 2). 116 tests. Deviations documented, no security claim. |
| Rust component proofs (`RDXZ*`, `RDXT/S/I/J/K`) | type-check clean; proof tests are `#[ignore]`d |
| Rust `RDXL64P1` (full transaction) | **cannot run**: resource preflight fails closed by design |

## Measured / derived numbers after the layout revert

The half-landed key-schedule overlay was reverted to a contiguous 1,920-bit bank
(the split was not consistent and the overlay's column lifetime was unproven).
That costs 1,152 trace columns and makes the fail-closed preflight worse, not
better â€” recorded honestly rather than hidden:

| Quantity | Value |
|---|---|
| RDXL trace | 8,192 Ã— 15,629 BabyBear values (512,131,072 B) |
| Randomized matrix | 16,384 Ã— 15,633 (1,024,524,288 B) |
| PCS LDE payload | 4,098,097,152 B (3.82 GiB) |
| Randomized + LDE coexistence | 5,122,621,440 B (4.77 GiB) |
| Cross-target process cap used by the guard | 1,073,741,824 B (1 GiB) |
| Best measured input-half profile | `RDXJ64P1`, 9,518 MiB peak working set |
| Component proof sizes | 175,252â€“327,502 B |

## Decision: the M3 lean-relation experiment (executed 2026-11-08)

`python -m experiments.lean_relation_sizing` and `LEAN-RELATION.md` record a
decision-grade result:

| Profile | Peak @4x (single proof) | Peak @9.5x (planning) | Desktop 4 GiB | Phone 1 GiB |
|---|---:|---:|---|---|
| R-fat (RDXL64P1 today, 14,173 cols) | 27.7 GiB | 65.7 GiB | 16x over | 28x over |
| R-lean (drop in-circuit KDF/AEAD) | 8.5 GiB | 20.1 GiB | 5.0x over | 8.5x over |
| R-lean + packed sibling | 8.0 GiB | 19.0 GiB | 4.8x over | 8.0x over |
| R-lean + packed + algebraic hash (counterfactual) | 5.2 GiB | 12.3 GiB | 3.1x over | 5.2x over |
| RDXZ64P1 path-only floor | 4.9 GiB | 11.7 GiB | 2.9x over | 4.9x over |

All at production blowup (log_blowup=3); at the test blowup of 2 every figure halves.
Measured on this host (`MEASUREMENTS.md`): a single focused path-only proof peaks at
**2.49 GiB / 17.9 s** at blowup 2 (LDE 0.62 GiB, ratio 4.04x); a composed multi-proof
test peaks at **8.61 GiB / 60.0 s** (LDE 0.92 GiB, ratio 9.39x).

- The measured path-only floor fits the desktop gate **only at the test blowup**;
  at production parameters it is already 4.9 GiB.
- Dropping in-circuit KEM/AEAD is justified by the soundness note (Part A of
  `LEAN-RELATION.md`), but it is not sufficient: 8.5 GiB at production.
- **Correction (2026-11-08, after the suite ran):** an earlier version of this table
  claimed packing the path witness would bring the relation to 1.0-2.4 GiB. That was
  wrong on two inputs - the real width is 14,173 (not 15,629) and the path witness is
  1,024 bits (not 8,192), so packing saves 480 columns, not ~7,800. The corrected
  model is above; the conclusion changes from "packing is the lever" to "a single
  monolithic AIR cannot meet the phone budget in any configuration tested".
- Mobile is **not reachable** by this architecture: the phone ceiling is about 1,020
  columns at 4,096 rows, and the smallest relation (path-only) is 5,043.

## Candidate B is now the active track (2026-11-08)

Per `ARCHITECTURE-DECISION.md` D-ADR-2, Candidate B (Monero-style ring anonymity)
is the product architecture; Candidate A is parked as the credibility baseline.
The first working slice is in `radix_core/candidate_b/`:

- A real **linkable ring signature** (Abe-Ohkubo-Suzuki / Liu-Wei-Wong) over a
  256-bit group: 15 tests including ring sizes 1-16, tamper rejection, and
  cross-ring linkability.
- **Protocol**: notes, equal-value rings, depth-64 anchored membership, tag
  uniqueness, atomic block application, decoy selection, and canonical message
  binding. 15 tests including double spend, same-block replay, mixed-value rings,
  forged roots, and atomicity.
- **Demo**: `python -m examples.candidate_b_demo` builds and applies a 5-note ring
  spend (224-byte signature, 3 ms sign, 5 ms validate) and rejects the double spend.

**The PQ gap is explicit and enforced**: the backend is a discrete-log group, so
Shor breaks it. `CANDIDATE_B_PROTOTYPE_SECURITY` declares no post-quantum
assumptions, and a launch-gate test asserts that a mainnet configuration using it
is refused. See `CANDIDATE-B.md` for the swap plan (B1-B5) and the size targets.

**B1 is now pinned** in `CANDIDATE-B-PARAMETERS.md`: the SMILE manifest
`(q, d, l) = (~2^32, 128, 32), k=4, ell=13, kappa=10, lambda=10, mu=5` transcribed
from the full version (p. 48, Fig. 11), together with the paper's size tables
(15.96-18.73 KB ring signatures; 30 KB for a (2,2) transaction at ring 2^15).
`radix_core/candidate_b/lattice/` implements the negacyclic ring and the BDLOP
commitment with 14 tests. The exact modulus is only given as "~2^32" in the paper,
so the prototype fixes an NTT-friendly 32-bit prime and sets
`MODULUS_FROM_PAPER = False`; no security claim is attached to it.

**B2 layers landed (2026-11-08).** On top of that base, in
`radix_core/candidate_b/lattice/`:

- `sigma.py` is the opening proof `pi` of Fig. 5: ternary challenge, 2^20 masking,
  no rejection sampling, 6,784 B, 10 tests.
- `tensor.py` is the one-hot / Kronecker indexing that Fig. 6 uses to select a ring
  member without naming it: `n = l^m` up to 2^25, column selection returns exactly
  one column, 9 tests.
- `ntt.py` is the negacyclic number-theoretic transform: exact integer arithmetic,
  twist + radix-2, `O(d log d)` instead of `O(d^2)`. It is not an optimisation
  nicety â€” the Fig. 6 recursion is stated in the NTT domain (Lemmas 2.1/2.2 are
  statements about NTT coefficients and the "first `d/l` zero coefficients"), and
  every honest value there is committed as `NTT^-1` of a short vector. `ring.mul`
  uses it; `mul_naive` stays as the audited reference and the tests assert they
  agree coefficient for coefficient. 10 tests. Measured: 1.97 ms -> 1.00 ms per
  multiplication, full suite 9.97 s -> 5.79 s.
- `subring.py` is the quartic slot decomposition, i.e. SMILE's `M_q`:
  `R_q = prod_i Z_q[X]/(X^4 - r_i)` over the 32 roots of `Y^32 = -1`. This is the
  convention the recursion is written in, and it reproduces the paper's lemma
  exactly: `g(y)`, the sum of the 32 quartic residues, equals
  `32(y_0 + y_1 X + y_2 X^2 + y_3 X^3)`, so the "first four coefficients vanish"
  test is the pairing `<v, x> = 0` and not an approximation of it. 12 tests,
  including that `<w, w'>` of constant vectors is their scalar dot product.
- `recursion.py` implements equation (7) of p. 6, the reduction the whole scheme
  rests on: `<P(v_1 (x) ... (x) v_m) - w, gamma> = <v_1, P'(v_2 (x) ... (x) v_m)> - <w, gamma>`,
  with `P' = [gamma^T P_1 ; ... ; gamma^T P_32]`. Verified numerically at `m = 2`
  (a 32 x 1024 matrix over `M_q`), including that a wrong witness is rejected.
  9 tests. This is the "one tensor factor fewer" step that makes the proof size
  linear in `m`; the quadratic/binary constraints on top of it are what remain.
- `aggregation.py` is **Fig. 5 in full**: `k` input commitments folded into one
  `omega = (f; g_1..g_k; g_w)` under one randomness, with sparse ternary
  challenges, `z = y + sum c_i s_i`, `a* = sum c_i a_i - a_w`,
  `g* = sum c_i g_i - g_w + b.z`, and `pi`. The verifier recomputes every value from
  public data (no secret needed) via the identity
  `g* = a*.r + sum_i c_i u_i`. 14 tests. Measured proof: **19,072 B at k=2**,
  20,096 B at k=4.

**Fig. 6 itself is not implemented.** What is missing is not a corner: hiding *which*
column of `T` was selected requires proving the tensor relation with the p. 23
quadratic constraints (binary support, the `d/l` zero-coefficient trick,
`h = g + y_1 + ... + y_m`, and the multiplicative-relation proof between committed
values). A verifier that skipped it would accept a proof of nothing, so it is not
stubbed, faked, or marked done. `aggregation.py` is the layer Fig. 6 keeps unchanged;
the set-membership step swaps the revealed index for that relation. The NTT
substrate that the recursive argument is written in is now in place, so the next
component can be written against it instead of being rewritten afterwards.
**The set-membership proof is implemented (2026-11-08).** `lattice/setmembership.py`
is the protocol of Fig. 7 with the Fig. 8 recursion and all fifteen checks of
Fig. 9: a BDLOP commitment to `(0_kappa, v_1..v_m, w', x_2..x_m, g, psi)`, the set
matrix `P = [NTT(-c' pk_j)]` of eq. (31), one challenge and one commitment per
tensor factor, the garbage commitment and `omega`, and the multi-round
Fiat-Shamir of p. 43 with the message bound into `c'`. A 1024-member ring
(`m = 2`) proves in **21 s** and verifies in **19 s**, producing a **32,512-byte**
proof.

Three transcription errors were found by test rather than guessed at: Fig. 7
commits `w'` and line 04 subtracts `A z'` afterwards; `B^T gamma` is the
*constant* vector `(gamma_0, ..., gamma_0)` and not `gamma * 1`; and `F_1` uses
`f_{m+i}`, not `f_{m+i-1}`.

Deviations, stated in the module and unchanged: no rejection sampling (masks are
`2^20`), the `e_1` term of `F_m` placed at order `c^2` because Fig. 9 line 12's
order-`c` placement makes the honest check unsatisfiable, `m >= 2` only, and the
message bound into `c'`. Research component: no security claim without
independent review.

**New option recorded.** `studies/2026-1983.pdf` turned out to be *Akita*, a 2026
lattice polynomial commitment scheme (58-68 KB proofs, sublinear prover memory,
22-109x faster verification than Greyhound). It is not a transaction proof, but it
could remove the FRI LDE that killed the Candidate-A device budget. Recorded as
option F in `ARCHITECTURE-DECISION.md` with D-ADR-6: price it before committing a
year to SMILE.

**Akita assessed (2026-11-08):** it cannot be swapped into Candidate A (univariate
FRI PCS versus multilinear PCS), so using it means a new architecture - **Candidate
C** = Candidate-A relation as a Rust guest + Jolt zkVM + Akita. Jolt's measured
memory is ~1 GiB at 2^21 cycles and 6.4 GiB at 2^25, so the zkVM trace dominates and
the 1 GiB phone cap becomes marginal, while Candidate B needs kilobytes. **B stays
the active path; C is the designated fallback** with explicit re-open triggers. See
`AKITA-ASSESSMENT.md`.

## Not implemented (unchanged blockers)

- A complete transaction proof, an ML-KEM relation, GCM/GHASH authentication.
- Recipient key privacy (P0), proof of key possession, seed/mnemonic recovery.
- Node, P2P, PoW, mempool, genesis, block wire format, block resource caps.
- Any external cryptographic or consensus review.
- Production FRI parameters in the shipped provers (they use a 2-query test config).

## Skipped checks and re-enable conditions

| Skipped | Reason | Re-enable when |
|---|---|---|
| 7 Rust proof tests (`#[ignore]`) | peak RSS is unbounded and exceeds the provisional device budgets | a profile is measured under a 4 GiB desktop cap |
| `RDXL64P1` proving | preflight returns `ResourceBudgetExceeded` before allocation | the lean-relation experiment (Â§ M3) produces a fitting profile |

## Launch posture

`MAINNET_SWITCH.is_open == False`. The reasons are machine-readable:

```powershell
python -m examples.launch_gate_check
```

No flag, environment variable, or runtime path opens it. See
`MAINNET-SWITCHOVER.md`.

## Known flake (recorded 2026-11-08)

`tests/test_nonce_multiprocess.py::test_sqlite_nonce_reservation_is_unique_across_processes`
failed once during a full-suite run and passed 3/3 in isolation and on rerun. It is a
multiprocess SQLite test, so contention with the rest of the suite is the likely cause;
it is unrelated to the lattice work but is recorded rather than silently re-run away.
If it recurs, the fix is a bounded retry on `SQLITE_BUSY` in the reservation path, not a
longer sleep.


