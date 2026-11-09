# An implementation study of a post-quantum private payment system

**Draft skeleton.** Title, abstract, claims and section outline, with the measured numbers
filled in from the repository. What is missing is the prose between the headings and the
evaluations marked TODO.

> Research prototype. No value, no security claim, not a currency.

---

## Abstract

We report an implementation study of SMILE (ePrint 2021/564), a module-lattice set-membership
proof with applications to ring signatures and confidential transactions. The contribution
is not new cryptography. It is a **second, independent implementation** of the same protocol
in Rust, cross-verified against the Python reference in both directions, together with the
measurements and the defects that arrangement surfaced.

Three things we report: proofs of **21,760 bytes** at ring size 1024, a 33.1% reduction from
the initial implementation by bounding and packing the responses; prover and verifier costs
of **475 ms** and **105.8 ms** in Rust against one to two minutes and twenty seconds in
Python; and **four defects** found by differential testing, none of which reading or review
had caught, including a commitment-arity error that agreed with the correct formula in
exactly one configuration and was wrong in every other.

---

## Claims, stated precisely

The paper claims only these. Anything not on this list is not a claim.

1. The protocol of SMILE Figures 7-9 is implemented twice, and each implementation accepts
   the other's proofs.
2. The proof is 21,760 bytes at ring size 1024 with the parameters given in §4.
3. Proving costs 475 ms and verification 105.8 ms in Rust on the hardware named in §6.
4. Four defects were found by differential testing and are reproducible from the artefacts.
5. A delta-model estimate puts the two M-SIS instances at 2^158 and 2^167.

**Not claimed:** any security level. The estimate is a delta model, not an estimator run; the
extraction argument is the paper's, with a restatement signed by an external reviewer but not
independently proved here; and the implementation has not been audited.

---

## 1. Introduction

- The privacy problem a ring signature solves: prove membership without naming the member.
- Why post-quantum matters for a payment system: the ledger outlives the attacker timeline.
- What this paper is: an implementation study, and why that is worth reporting.

TODO: two paragraphs of motivation.

## 2. Background

- SMILE in one section: Fig. 7 (prover), Fig. 8 (recursion), Fig. 9 (verifier).
- Module-SIS and module-LWE over `R_q = Z_q[X]/(X^128 + 1)`.
- The BDLOP commitment and why one commitment serves the whole statement.

## 3. Why two implementations

This is the paper's method section and its reason to exist.

- A second implementation is a **differential test**: a specification bug that both
  implementations would have to share is unlikely.
- Cross-language acceptance in both directions is the strong form: a proof from one is
  checked by the other, over the same transcript, the same challenge derivation and the
  same encoding.
- What it costs: the port is roughly the size of the original, and every wire-format change
  must be made twice and verified twice.

### 3.1 The discipline that made it work

Bottom-up porting with known-answer values from the reference at every layer: R_q
arithmetic, the quartic CRT, sampling, the transcript, the commitments, the recursion, the
challenge derivation. A layer is ported only when it reproduces the reference's output
exactly. This is what turned the port from "a rewrite" into "a test".

## 4. Parameters

| | |
|---|---|
| `q` | 4,294,966,337 (`ord_256(q) = 4`, 32 irreducible quartics) |
| `d, l` | 128, 32 |
| `k, ell, kappa` | 4, 13, 10 |
| Ring size | 1024 (`32^2`) |
| `s, s'` | 2665.5, 1673.0 (discrete Gaussian, 12σ truncation) |
| `beta, beta'` | 244,992, 96,512 |
| `k'` | 1 |

The modulus choice is load-bearing: at `ord_256(q) = 4` each slot is a field, which closes
two separate holes in the paper's analysis (the challenge-difference cap and the
slot-constancy property). §5.3 explains why that makes a theorem where a split modulus
would have had a conjecture.

## 5. Implementation

- The Python reference: clarity over speed, used as the oracle.
- The Rust port: `u128` slot accumulation, a Barrett reduction, no external crates.
- The seam: one process boundary, with a request format shared by the prover and verifier
  so a single serialiser serves both directions.

### 5.1 The discrete Gaussian

The reference originally rounded a continuous Gaussian. Two problems: it is not the object
Lemma A.6 is stated for, and it is **not portable** — two implementations rounding floats
disagree in the last bits, so the analysis applies to neither while a cross-language test
appears to pass.

The fix is one cumulative table, read at runtime by Python and `include_bytes!` by Rust, so
the two cannot sample differently. Truncated at 12σ: `2^-107.8` per coefficient, about
`2^-101.8` aggregated over a 4224-coefficient response.

### 5.2 Compression

| | before | after |
|---|---|---|
| Untagged proof | 32,512 B | **21,760 B** |
| Tagged proof + tag | 38,656 B | **23,040 B** |

Two steps, both soundness-neutral: bounding the responses at `12σ` (a check the paper
requires and the implementation had omitted) and packing them as 16-bit centred values
rather than 32-bit residues. The remainder of the gap to the paper's 17.27 KB is compressed
public keys and Bai-Galbraith, which change the statement rather than the encoding and are
not attempted here.

### 5.3 What the modulus buys

TODO: the field-regime argument, and the honest note that module-LWE hardness proofs in the
literature are stated for `q ≡ 1 mod 2n`, so this parameter set holds a conjecture where a
split modulus would hold a theorem.

## 6. Evaluation

All figures measured on the machine and commit named in the artefacts. No projections.

| | |
|---|---|
| Prove | 475 ms |
| Verify | 105.8 ms |
| Rejection attempts per proof | 9.75 |
| Proof, untagged | 21,760 B |
| Proof, tagged + tag | 23,040 B |
| Parallel verification, 8 cores | 4.22x |
| Proof decode | 2.7 ms |
| Noise-aware proof at ell = 17 | 22,784 B |
| Replay per year of chain at 10 tx/block | 3.9 hours |

TODO: hardware description, and the Python figures for contrast.

## 7. Defects found by differential testing

The paper's most useful section, and the reason to write it.

| Defect | How it was found | Why review missed it |
|---|---|---|
| Commitment arity `κ+λ+m+1` instead of `κ+rows+2m+1` | the port disagreed with the reference | the two agree exactly when `rows = 8` |
| `g`'s zero prefix applied to slots, not coefficients | the port disagreed | every stage still passed; only the `h`-prefix check caught it |
| The genesis hash did not commit to the allocation | building a second node | both chains looked valid independently |
| A block reward to a reused key collapses | writing the reward test | the failure only appears with two rewards to one key |

Each is reproducible from the artefacts. The first two are the argument for the method:
neither was findable by reading, and both were wrong in both implementations.

## 8. Limitations

Stated plainly, because a paper that hides these is not credible.

- **Amounts are visible.** The range proof is specified and its primitives are built and
  tested, but it is not inside the proof.
- **One-time addressing is partially built.** The lattice derivation works and is tested:
  a short `XOF(S)`, the noise-aware `[A | I_k]` statement at `ell = 17`, and the public tag
  image `T_K = A'·k`. What is missing is deriving `S` from a real KEM rather than a
  caller-supplied secret, and wiring the meta-address into the wallet. The bound depends on
  the spend-key distribution: with this proof's uniform-small keys the stealth secret
  reaches `mu + 2`, not `mu`.
- **No estimator run.** 2^158 and 2^167 are delta-model figures with named cost models
  (ADPS16 and MATZOV reported side by side), not output from `lattice-estimator`.
- **The noise-aware statement is wired but not proved sound.** The extraction argument for
  `[A | I_k]` is unwritten; the statement shape works, which is not the same thing.
- **No audit.** The extraction argument is the paper's; the restatement is signed by a
  reviewer but not proved here.
- **The sampler's accept/reject test is still floating point.**
- **The network is authenticated but not encrypted.** Messages carry an HMAC-SHA256 when
  a shared secret is configured, so a peer cannot alter traffic undetected -- but anything
  on the path can still read it, and peers are identified by shared secret rather than by
  a key.

## 9. Reproducibility

```powershell
python -m pytest -q -m "not slow"    # 569 passed, 1 known xfail
cd proof_rust && cargo test          # 74 passed
python experiments/verify_rust_proof.py
python experiments/estimate_sis.py --check
```

Every number in the paper is produced by one of these commands or by a script in
`experiments/`. A number that cannot be reproduced from the artefacts is a defect in the
paper and should be reported as one.

## 10. Conclusion

TODO: what an implementation study contributes, and what it does not.
