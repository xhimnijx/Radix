# Akita compatibility review: Candidate-A / ML-KEM

**Status: research review only. No Akita code, PCS replacement, ML-KEM AIR, or GHASH AIR has been implemented.** The supplied paper is *Akita: A High-Performance Lattice-Based Polynomial Commitment Scheme* (2026-1983.pdf). The reviewed claims are from Sections 3.1, 3.6, 7.3, 8.2, 10, and the abstract/introduction.

## Decision

Akita is a plausible separate PCS research direction for reducing commitment/proof costs, but its reported measurements do not establish that it solves Candidate-A's memory or proof-size limits. The proposed use of HMZ quotient-lift to verify ML-KEM equations **natively in the existing BabyBear extension field is algebraically invalid**. ML-KEM's coefficient field and BabyBear have different characteristics. GHASH has a second, independent characteristic/modulus mismatch. Do not add this proposed ring switch to the current AIR or describe it as a solution to either circuit.

## What Lemma 3.4 and Section 7.3 actually establish

For a relation over `R_q = F_q[X]/(X^d + 1)`, canonical degree-`< d` representatives satisfy the ring equation exactly when a quotient polynomial exists:

`M_tilde(X) w_tilde(X) - h_tilde(X) = (X^d + 1) r(X)`.

Lemma 3.4 gives uniqueness and a degree bound for `r`. After the witness **and quotient** are committed, evaluating at a uniformly sampled challenge `alpha` in an extension field `E` of the same characteristic gives a Schwartz-Zippel test; the paper's basic bound is `(2d - 1) / |E|`. Section 3.1 defines the evaluation field as `E = F_q^k`; it is not an arbitrary, unrelated extension field. Section 7.3 applies the method to Akita's scheduled ring rows, with per-row native dimensions and a shared challenge. Its quotient-free transpose-convolution alternative also works over the row's coefficient field and uses a different, explicitly accounted soundness bound.

This is a sound algebraic technique under those field, commitment-order, degree, and soundness assumptions. It is not a general conversion of arithmetic from one field characteristic to another.

## Why the proposed BabyBear use fails

- ML-KEM uses coefficients modulo `q = 3329`, i.e. characteristic 3329, in `F_3329[X]/(X^256 + 1)`. The current harness uses BabyBear, characteristic `p = 2,013,265,921`, and its challenge field is `F_p^4` (see `README.md`). Every extension of `F_p` still has characteristic `p`; it cannot contain `F_3329` as a subfield. Therefore the Lemma 3.4 identity over `F_3329` cannot be evaluated as an identity in the current BabyBear extension. Reinterpreting residues `0..3328` as BabyBear integers does not preserve addition or multiplication modulo 3329.
- Sampling `alpha` only in `F_3329` is not a secure substitute: for `d=256`, the quoted quotient-lift bound is at best `511/3329` (about 15.3%). A sound construction would need a sufficiently large extension **of `F_3329`**, and a proof/commitment/transcript that correctly binds the coefficients and quotient before that challenge. That is not the current Plonky3 BabyBear STARK configuration.
- GHASH is arithmetic in `GF(2^128)`, characteristic 2, with its own irreducible reduction polynomial. It cannot be evaluated as a `GF(2)` identity in a BabyBear extension either. The Akita section's negacyclic modulus `X^d+1` is also not GHASH's reduction polynomial. A generalized quotient check would still require characteristic-2 challenges and a matching committed relation, or an explicit bit/limb/carry encoding in BabyBear.
- A BabyBear encoding route is possible in principle, but it must constrain canonical ranges and every modular reduction/carry so BabyBear wraparound cannot admit false integer identities. That is a different AIR design, not a native application of Lemma 3.4, and it needs its own soundness and resource analysis.

The existing RDXL AIR does **not** currently prove ML-KEM decapsulation/encapsulation or GCM/GHASH; the proposed method would be a future circuit direction, not a replacement for existing constraints.

## What else would be required for ML-KEM

The ring switch checks a committed polynomial-ring relation. It does not by itself prove that the complete ML-KEM algorithm was followed. A transaction proof still needs the correct witness encodings/ranges and bindings for key derivation, noise sampling, polynomial operations and reductions, NTT/representation conversions, compression/decompression, ciphertext parsing, re-encryption/CCA checks, and shared-secret derivation. The quotient (or quotient-free public-weight computation), challenge timing, relation batching, transcript binding, and final verifier must all be integrated into a concrete PIOP/PCS and analyzed together. Merely evaluating the ring equation at a challenge does not establish these omitted algorithm steps.

A viable investigation would first choose one of two explicit architectures:

1. A separate `F_3329^k` algebraic/commitment layer with adequate challenge size and a proved bridge to the public BabyBear STARK statement; or
2. A BabyBear AIR that explicitly encodes ML-KEM's modular coefficient operations with bounded limbs, range constraints, and carries, then measures whether this beats the direct construction.

Neither option is implemented or resource-qualified. In particular, a separate field layer must not be treated as a proof of the BabyBear AIR unless the bridge and joint soundness are specified.

## PCS and privacy claims: useful direction, not drop-in results

The paper reports a Rust Akita PCS implementation and 58–68 KB standalone opening proofs in its evaluated settings, as well as sublinear memory overhead beyond the committed polynomial. These are results for Akita's lattice PCS and multilinear/sum-check protocol, not measurements of this harness's dense 14,477-column RDXL trace, full transaction proof, laptop RSS, or mobile RSS. The harness currently uses Plonky3's univariate AIR/FRI stack (`HidingFriPcs`); Akita uses multilinear commitments, folds, and sum-check. Replacing the backend therefore requires a PIOP/commitment redesign and a new end-to-end implementation and benchmark. RDXK's prior 327,502-byte envelope and the paper's 58–68 KB PCS results are not directly comparable proof shapes.

The terminal protocol described in Section 8.2 sends the folded response `z = sum_i c_i s_i` in the clear. The paper's stated security theorem is knowledge soundness, not an application-witness zero-knowledge theorem. Treat Akita as **not established ZK for Candidate-A** unless a masking/hiding construction is added and proved for the complete composition. The clear response is a concrete privacy-review requirement; this note does not claim that one response alone always recovers a particular secret. The paper explicitly proves Fiat–Shamir security in the classical ROM and leaves QROM security as future work (Sections 1.1 and 10). Its lattice assumptions and its FS theorem are separate security coordinates.

Akita does not address Gate 1's recipient/ciphertext key-privacy issue; that remains a wire-format/encryption/stealth-address design question, independent of the PCS.

## Safe next step

Do not code the proposed direct BabyBear ring switch. Keep RDXL's existing proof/resource gates and ML-KEM/GHASH gaps explicit. If this direction is pursued, first write a field-correct relation specification (including the exact coefficient domain, modulus, challenge extension, quotient or transpose-convolution witness, commitment/challenge order, and total soundness budget), then build a tiny independent reference test for the chosen field architecture. Only after that test and a complete bridge design should a production AIR/PCS prototype be considered. No heavy proof, Akita port, or mobile-fit claim follows from this paper review.
