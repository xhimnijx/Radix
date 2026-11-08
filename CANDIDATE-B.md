# Candidate B - working prototype and swap plan

**Status:** protocol prototype running with a **classical** linkable ring signature.
Not post-quantum yet. **Date:** 2026-11-08.

This document is the honest state of the architecture chosen in
`ARCHITECTURE-DECISION.md` (D-ADR-2): a Monero-style coin with ring anonymity,
linkable tags, and a path to post-quantum signatures.

---

## 1. What actually runs

`python -m examples.candidate_b_demo` produces a real spend:

```
ledger: 12 notes of value 20, height 100
spend built:
  ring size:        5 notes (indices [3, 4, 5, 7, 10])
  signature bytes:  224
  canonical message:554 bytes
  linking tag:      54baeab323df582c83756dd0e50347bd...
  signing time:     3.0 ms
  validation time:  5.1 ms (64-level membership x ring)
block applied: height 101, 13 notes, 1 tag
double spend -> rejected: tag has already been spent
```

Modules:

| Module | What it is |
|---|---|
| `radix_core/candidate_b/group.py` | 256-bit safe-prime Schnorr group, hash-to-scalar, hash-to-point, canonical encodings |
| `radix_core/candidate_b/lsag.py` | Abe-Ohkubo-Suzuki / Liu-Wei-Wong linkable ring signature, sign/verify, encoding |
| `radix_core/candidate_b/protocol.py` | notes, anchored rings, spends, tag set, atomic block application, decoy selection |
| `tests/test_candidate_b_lsag.py` | 15 tests: round trips for ring sizes 1-16, tampering, linkability, encoding |
| `tests/test_candidate_b_protocol.py` | 15 tests: balance, double spend, same-block replay, ring value equality, root/anchor, atomicity |

Properties that are **actually implemented and tested**:

- **Signer ambiguity** over a ring of equal-value notes. The signature has one
  response per member and no field reveals the signer.
- **Linkability**: the tag is deterministic per note key, so the same note cannot
  be spent twice - including within one block, and including a re-signed spend
  against a newer root.
- **Anchored membership**: every ring member is authenticated by a depth-64 path
  against the transaction's note root.
- **Atomicity**: a block containing one invalid transaction leaves the previous
  state untouched.
- **Value conservation** with public amounts, and fees burned in this prototype.

## 2. What is deliberately *not* implemented

| Gap | Why it matters | Plan |
|---|---|---|
| **Post-quantum signature** | The group is discrete-log; Shor breaks it. This is the whole reason the project exists. | Replace LSAG with a lattice linkable ring signature (SMILE-class) behind the same protocol seam. See section 4. |
| **Amount hiding + range proofs** | Values are public, so rings must be restricted to equal values (CryptoNote v1). That leaks the value and caps the anonymity set per denomination. | Pedersen/lattice commitments plus a range proof (RingCT-equivalent), then rings may mix values. |
| **Recipient discovery** | A note is addressed to a published one-time key; the sender must know it out of band. | PQ stealth address (see `PRIVACY-MODEL.md` G2/G5). |
| **Historical anchoring** | The prototype anchors at the current root only. | Reuse Candidate A's branch-relative `anchor_ok` with retained roots/paths. |
| **Persistent state, P2P, PoW** | None of it exists. | `TESTNET-SCOPE.md`. |

The launch gate enforces the first gap: a configuration using this backend is
refused for mainnet because it declares no post-quantum assumptions
(`radix_core/launch.py`, `CANDIDATE_B_PROTOTYPE_SECURITY`).

## 3. Why this ordering is right

The lattice signature is the *risk*, but it is not the *volume*. Everything built
here - note records, equal-value ring selection, tag uniqueness, anchored
membership, atomic block application, wallet decoy selection, canonical message
binding - is independent of which linkable ring signature is used. Getting it
working first means:

1. A new signature backend has a **conformance target** (the 30 tests) rather than
   being judged on paper.
2. The protocol's own failure modes (double spend, replay, mixed-value rings,
   forged paths) are already covered, so a backend failure is unambiguous.
3. Sizes are known: 32 bytes per ring member per input. A ring of 16 with one
   input is 576 bytes of signatures, before note keys and amounts.

## 4. The PQ swap plan

`ARCHITECTURE-DECISION.md` B1-B5 remains the gate. Concretely:

**B1 - parameter manifest.** Transcribe a pinned SMILE revision (ePrint 2021/564)
into `candidate_b/lattice/parameters.py`: ring/module dimensions, modulus, Gaussian
width, rejection-sampling bounds, challenge space, hash domains, and claimed
security. No guessed values. This step needs the paper; if it cannot be retrieved,
the manifest stays empty and B2 does not start.

*Status 2026-11-08:* **manifest pinned** in `CANDIDATE-B-PARAMETERS.md` from the
full version: `(q, d, l) = (≈2³², 128, 32)`, `k=4`, `ℓ=13`, `κ=10`, `λ=10`, `µ=5`
(p. 48, Fig. 11). The exact modulus is only specified as "≈2³²", so the prototype
fixes `q = 4,294,962,689` and flags `MODULUS_FROM_PAPER = False`. Ring arithmetic
and the BDLOP commitment are implemented and tested against it
(`radix_core/candidate_b/lattice/`, 14 tests). The set-membership proof, the
bimodal-Gaussian rejection sampling and the ring transformation remain open; the
B2 checklist in `CANDIDATE-B-PARAMETERS.md` §5 scopes them with page references.

**B2 - signature backend.** Implement `sign`/`verify` for the lattice scheme with
the same external contract:

```python
def sign(message: bytes, ring: tuple[bytes, ...], signer_index: int, secret) -> bytes
def verify(message: bytes, ring: tuple[bytes, ...], signature: bytes) -> bool
def tag(secret, verification_key) -> bytes
```

Keys and tags become byte strings rather than group elements; `protocol.py` only
ever treats them as opaque, so the change is contained.

**B3 - linkability game.** The one property the prototype proves by construction
(deterministic tag) must be re-established for the lattice scheme: same note
across arbitrary rings yields the same tag; distinct notes never collide. A test
that signs with two different rings and compares tags is already written and can
be ported unchanged.

**B4 - PQ stealth address.** Replace the "published one-time key" with a KEM-based
derivation. The recipient must recognise notes without the sender revealing which
address was paid (see G1-G3 in `PRIVACY-MODEL.md`).

**B5 - amount commitments.** Replace public values with commitments and add a range
proof; then relax the equal-value ring restriction and measure the size cost.

## 5. Sizes and costs to beat

| Quantity | Prototype now | Target for a phone wallet |
|---|---|---|
| Signature, ring 5, 1 input | 224 B | <= 1 KB |
| Signature, ring 16, 1 input | 576 B | <= 2 KB |
| Canonical message | 554 B | <= 1 KB |
| Signing time | 3 ms | <= 1 s |
| Validation time | 5 ms | <= 100 ms |
| Prover RAM | negligible (no proof system) | <= 1 GiB |
| **SMILE target (paper, Fig. 11)** | — | **15.96-18.73 KB at ring 2^5-2^15** |
| **SMILE tx target (paper, Fig. 3)** | — | **30 KB for (2,2) at ring 2^15** |

The reason Candidate B was chosen is visible in that last row: there is no
FRI-style prover, so the 1 GiB device budget is not the binding constraint. The
binding constraint becomes the lattice arithmetic - which is exactly what B1/B2
must measure.

## 6. Honest risk statement

- The lattice backend is **not** in this repository. Until it is, Candidate B is a
  Monero-style prototype with classical cryptography, and it must never be
  described as post-quantum.
- SMILE-class constructions are research, not standards. Parameter transcription,
  the global tag, and composition with amount proofs all need independent review.
- Even fully working, this is one layer of a coin that still needs a node, P2P,
  mining, wallet recovery, audits, and legal review.
- The prototype's decoy selection is deterministic hash ranking. Real decoy
  selection must match the spend-age distribution or the ring leaks the signer;
  this is a known Monero research problem and is deliberately not faked here.
