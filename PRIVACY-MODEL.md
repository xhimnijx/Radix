# Privacy model: what "Monero-class" actually means

**Status:** design analysis, not a proof. **Date:** 2026-11-08.
**Purpose:** replace the project's current, too-strong "recipient key privacy" game
with games that match Monero's real guarantees, so that (a) the construction can be
judged fairly and (b) a redesign is not spent on an unsatisfiable property.

---

## 1. Monero's actual guarantees

| Property | Mechanism | Leakage Monero accepts |
|---|---|---|
| Sender ambiguity | Ring signature over decoys (ring size 16 by default) | Ring membership is public; decoy selection leaks statistically |
| Recipient unlinkability | Stealth address: one-time output key `P = H(rA)G + B` from an ephemeral `R = rG` | The payer knows the recipient; an observer with the **view key** can identify and link that wallet's outputs |
| Amount hiding | RingCT commitments + range proofs | Fee is public |
| Scanning | View key `a` (or `(a,B)` for full view) | View key compromise reveals all incoming history of that wallet |
| Network | Dandelion++ | Not a guarantee against a global observer |

The critical point: **a view key is a scanning capability.** Monero's design *intends*
that holding a candidate view key lets you test whether an output belongs to that
wallet. A game that forbids this is not "Monero-like"; it is stronger than Monero and
is unsatisfiable by any scan-based private-transfer design.

## 2. Games, restated in Monero's terms

Let `addr = (A,B)` be a recipient address (viewing + spend public keys) and `sk_v` its
view key. All games are against a chain observer who sees every block, output,
nullifier and proof.

**G1 - Recipient unlinkability (address reuse).** The challenger gives the adversary
two outputs, either both to `addr*` or each to a different address. Without `sk_v*`,
the adversary guesses which with advantage negligible in the security parameter.

*Monero:* holds via fresh one-time keys. *Radix-Candidate-A:* the note owner
`p = H_note-owner(pk_s, K)` is fresh per output because `K` is fresh, so the on-chain
link is the KEM ciphertext, which is pseudorandom without `sk_v`. **Holds, subject to
review.**

**G2 - Recipient key privacy (candidate testing, no secret).** The adversary is given
one output and two candidate addresses but **neither** view key, and must decide
which address (if either) it belongs to. Advantage negligible.

*Monero:* holds (needs `a` or `r`). *Radix:* holds if ML-KEM ciphertexts are
indistinguishable from random without `sk_v`, which IND-CCA implies. **Holds,
subject to review.**

**G3 - View-key compromise (disclosure, not a break).** Given `sk_v`, the adversary
identifies every output to `addr*` and links them. This must be stated as leakage,
exactly as in Monero. It is *not* a failure of G1/G2.

**G4 - Sender anonymity.** Given a spend, the adversary cannot tell which unspent note
was consumed. *Monero:* ring of 16. *Radix-A:* membership in the full unspent tree -
strictly stronger *given a large unspent set*, but with no decoys the anonymity set is
the real set, which is small early in a network's life.

**G5 - Amount confidentiality.** Hidden values, range-proven, exact integer
conservation. Both designs share this structure.

**G6 - Multi-user / cross-wallet tests.** Given outputs to many addresses and one
compromised view key, the adversary learns only that one wallet's outputs. No
information about other recipients. Both designs hold (subject to review).

**G7 - Quantum observer.** An adversary who records ciphertexts now and can run Shor
later must learn nothing about values or spend authority. Requires commitments,
nullifiers, encryption and proofs to be Shor-free. *Radix-A:* SHAKE + ML-KEM +
hash-based STARK - yes. *Monero:* no (ECDH stealth addresses and CLSAG are broken by
Shor). **This is the whole reason the project exists.**

## 3. Evaluating the current construction

| Game | Current Radix Candidate A | Verdict |
|---|---|---|
| G1 recipient unlinkability | owner `p = H(pk_s, K)` fresh per output; ciphertext pseudorandom without `sk_v` | **appears satisfied** |
| G2 candidate testing without a secret | ML-KEM IND-CCA; no public test on `ct_kem` | **appears satisfied** |
| G3 view-key compromise | `sk_v` decapsulates and links everything | **inherent leakage, must be disclosed** |
| G4 sender anonymity | full-tree membership; no decoys | satisfied formally; weak early |
| G5 amounts | hash commitments + in-circuit integer balance | satisfied formally |
| G6 cross-wallet | per-address key; no shared state | appears satisfied |
| G7 quantum observer | SHAKE/ML-KEM/STARK | satisfied, modulo assumptions |

### The correction to the project's risk register

`archive/candidate-a/Radix-Gate-1-Feasibility-Log.md` section 3 lists as P0: *"An observer who obtains a
candidate recipient's viewing secret can decapsulate each KEM ciphertext ... and test
it."* That is **G3**, and Monero has exactly the same property. Game 9 in
`archive/candidate-a/Radix-Gate-A-Cryptographic-Review.md` section 2.4 formalises it as a distinguishing
game where the adversary **is given** candidate viewing secrets and must still be
unable to tell which recipient a ciphertext is for. **No scan-based design can pass
that game, including Monero.** It should be replaced by G2 plus the disclosure in G3.

This matters practically: if the P0 is mis-scoped, a redesign of recipient discovery
may be unnecessary - the real blockers are proof cost (`ARCHITECTURE-DECISION.md`)
and wallet UX (seed recovery, address format), not key privacy.

**What still genuinely differs from Monero and should be improved:**

1. **Scan cost and output size.** ML-KEM-768 costs 1,088 bytes and one decapsulation
   per output; Monero's ephemeral key is 32 bytes and one scalar multiplication. With
   a lifetime of outputs, scan time is the dominant wallet cost. A PQ stealth-address
   construction (eprint 2025/112) may reduce this; measure, do not assume.
2. **Address size.** 1,318 bytes and no text encoding. Monero's is 95 characters.
   This is a usability blocker, not a privacy one.
3. **View-key separation.** The design has separate spend secret and viewing key, so
   view-only wallets work. Confirm that a view-only wallet cannot compute
   nullifiers and that the wallet never needs the spend secret to scan.
4. **Anonymity set size.** A global-tree design is only as private as the number of
   unspent notes; early on it is small, and the 60-block anchor makes every spend
   recent. Rings give a *guaranteed* minimum ambiguity (16) even on day one.

Point 4 is the strongest argument for Candidate B independent of proving cost: it
gives a floor on anonymity that does not depend on adoption.

## 4. What must be written before either candidate can claim R1

1. Adopt G1-G7 as the game set (superseding review game 9).
2. For each game, state the assumption and the concrete advantage bound.
3. Publish a leakage table including G3 (view key), timing, output shape, fee, and
   network metadata.
4. Have an independent reviewer sign the scoping - the scope is now testable, which
   is the point.

## 5. Claim language

**Permitted:** "designed to provide Monero-class sender, recipient and amount
privacy, with the same view-key leakage Monero accepts, and additionally resistant to
a future Shor-capable adversary."

**Not permitted:** "untraceable", "fully anonymous", "quantum-proof", "no one can
link your outputs", or any claim that a view key cannot identify its own wallet's
outputs.
