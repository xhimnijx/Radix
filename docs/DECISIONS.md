# Decision record: D1 (architecture) and D2 (privacy claim)

**Date:** 2026-11-10. These are D1 and D2 of `PLAN.md`, the two decisions that everything
downstream depends on. They are frozen here so that work can be scheduled against them and so that
a later change is a visible revision rather than a silent drift.

---

## D1 — The launch architecture is Candidate B

**Decision.** The launch path is **Candidate B**: the SMILE lattice ring signature over a spent-tag
ledger, as implemented in `radix_core/candidate_b/lattice/` (Python, the specification) and
`proof_rust/` (Rust, the second implementation), wrapped in `radix_testnet`.

**What that means concretely.**

- `radix_core/candidate_b/` is the cryptography the chain uses.
- `proof_rust/` is part of the release build. Cross-language agreement is a project invariant:
  each implementation verifies the other's proofs, and a change that breaks that is a defect.
- `radix_core/` Candidate A (the Pedersen/ML-KEM/Merkle reference core) is **not** on the launch
  path. It stays as an archive with its tests, because its primitives are still the reference for
  value commitments, but nothing in the running node imports it. Formal removal is Z-1.
- `launch.py` describes a Plonky3/STARK design that does not exist here. It must either describe
  Candidate B or be removed; a "mainnet switch" that gates a different system is worse than none,
  because it looks like a safety mechanism and is not one. Formal fix is Z-8.

**Consequences.**

- The modulus is `q = 4,294,966,337` at `ord_256(q) = 4`, which makes each CRT slot a field. That
  choice is what gives the `q^-4` challenge-difference bound and makes slot-constant binaryness
  sound; it is also what makes a coordinatewise Hadamard product inexpressible in the α-slots. The
  range layer inherits both consequences.
- Proof size is ~22–32 KB and verification ~110 ms in Rust. Those are the numbers the device-fit
  items (F-1, F-2) are measured against.
- `radix_core/wallet_keystore.py` stays; the testnet must use it (W-3).

---

## D2 — The claim: one sentence, two phases

**The normative sentence.**

> Radix provides **sender anonymity within a ring of 1,024 keys** using a post-quantum SMILE ring
> signature. **Transaction amounts are public in the current testnet and will become confidential
> when the value-binding construction (C-1) closes; the confidential mode is the target and the
> public mode is the honest interim state.** The node reports which mode it is running, and a
> client must not assume confidential amounts until that report says so.

**Why two phases rather than one claim.** Stating "confidential amounts" today would be false: the
range constraint exists inside the proof and is cross-verified, but it proves a slot-constant
statement that both external reviewers have confirmed is **not** the amount statement. The
coefficient-domain bridge is open research (C-1). Stating "public amounts" alone would silently
abandon the goal the project was built for.

So the claim is stated with its phase, and the phase is machine-readable, so a client can branch on
it instead of on a document version.

**What is claimed now, exactly.**

- An observer cannot tell *which* of 1,024 ring members signed a spend, beyond the anonymity the
  ring size and the decoy distribution give.
- An observer **can** see every input value, every output value, and the fee.
- The ring is built from the note pool by the chain, not by the sender, so a sender cannot choose a
  ring of their own keys.

**What is not claimed now, and must not be implied.**

- Amount confidentiality.
- Unlinkability across spends of the *same* key. A tag is derived from the secret, so a key is
  spendable once; one-time addressing (C-8) is what removes that.
- Sender anonymity against an adversary who can spend the ring members' keys.
- Anything about an audited scheme. No audit has been performed (C-3).

**Consequences.**

- The RPC returns the mode (§ below). The docs and the RPC must agree; a mismatch is a defect.
- C-1 stays on the critical path as the **target**, but its absence does not block the interim
  claim, so the plan can proceed while it is open.
- User-facing material must say "amounts are public" in the same place it says "post-quantum ring
  signatures", because the second is true and the first is what a user would be hurt by.

---

## Reflection in the code

| Where | What it must say |
|---|---|
| `GET /api/status` | `"privacy": {"mode": "public-amounts", "ring": 1024, "confidential": false}` |
| `docs/PAPER.md` §8 | amounts are not hidden; the range constraint is in the wrong subspace (already recorded) |
| `README.md` "What this is not" | amounts are visible; ring anonymity is the property that exists |
| The proof statement | the SMILE relation proves ring membership and, once bound, balance over **public** values |

The status field is the normative one: a client that reads `confidential: false` must not present
amounts as private, whatever a document says.
