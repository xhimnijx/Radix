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


---

## D3 — Consensus is PoW as designed, with the security budget stated

**Decision.** Proof of work as implemented: LWMA-90 difficulty with 2× clamps, a slow start over
the first 4,000 blocks, median-time-past for timestamps, and fork choice by cumulative work
(`Σ 2^256 / target`, fixed to stop it being the block count).

**Rejected.** PoS/BFT. It removes the 51% economics and adds a validator set, finality and slashing
— a rewrite of `chain.py`, and roughly neutral in effort unless the expertise already exists. It
was not chosen, so the security budget below is a miner-cost model rather than a stake model.

### The security-budget model

An attacker needs more than half the hash rate for long enough to build a competing branch deeper
than the honest one. The cost has three parts:

```
cost  =  (hash_rate_share × network_hash_rate × hardware_cost_per_hash)     capital
       + (the same hash rate × power_per_hash × hours × price_per_kWh)      energy
       + (the value at risk × probability of detection and reversal)        consequence
```

The model is only as good as `network_hash_rate`, and at launch that number is **unknown and
small**. So the honest statement is not a number, it is a bound:

| assumed network hash rate | share needed | capital to rent it (indicative) | verdict |
|---|---|---|---|
| 10 kH/s | 5 kH/s | trivial — a laptop | **no security** |
| 1 MH/s | 0.5 MH/s | one GPU for an afternoon | **no security** |
| 1 GH/s | 0.5 GH/s | a modest farm | weak |
| 1 TH/s | 0.5 TH/s | serious capital | defensible |

**Consequence, stated plainly:** with the emission schedule as written (2,000 atoms decaying to a
tail of 60), the security budget in *value* is zero, because the chain carries no value. PoW is the
right choice precisely because it makes that visible: an attacker's incentive is bounded by what
they can steal, and until the chain holds value there is nothing to steal. What PoW does **not**
give at this size is resistance to a bored attacker with a laptop, and no amount of parameter
tuning fixes that — only value, and therefore a real hash rate, does.

**What this obliges.** E-2 must publish this model with real numbers before launch, and the launch
gate must state the assumed hash rate it is defending against. A chain that launches below its
stated assumption is launching with the security budget unverified.

---

## D4 — Unit, decimals, and the supply cap

**Decision.** One unit is **100 atoms**; two decimal places. The supply cap is **570,100,000 atoms
= 5,701,000 units**.

**Why that cap.** C1's ninth-pass verdict made it load-bearing: the trace-paired balance argument is
a congruence modulo `q`, so it yields integer balance only if every total stays below `q/2`. With
`q = 4,294,966,337`, that is 2,147,483,168 atoms. The schedule reaches 570,093,820 — a factor of
3.77 below the bound, so the cap is a property the emission schedule already had rather than one it
had to be given.

The constants live in exactly one place, `radix_testnet/units.py`, and the chain enforces the cap in
`check_supply`.

---

## D5 — The wallet model is one-time addressing

**Decision.** Every payment goes to a **one-time address**. A meta-address publishes a spend key and
its tag image (`T_K = A'·k`); the sender derives a short shift from a shared secret and computes
`P = A·(k + δ)` and `T = T_K + A'·δ`; the recipient derives `p = k + δ` and spends it.

**Why.** Today the tag is a function of the secret, so an account is spendable exactly once and
change has to cycle through four accounts. That is not a wallet limitation that can be papered over
— it is the same key being reused, and it makes a wallet hold four notes rather than four thousand.

**What it costs.** The derivation is implemented and tested (`stealth.py`), but nothing wires it: a
wallet must receive to a meta-address, scan for outputs it can derive, and spend them (C-8, W-1,
W-2). The scan is the hard part, not the derivation.

**Rejected.** An account model with the tag derived per note. Simpler to reason about, but it
changes the tag construction and therefore C-12 and the withdrawn-tag path, and it gives up
unlinkability that one-time addressing provides for free.

---

## D6 — The launch bar

**Not decided here.** D6 requires the go/no-go gate in `PLAN.md` §G to be signed by **named
owners**, and naming people is not something this record can do. It stays open until the owner
assigns names to the eight gate items.
