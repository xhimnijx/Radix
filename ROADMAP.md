# Future goals

**North star:** a permissionless, post-quantum, private payment network that
ordinary people can run on ordinary hardware. Same promise as Monero, on maths a
quantum computer cannot break.

This replaces the old Candidate-A plan (now in `archive/candidate-a/PLAN.md`).
It is a plan, not a promise; every milestone has a pass rule written *before* the
work, so a failure is visible rather than argued away.

## Where we are

A working lattice ring signature with a linking tag, a spend layer that checks
balance and refuses reused tags, and 404 tests that run the real protocol.

| Quantity | Value |
|---|---|
| Ring size | 1,024 members (`l^m`, `l = 32`, `m = 2`) |
| Signature | 32.5 KB; 51.6 KB with the tag |
| Prove / verify | ~20 s / ~20 s in CPython, single thread |
| Audit status | none |

That is the cryptography. Everything else a currency needs — network, consensus,
wallet, economics — is absent. See `PLAIN-ENGLISH.md` for the unvarnished list.

## The four questions that decide whether this can exist

Answer these before building anything large. Each has a failure branch.

1. **Is the maths right?** An independent reviewer must be able to read
   `setmembership.py` against Figs. 7-9 and either confirm or refute it, including
   the three documented deviations. *If it cannot be confirmed, B is not viable as
   specified.*
2. **Is the tag sound?** Our tag rests on a Module-SIS assumption about a single
   polynomial image. Somebody must price it: what norm bound, what lattice
   estimator, what concrete security at the chosen parameters. *If it prices below
   the target, the tag needs redesigning or the ring size shrinks.*
3. **Can the pieces become one proof?** Today the tag is a second proof bound to
   the signature. A real transaction wants one witness covering ring, tag, amount
   and range. *If composition costs more than ~100 KB or seconds-to-verify, the
   design does not scale to a phone.*
4. **Does it run on a laptop?** Rust, not Python. Proving and verifying must fit
   the original device budget: 4 GiB desktop, 1 GiB phone.

## Milestone ladder

### R0 — Review packet and frozen parameters *(first pass done, 2026-11-08)*

Two reviews came back, then a second round. The transcription held; the first tag
was withdrawn as forgeable and rebuilt the same day as a same-witness extension
(38.7 KB at k' = 4, one proof). Three things remain, in order of severity:

1. **The challenge-difference term caps soundness at ~24 bits** at this modulus.
   The unit checks fix the `c^2` attack but not the extractor, which needs
   `c - c~` invertible. The fix is an irreducible-quartic `q` (`q = 1 mod 64`,
   `q != 1 mod 128`), which in turn needs the quartic-CRT multiplier to keep
   multiplication fast — no 128-point NTT exists for such a `q`.
2. **The `2^20` mask caps it at ~2^50.** Restore the paper's Gaussian masks and
   `Rej0`/`Rej1`, re-derive `beta` and `beta'`, and price them.
3. **The extracted `v_i` is a 128-coordinate idempotent, not a 32-entry one-hot
   vector.** Anything that consumes it stops parsing. Needs a linear
   slot-constant constraint and an `alpha` slot, which the current `c^2` slot does
   not have spare. This blocks B2 as soon as a range proof wants `v_i`.

`REVIEW-FINDINGS.md` is the record; `REVIEW-REQUEST.md` is the brief for the next
pass.

**Performance, measured 2026-11-09 (`PERFORMANCE.md`).** A depth-2 proof is 14,450
ring multiplications to prove and 4,741 to verify. The Rust arithmetic runs one at
20.1 us, which projects to ~0.36 s to prove -- two orders of magnitude inside the
60 s phone bar -- and ~0.13 s to verify, which **misses** the 100 ms bar once a
phone's 3-5x slowdown is applied. Prove is solved; verification needs batching or
a faster multiplication, and neither is measured yet.

**Exit:** a reviewer signs an attestation over `parameters_hash()`; the modulus is
either SMILE's or a justified choice; the three deviations are resolved against a
reference implementation; the tag assumption is priced.

*Deliverable:* `AUDIT-PACKET-LATTICE.md` turned into a review with answers, not just
questions. The brief to send is `REVIEW-REQUEST.md`. This is the gate the whole project hangs on.

### R1 — One composed transaction proof (old B5)

**Exit:** a single proof covering: one-of-N ring membership, the linking tag, an
amount commitment, and a range proof; ≤ 100 KB; verification ≤ 100 ms in Rust.

*Why one proof:* separately-witnessed sub-proofs leak the link between them and
can be mixed and matched by an attacker.

*Failure branch:* if composition blows the budget, shrink the ring (m = 2 → maybe
smaller rings with a different anonymity argument) or revisit the architecture.

### R2 — Wire format and wallet

**Exit:** canonical encoding for spend, note, address and proof, with test
vectors; a wallet that can create outputs, scan them, and build a spend offline;
keystore with the existing Scrypt/AES-GCM discipline. The current `radix_core`
codecs are the starting point, but they were written for Candidate A and must be
re-derived, not inherited blindly.

### R3 — Node and network

**Exit:** two nodes gossip spends, keep a shared output set, and reject malformed
or double-spending transactions; a spend propagates in under a second on a LAN;
the node runs in bounded memory on a 4 GiB box.

Nothing exists here yet. This is the largest engineering gap, and it is ordinary
software engineering — but it is also where most of the elapsed time will go.

### R4 — Consensus

**Exit:** a written decision on how blocks are produced (proof-of-work is the
honest default for permissionless; anything else must justify itself), a
specification, and a reference implementation that converges under partition and
reorg.

This is a *governance* decision as much as a technical one. It cannot be deferred
past R3.

### R5 — Public testnet

**Exit:** strangers can join, mine or not, send each other worthless coins, and
break it. No value, no promises, a published incident log.

### R6 — Economics and genesis

**Exit:** supply schedule, emission, fee market, genesis block construction, and
an argument for why the distribution is not obviously unfair.

### R7 — Audit and gate

**Exit:** at least one independent cryptographic audit with findings closed, plus
a second opinion on consensus; the launch gate opens only by a signed,
hash-pinned decision. The gate exists today and is closed; it should never open
by turning a flag.

## What would make us switch to Candidate C

Candidate C (Jolt zkVM + Akita PCS) is archived, not deleted. Re-open it if, and
only if:

- the reviewer finds a **soundness** problem in the SMILE construction that is not
  repairable, or
- R1 composition cannot fit the device budget even after shrinking the ring, or
- the tag assumption prices below ~100 bits at usable parameters.

Difficulty alone is not a reason to switch. A proven dead end is.

## What we will not do

- Open the mainnet gate without a signed review.
- Ship a "testnet" that holds value.
- Publish a size or speed claim that a test in this repository does not support.
- Re-introduce Candidate A's prover as a workaround for a hard problem here.

## The next three things

1. Hand `AUDIT-PACKET-LATTICE.md` to a cryptographer and get question 1 answered.
2. Port the proving path to Rust and re-measure — the 20 s Python figure says
   nothing about the real device budget.
3. Write the range-proof and composition design (R1) on paper before writing code,
   the way the SMILE figures were transcribed before they were implemented.
