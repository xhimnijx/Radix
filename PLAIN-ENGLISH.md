# What we actually have, in plain English

No jargon. This is what exists today, what it does, and what it honestly cannot do
yet. If a sentence here disagrees with the code, the code wins; `STATUS.md` is the
dated record and `AUDIT-PACKET-LATTICE.md` is the technical audit.

## The one-sentence version

We have a working mathematical proof that lets someone demonstrate *"I am allowed to
spend one of these 1,024 coins, and I will not tell you which one"*, on maths a quantum
computer cannot break. It runs, it is tested, it is written twice in two languages that
agree, and two independent cryptographers have now put a number on it: the hard problem
underneath is worth about **2^158** operations — far beyond anything a classical or
quantum computer can do today.

## What changed since this page was first written

This document used to say the proof had been reviewed and the parameters were unpriced.
That is now out of date in three ways, and the corrections are more interesting than the
original text.

**The parameters are priced, and they are fine.** Two cryptography reviewers, working
independently, put the hard problem at roughly 2^158 and 2^175 operations. The earlier
worry that it might be far weaker came from a comparison that was backwards: the proof's
tolerance sat *below* what an attacker could reach, which means the attack is harder than
expected, not easier.

**I had the numbers wrong.** My own estimate used the wrong dimension for one of the two
problems — I used 23×128 where the correct figure was 33×128. The number 23 is the count
of commitments, which happens to equal the width in one special configuration. That is
the second time in this project that mixing up "how many commitments" with "how wide the
proof is" produced a wrong answer, and both times an independent implementation caught
it rather than a review.

**It now runs fast enough for a node.** The same proof can be produced by a second
implementation written in Rust, which agrees with the first in both directions, and a
node checking a spend goes from 40 seconds to under half a second — about 91 times
faster. That is the difference between a demonstration and something you could run on a
phone's behalf.

**And it fits in your pocket.** There is an Android app, 24 KB, that talks to a node on
your network. It holds no keys: the node signs. That limitation is stated in the app
itself.

## What it is trying to be

Monero, but built on maths that a quantum computer cannot break. Monero hides who
is paying by mixing your coin with 15 decoys drawn from real coins. That is a
*ring signature*: a signature that proves "one of these keys signed" without
saying which.

Monero's ring signatures rest on the same class of maths as ordinary internet
encryption (elliptic curves), which a large quantum computer would break. Ours
rests on *lattice* problems, which no known quantum algorithm solves.

## What exists today, piece by piece

Think of a coin as a locked box with a public padlock. The owner knows the key.

| Piece | Plain English | State |
|---|---|---|
| **The lock** (public key) | A padlock derived from a secret key, using lattice maths | works, tested |
| **The ring signature** | "One of these 1,024 padlocks is mine and I can prove it, without saying which" | **works**, 32.5 KB, ~20 s to make and ~20 s to check in Python |
| **The tag** | A serial number that is *the same* every time you spend the same coin, so the network can refuse a second spend | **works, rebuilt.** The first version was forgeable (a review found it, I reproduced it); it is now folded into the same proof as the signature, 33.5 KB. Same-note linkability only |
| **The spend** | "Here is a signature, here are the coins I am creating, and the values balance" | works, checks balance and refuses a reused tag |
| **Encrypted notes / addresses** | The message to the recipient, sealed with post-quantum key exchange and AES | works (inherited from the earlier design), tested |
| **The mainnet switch** | A deliberately locked door that refuses to open until a human signs off | works, and it is **closed** |

The test suite is 404 checks. The fast ones run in 16 seconds; the ones that make
real proofs take about 20 seconds each, which is why the full run is ~7 minutes.

## What we do NOT have

Being blunt, because this is the part that decides whether the project is real:

- **No network.** No nodes, no peer-to-peer gossip, no way for two computers to
  agree on anything.
- **No consensus.** No rule for who adds the next block, no proof-of-work, no
  finality. This is the single largest missing piece of a *currency*.
- **No wallet for this design.** The existing wallet belongs to the old
  Candidate-A track. The new pieces have an API, not an app.
- **Values are not hidden.** Coins carry an amount in the clear. Monero hides
  amounts with range proofs; we have not built that yet.
- **No audit.** Nobody qualified has reviewed the maths. It is a research
  prototype and it says so in every document.
- **Not the paper's parameters.** The modulus is a placeholder of the right size,
  not SMILE's exact one. Every security estimate depends on that number.

## What "post-quantum" does and does not mean here

It means: every primitive in the design is chosen so that *known* quantum attacks
do not apply. Lattice problems are believed hard for quantum computers, and the
signature is built directly on them rather than on elliptic curves.

It does **not** mean "proven safe forever". It means "no known shortcut, and the
assumptions are written down". Nobody can honestly promise more than that, for any
system.

## How private is it, honestly

- The verifier learns **that** one of 1,024 keys signed, and nothing about which.
  That is the same privacy Monero's ring signature gives, at a ring size of 1,024
  instead of 16.
- The verifier learns a **tag** that is the same for two spends of the same coin,
  so double spending is detectable. It is a random-looking value, not an
  identity. Caveat: the tag is only collision-resistant for *distinct* notes at
  the larger parameter setting, which is not the default.
- The verifier currently learns the **amount** (see the gap above).
- Timing and network-level privacy are not addressed at all.

## If you showed this to a cryptographer today

They would find: a faithfully implemented version of a published scheme
(ePrint 2021/564), three transcription deviations documented in the module's
header, one novel addition (the tag) whose security rests on a written assumption,
a test suite that runs the real protocol rather than mocking it, and no audit.

That is a good starting position for a review. It is not a product.
