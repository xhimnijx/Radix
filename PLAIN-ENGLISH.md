# What we actually have, in plain English

No jargon. This is what exists today, what it does, and what it honestly cannot do
yet. If a sentence here disagrees with the code, the code wins; `STATUS.md` is the
dated record and `AUDIT-PACKET-LATTICE.md` is the technical audit.

## The one-sentence version

We have a working mathematical proof that lets someone demonstrate *"I am allowed
to spend one of these 1,024 coins, and I will not tell you which one"*, on maths a
quantum computer cannot break. It runs and it is tested. Two independent
cryptographers reviewed it in November 2026: the proof itself held up, but they
found that the parameters do not yet justify a 128-bit security claim, and that
the serial number meant to catch double spending could be forged — I reproduced
that forgery, and it has been withdrawn.

So: the privacy half exists and is sound in construction; the anti-double-spend
half does not exist; the parameters are open. It is **not** a coin: there is no
network, no wallet app, no mining.

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
