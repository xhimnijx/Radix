---
title: One-Time Addressing
tags: [design, research, open]
---

# One-time addressing

> [!warning] Status: unsolved, and it is the second research risk after range proofs
> This note exists so the problem is written down before it is needed. There is no
> implementation, and the options below are not equivalent — two of them are known to
> fail, and the one that works costs an address format nobody wants.

## The requirement

Every output needs its **own** keypair, for two reasons that are easy to conflate:

1. **Privacy.** If all of a wallet's outputs share one key, the ring signature hides
   *which* key but the wallet's outputs are trivially linkable to each other.
2. **The tag is per key.** `T = A'·s` is a function of the secret, so one keypair can be
   spent exactly once. This is not cosmetic — it is why the testnet wallet has four
   accounts and moves change to the next one ([[The Wallet and Its Accounts]]).

So a wallet with `n` spendable outputs needs `n` distinct secrets, and three parties
have to agree on them:

- the **sender**, who must be able to create the output without interacting with anyone;
- the **recipient**, who must recognise and later spend it;
- **nobody else**, who must not be able to link outputs to each other or to the
  address.

## Why Monero's construction does not port

CryptoNote derives an output key as `P = H(r·V)·G + B`, where `B` and `V` are the
recipient's public spend and view keys, and `r` is a sender-chosen scalar. The sender
computes `H(r·V)` because it knows `r` and the public `V`; the recipient computes the
same value because it knows `v` and receives `r·V`. The shared secret comes from a
**Diffie–Hellman** exchange, which gives both sides the same scalar while keeping the
private component private.

There is no lattice analogue of that operation. `A` is linear over `R_q`, not a bilinear
group, so there is no `a·(b·G) = ab·G = b·(a·G)` to exploit. Any construction here must
either avoid a shared secret or add a new primitive.

## The options, including the ones that fail

### Option A — a shift by a small public scalar (fails on the secret bound)

The nearest lattice analogue: publish `P_spend = A·s_spend` and `P_view = A·s_view`, let
the sender choose a scalar `r`, publish `r`, and set

```
shift    = H(r)
pk_out   = P_spend + shift · P_view        = A·(s_spend + shift·s_view)
s_out    = s_spend + shift · s_view        (recipient only)
```

The algebra works and the sender cannot spend (it does not know `s_spend`). **It fails
on the norm.** The proof requires `‖s_out‖_∞ ≤ μ = 5`. A shift that is a random residue
mod `q` makes `s_out` enormous, so the scheme no longer proves membership of a short
preimage. To keep `s_out` short, `shift` must be a *small* scalar — and a small scalar
is guessable when it is public, which collapses the privacy: an observer can try the
few thousand possible shifts and link outputs.

**Conclusion: this is the natural construction and it does not work.** Anyone who
proposes it should be shown this paragraph.

### Option B — a pre-generated pool of one-time keys (works; ugly)

The recipient publishes a list of `N` public keys, each with a known secret, and the
sender takes the next unused one and names it by index.

- **Works** with no new primitive and no new assumption.
- **Address size** is `N × 2 KB`: a 1024-key address is 2 MB. Base64url of one key is
  already 2,735 characters ([[The Android App]]), so this is not an address, it is a
  file.
- **Coordination**: the sender must know which indices are unused, or the recipient
  must scan a window. Both leak usage patterns.

**Conclusion: usable for a testnet or a small closed group; not a currency address.**

### Option C — add a KEM and derive the key from the shared secret (fails on knowledge)

Encapsulate to the recipient with a lattice KEM; both parties learn the shared secret
`k`; set `s_out = H(k)`.

**Both parties learn it.** The sender can spend the output. This is the trap that looks
like it solves the problem and does not.

### Option D — a designated-sender or stealth scheme from a NIZK

Instead of deriving keys, have the sender prove "this output is for whoever can satisfy
predicate `P`", with the recipient deriving the spending condition from public data. This
is the approach taken by newer privacy designs. It needs the composition machinery this
project does not yet have (see [[The Set Membership Proof]] on the `alpha` slots) and it
reintroduces a proof per output.

**Conclusion: plausible, but it is a redesign, not a feature.**

## What I would do

**Short term (testnet):** keep the four-account wallet and be explicit that it is a
harness limitation. It already forces change to move between accounts, which is what
makes the tag behave correctly.

**Medium term:** Option B behind a "payment code" that the recipient can rotate, with a
windowed scan. It is honest, it needs no new cryptography, and it lets a real wallet
hold more than four notes. The cost is an address that is a list, not a string.

**Long term:** a proper answer needs either a bilinear-like structure that lattices do
not have, or the NIZK route in Option D, which depends on the composition work that the
`alpha`-slot discussion in [[The Set Membership Proof]] is already circling.

## Questions for C1 and C2

Included in [REVIEW-REQUEST.md](../REVIEW-REQUEST.md) as Q-F's neighbours, but
stated here in context:

1. Is there a published lattice stealth-address construction that does not require a
   Diffie–Hellman-like operation? If it exists, this note is obsolete and that is the
   best possible outcome.
2. If the answer is "no, and the norm bound is the obstruction", is there a variant of
   the proof that tolerates a *large* shift in `s_out` — for example by proving
   smallness of `s_spend` and `s_view` separately and carrying the shift as a public
   scalar? That would repair Option A, and it is the only route I can see to a normal
   address format.
3. Does Option B have a failure mode I have missed, beyond address size and usage
   leakage?

## Related

- [[The Wallet and Its Accounts]] — why accounts are spendable once today
- [[Linkable Tags]] — the tag is a function of the key, which is the reason for all of this
- [[Status and Honest Limitations]] — where this sits in the order of work
