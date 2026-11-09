---
title: Fiat-Shamir and the Transcript
tags: [protocol, implementation]
---

# Fiat–Shamir and the transcript

The proof is designed as an *interactive* conversation: commit, receive challenge,
respond. To make it non-interactive the challenge is replaced by a hash of everything
said so far. This is the **Fiat–Shamir transform**, and it is only sound if the hash
input includes every message in the right order.

## The transcript object

`transcript.py` and `transcript.rs` implement an absorb-then-squeeze transcript over
**SHAKE256**:

```python
tx = Transcript(PROOF_TAG)
tx.absorb(b"message", message)
tx.absorb(b"w", encode(w))
tx.absorb(b"t", encode(commitment[:head_length]))
c_prime = draw_ternary(tx, b"c-prime")
```

Each `absorb` appends a length-prefixed frame: `[len(label)] label [len(payload)] payload`.
Each `challenge` re-hashes the whole accumulated byte string plus a squeeze request,
takes the requested bytes, and then absorbs the result too.

## Why every detail matters

A challenge must be unpredictable to the prover **at the moment it commits**. That
requires:

1. the message, because otherwise a proof could be replayed for a different
   transaction;
2. the commitments, because otherwise the prover could choose them after seeing `c`;
3. `w`, which the verifier recomputes as `B₀z − c·t₀`;
4. the label and domain tag, so a challenge from one position cannot be reused in
   another.

Get any of these wrong and the proof still *works* — it just stops being sound. That is
why the ordering is stated precisely in
[[The Set Membership Proof]] and why a port must match it byte for byte.

## The domain tag

Every protocol has its own tag, e.g. `b"radix/b/setmembership/v1"`. Two different
protocols must never derive the same challenge from the same data, or a proof from one
could be replayed in the other.

## How the port proved the transcript is right

The Rust port reproduces, byte for byte:

- `draw(b"alpha")` after absorbing `("message", b"hello")` → digest `d35674e8…`;
- `draw_ternary(b"c")` → `(0, 0, −1, 1, 1, 0, 1, 0, …)`;
- SHAKE256 of the empty string, `"abc"`, and a 500-byte input, against `hashlib`.

The strongest evidence is indirect: the Rust verifier accepts a Python proof, and the
Python verifier accepts a Rust proof. Both would be impossible with a mismatched
transcript.

## The "why is there a squeeze request frame" question

Because absorbing the *request* before squeezing means the transcript commits to
"asked for `c` with length 32" before the answer exists — so the same transcript
cannot be coerced into producing a different-length output that collides.

## Next

[[Linkable Tags]] — the extra piece Radix adds so a double spend is detectable.
