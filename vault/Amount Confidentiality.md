---
title: Amount Confidentiality
tags: [design, research, open]
---

# Amount confidentiality

> [!warning] Status: designed, not implemented. This is the largest functional gap.
> Today every output carries its value in the clear. A transaction proves that the
> inputs sum to the outputs plus the fee, and nothing else. Everything below is a
> design note, and the recommendation is deliberately not "do what Monero does".

## What has to be true

For an output of value `v` in a transaction with inputs summing to `V_in`:

1. **Hidden.** No observer learns `v` from the chain.
2. **Non-negative.** A value of `-5` would mint money out of a negative output, so `v`
   must be proven to lie in `[0, 2^n)` for some `n` (64 is the usual choice).
3. **Balanced.** `Σ v_in = Σ v_out + fee`, checkable without learning any `v`.
4. **Post-quantum.** The whole point of this project. See the next section.

## Why Bulletproofs are the wrong answer here

Monero uses Pedersen commitments over the Ed25519 curve plus Bulletproofs. It is
tempting to copy it, and **it would quietly destroy the project's central claim.**

- A Pedersen commitment `C = v·G + r·H` hides `v` only while discrete logarithms are
  hard in that group.
- Bulletproofs' soundness rests on the same assumption, through its inner-product
  argument.

A quantum computer breaks discrete log on a curve in polynomial time with Shor's
algorithm. Adding a curve-based commitment to a lattice-based ring signature would put
a **classically-secure** component into a **post-quantum** protocol, and the composite
would be exactly as quantum-vulnerable as the weakest part. The transaction would still
be "quantum safe" in the marketing and not in the mathematics.

So the answer cannot be an EC range proof. It has to be a range proof over the same
ring, or no range proof at all.

## The options that survive the post-quantum requirement

### Option A — MatRiCT / MatRiCT+ (the closest existing work)

Esgin, Zhao, Steinfeld, Liu, and later Kuchta et al., built **MatRiCT** (2019) and
**MatRiCT+** (2021): lattice-based RingCT, which is Monero's protocol rebuilt over
`R_q`. They prove exactly the four properties above, with ring sizes in the same range
as ours (hundreds to a thousand), and they are the nearest thing to a published
blueprint for what Radix is building.

Why it is the right first place to look:

- same algebraic setting, so the commitment and the ring signature can share a modulus
- the range proof is built from the *same* commitment machinery rather than a second
  proof system
- the papers discuss the decoy-selection and linking problems a real ledger has

Why it is not automatically the answer:

- **I have not verified its numbers in this session.** Any figure for proof size or
  verification cost in this note is mine and an estimate; quote the paper.
- Its construction makes different choices from SMILE, and the `alpha`-slot machinery in
  [[The Set Membership Proof]] does not map onto it directly.
- Ring signatures of this shape are **large**. Ours is already 32 KB for one input. A
  RingCT transaction with a range proof on top is plausibly 40-60 KB per input, and that
  number decides whether the design is usable at all (see the chain-growth arithmetic in
  [[Status and Honest Limitations]]).

### Option B — LaBRADOR and lattice proof systems

LaBRADOR (2022) proves knowledge of short vectors satisfying linear relations, and is
more flexible than a fixed RingCT template: a range proof is "I know a short `v` whose
commitment is `C`, and `v` is in range". Proofs are tens of kilobytes and the prover is
expensive.

The attraction is that it could *replace* the custom machinery with one general
argument. The cost is that the whole design becomes "a general proof system", which is a
much larger and much less audited surface than a purpose-built range proof.

### Option C — hash-based arguments (Aurora, Ligero, STARKs)

Transparent and post-quantum, but proofs are hundreds of kilobytes and provers are
seconds to minutes. For a currency that stores every proof forever, that interacts badly
with the 39 KB transaction already being too large.

**A second proof system in every transaction is a composition risk as much as a size
risk.** Whatever is chosen has to be analysable together with the ring signature, not
beside it.

### Option D — denominations, using the machinery that already exists

This one is speculative and specific to our primitives, which is why it is worth
writing down.

We already have a proof that *"the thing I hold is one of these N public keys"* — the
`alpha`-slot set membership with `32^depth` keys. An output does not have to commit to an
arbitrary 64-bit integer. It could commit to **one of a fixed set of denominations**:
{1, 2, 5, 10, 20, 50, 100, …} scaled by powers of ten, say 1,024 denominations in total.

- **The range proof becomes a membership proof**, which is the one thing this codebase
  already does well.
- Balance still works: commitments are additively homomorphic over `R_q`, so the sum
  check is unaffected.
- **Privacy is weaker in one specific way**: an observer learns the transaction's total
  if the denomination set is small and the graph is small. With many denominations and
  many inputs it degrades gracefully, but it is not the same guarantee as a hidden
  integer.

Cost: change outputs need several notes (a 137-unit payment is 100+20+10+5+1+1), which
multiplies transaction size by the decomposition length. With a 39 KB proof per input,
that is fatal unless the notes are cheap.

**Verdict: elegant, probably impractical, worth one experiment before dismissing.**

## Recommendation

**Do not implement anything yet.** The order should be:

1. **Read MatRiCT+ properly** and extract its range-proof construction, proof sizes and
   verification cost, and check whether the `A`-matrix structure can be shared with
   SMILE's. If it can, most of this note collapses into "adapt MatRiCT+".
2. **Decide the size budget first.** A transaction is 39 KB today. If the target is a
   chain someone will download, the *total* per transaction cannot exceed roughly 60 KB,
   which leaves ~20 KB for the range proof and everything else. That constraint should
   drive the choice, not the other way round.
3. **Only then** choose between A and D, and write the statement shapes down before any
   code.

## Questions for C1 and C2

1. **Is MatRiCT+ the right starting point**, or is there a construction better suited to
   SMILE's `alpha`-slot structure? In particular, does its range proof need the same
   `A` as the ring signature, or a second matrix?
2. **Can the range proof share the commitment matrix `B`** we already use, or does it
   require independent randomness that doubles the commitment width?
3. **What is the smallest post-quantum range proof for 64-bit values** in a setting where
   the commitment is `A·r + G·v` over `R_q` with ternary `r`? If the answer is "hundreds
   of kilobytes", say so, because it changes the design rather than the parameters.
4. **Is Option D (denominations) sound as a privacy mechanism**, or does the
   denomination decomposition leak more than it saves? My instinct is that a
   power-of-ten decomposition leaks the magnitude of a payment, which is often the thing
   you most want hidden — but I would rather be told than guess.
5. **Does adding amounts change the soundness of the tag?** The tag is `A'·s` over the
   same secret; if the statement grows, does `k'` need revisiting?

## Related

- [[The Set Membership Proof]] — the `alpha` slots and what they could carry
- [[Linkable Tags]] — why the statement shape matters
- [[One-Time Addressing]] — the other research risk, and it interacts with this one
- [`REVIEW-REQUEST.md`](../REVIEW-REQUEST.md) — where these questions are being put
