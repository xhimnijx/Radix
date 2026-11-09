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

### Option A — SMILE's own confidential-transaction construction

The paper this project implements **already contains a confidential-transaction
protocol**, and section 4.5 gives its sizes. Figures below are from
`studies/2021-564.pdf` (ePrint 2021/564), pages 1, 48, 55 and 56.

| What | Size |
|---|---|
| Ring signature alone, ring size `2^5` | 16 KB |
| Ring signature alone, ring size `2^10` | **17.27 KB** |
| Ring signature alone, ring size `2^25` | 21.53 KB |
| **Full CT proof, 2 inputs / 2 outputs, ring size 1024** | **26.49 KB** |
| Full CT proof, 100 inputs, ring size 1024 | 344.26 KB |
| A single output coin | 3.78 KB |

**This reverses the estimate I wrote in the first draft of this note.** I guessed that a
range proof would add 15–20× and blow the size budget. The paper's own number for a
*complete* confidential transaction — hidden amounts, hidden sender, ring size 1024 — is
**26.49 KB**, which is *smaller than our current 24.5 KB untagged proof for a single
input.*

The consequence is the opposite of the one I expected:

- **Amounts are affordable.** At 26.49 KB per transaction, ten transactions per
  120-second block is 69 GB/year, and one per block is 7 GB/year — inside the 100–300 GB
  budget set in `docs/CONSENSUS.md`.
- **Our implementation is the problem, not the design.** We are at 24.5 KB for one
  input with visible amounts, against the paper's 26.49 KB for two inputs and two
  outputs with hidden amounts. Roughly a 2.5× gap, and it is *compression*, not
  cryptography.

### Where the gap comes from

The paper is explicit about three optimisations this implementation does not make
(pages 55):

1. **Compressed public keys** — the Dilithium technique of transmitting `t0` rounded
   modulo `2^D` rather than in full.
2. **Bai–Galbraith compression** — the MLWE error is not opened explicitly; a rounded
   `w'` is sent and the remainder masks the error, with a second rejection step.
3. **Entropy coding of `z`** — the paper computes its bandwidth by the entropy of the
   discrete Gaussian rather than by `W·d·log q`. This is where most of the saving is:
   a Gaussian of standard deviation `sigma` costs about `log2(sigma sqrt(2 pi e))` bits
   per coefficient, not `log2(q)`.

Point 3 alone explains most of the difference, and it is a *representation* change that
does not touch the proof's soundness — which makes it the highest-value optimisation
available, and a natural next work item.

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

The question is no longer whether amounts fit — the paper says they do, at 26.49 KB for
a 2-in/2-out transaction. The questions are:

1. **Close the compression gap first.** 24.5 KB → the paper's ~17 KB ring signature is
   a representation problem (entropy-coded `z`, compressed keys, Bai–Galbraith), not a
   cryptographic one. Until that is done, we are not comparing like with like, and every
   amount-related estimate inherits the overhead.
2. **Then implement the CT construction from section 4.5**, which the paper already
   specifies for these parameters.
3. **Then re-measure.** If a real 2-in/2-out proof lands near 26.49 KB, amounts cost
   less than the current tagged transaction and the size argument disappears.

**Still no implementation in this note.** The ordering is the recommendation.

## Questions for C1 and C2

1. **Is the 26.49 KB figure for 2-in/2-out achievable in an implementation** that keeps
   our `alpha`-slot structure, or does it depend on the specific tensor encoding in the
   paper's section 4.5? The difference decides whether this is a porting job or a
   redesign.
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
