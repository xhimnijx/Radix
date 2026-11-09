---
title: What Reviewers Found
tags: [reviews, security, honesty]
---

# What reviewers found

Two independent cryptographers reviewed this work. This note records what they found,
including the defects, because a project that hides its bugs is not trustworthy.

The full record is `REVIEW-FINDINGS.md` in the repository; this is the readable
summary.

## The defects, in order of severity

### Q4 — The first tag could be forged (withdrawn)

The original design proved the tag with a separate sigma protocol. A reviewer showed
the tag proof bound only a *derived* row, not the individual components, so a cheater
could supply an unrelated witness.

**The author reproduced the forgery before the reviewer finished writing it up**
(`experiments/tag_forgery_repro.py`). The construction was withdrawn and replaced by
the same-witness extension in [[Linkable Tags]].

### Q3′ — The challenge-difference soundness was ~24 bits, not 128

At the original split modulus, the extraction argument divides by `c − c̃` and that
value must be invertible. In the split regime, `R_q ≅ Z_q^{128}`, so invertibility
requires all 128 coordinates non-zero, and two random ternary challenges agree
somewhere with probability ≈ `2^-24.4`.

**Fix:** choose `q` so the quartic factors are irreducible
(`q = 4,294,966,337`), which makes each slot a field and the failure probability
`~2^-123`. See [[The NTT and the Quartic Decomposition]].

### Q6 — The extracted index was not an index

Reviewer 2 argued that no modulus could fix this, because `r_i` is always a fourth
power. **Reviewer 1 showed that argument was scoped to the split regime**, and this
project verified computationally that at `q = 4,294,966,337` zero of the 32 `r_i` are
fourth powers — so the slots are fields and `v(v−1) = 0` really does force a 32-entry
binary vector.

**Reviewer 2 then retracted the claim explicitly in the record.** That is what a good
review looks like.

### Q5′ — The masking was unsound

The original code used a uniform `2^20` mask and an infinity-norm check. Reviewers
showed this made the *response* bound, not the secret bound, the security parameter —
about `2^50` rather than `2^128`.

**Fix:** Gaussian masks with `Rej1` at a calibrated width, and a true ℓ₂ verifier
bound. See [[Norms and Why They Matter]].

### Q2 — The paper itself is wrong in one place

The `e₁` term in Fig. 9 line 12 is placed at order `c` in the print but must be at
order `c²` for the honest prover's check to pass. Both reviewers agreed the *code* is
right and **the paper double-counts**.

## The corrections reviewers made to *their own* earlier claims

This is worth recording because it is the strongest evidence that the review was real
rather than performative:

| Claim | By | Retracted how |
|---|---|---|
| "No modulus rescues the slot-constancy hole" | Reviewer 2 | Retracted in writing: the argument silently assumed `256 ∣ q−1` |
| "The extraction threshold is `2^-8`" | Reviewer 2 | Retracted: `p` is the point mass of the *reduction*, giving `q^-4 ≈ 2^-128` |
| "`s, s′ ≈ 2^{13–14}` with rejection rate 1.2–1.5" | Reviewer 1 | Retracted: at that width the rate is 1.005–1.02; `M = √(3/2)` sits at `s ≈ 1.57T` |

All three retractions were recorded in `REVIEW-FINDINGS.md` **in place**, with the
retracted text visible, rather than deleted. A wrong number in an audit record should
be seen to be wrong.

## What the reviewers confirmed

- The Fig. 7–9 transcription is correct (with the one paper erratum above).
- The unit checks are necessary and were correctly identified as missing.
- `m = 1` must be refused, and for a stronger reason than the original docstring gave:
  with no `B` block the constraint `⟨1, v_i⟩ = 1` is never proved at all.
- The Rust port and the refusal of `--backend rust` when the binary is missing.

## What no reviewer has done

- Run a lattice estimator.
- Audited the Rust port.
- Reviewed the testnet, the app or the packaging.

[[Status and Honest Limitations]] lists what that leaves open.
