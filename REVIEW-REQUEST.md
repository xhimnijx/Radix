# Review request: seventh pass

For C1 and C2. Both papers are now in the repository and read. Three questions, one of
them decisive.

Full history: `REVIEW-FINDINGS.md`. This page is only what is open.

## What your last answers changed

| Your answer | What happened |
|---|---|
| `[25]` = Lyubashevsky–Nguyen–Seiler, CCS 2020, ePrint 2020/1183 | Obtained and read. The carry proof is the **relaxed range proof** (p. 5), not a bit-decomposition |
| Carry lives in the same `B′₀`, same rejection | Confirmed by the text: for addition the carry is binary (p. 4); it only grows when summing many integers, which is our case |
| Theorem B.1′ signed, conditional on the sampler and ring binding | **Both conditions are now closed** — see Q-P |
| `k′ = 1` | Implemented. Tagged proof 24,832 → **22,528 B**, tag 2,048 → **512 B**, total 26,880 → **23,040 B** |
| Your proposed repair is a deanonymisation | Accepted and recorded as a warning. `2025-112` §5.3 supplies the fixed construction — see Q-N |

## Measured, for context

- Untagged proof **21,760 B** (from 32,512 after bounding and packing both responses).
- Cross-language acceptance holds both ways at this size.
- Relaxed range proof: honest carry rejected **0 of 50**; coefficient inflated 40× caught
  **50 of 50**; inflated to `q/3` caught **50 of 50**.
- Real proof of work, LWMA-90, block rewards with a tail, two-node fork reconciliation.

---

## Q-N (decisive). Is `XOF(S)` short in 2025-112?

ePrint 2025/112 §5.3, p. 16–17. The recipient registers a spend Kyber key `K = (tK, ρK)`
and a view key `V = (tV, ρV)`; the sender encapsulates to `V`, obtaining `(R, S)`, and
computes

```
P = XOF(ρK)·XOF(S) + Decompress_q(tK, dt)
```

while the recipient derives `p = k + XOF(S)`, and `A·p + e1 = P` holds with
`e1 = Decompress_q(tK) − XOF(ρK)·k`.

**This solves the derivation problem.** The sender knows `S` and can compute `P`, but
cannot compute `p` without `k`. That is exactly the property the earlier public-shift
proposal lacked.

**The problem is the norm.** Our tag is `A′·s` and the proof requires `‖s‖∞ ≤ μ = 5`. If
`XOF(S)` is a hash output reduced modulo `q`, then `p` is uniform, which is a sound MLWE
secret for a KEM but is **not** something our proof can establish knowledge of as a short
vector.

**Asks:**

1. Does the 2025-112 construction intend `XOF(S)` to be **short** — sampled from a CBD or
   similar distribution — or uniform? The paper does not say in the protocol description.
2. If it must be uniform, does the security analysis break if it is made short? In other
   words, is a short `XOF(S)` a legitimate variant or a different protocol?
3. If short is legitimate, is `p = k + XOF(S)` then within a bound the SMILE proof can use,
   or does `k`'s own width plus the shift push it out of range?
4. If none of the above works, is there a stealth construction whose output secret is
   provably short and **tag-compatible** — i.e. one where `A′·p` can be computed by the
   sender without learning `p`?

This is now the single blocker on a hidden-amount launch. Everything else has a known
construction.

## Q-O. Digit membership, now that the relaxed proof exists

C1's earlier answer was that the digit proof is **not** the ring set-membership: it is two
bits per base-4 digit (`d = 2b₁ + b₀`), each proven with `v(v−1) = 0`, needing its own
α-slot budget — 64 bit-constraints per amount.

The relaxed range proof from `[25]` now bounds a *vector* cheaply, which raises a question
about whether the two are complementary or redundant.

**Asks:**

1. Do we still need per-digit binaryness at all, given the relaxed proof? My reading is
   yes: the relaxed proof bounds `‖f‖`, which gives small but *signed* coefficients, and
   non-negativity is exactly what a range proof must establish. Confirm or correct.
2. If both are needed, in what order — digits first (proving each is 0..3) and then a
   relaxed carry bound on the sum, or the relaxed proof on the digit vector directly?
3. What is the **α-slot budget** for 64 bit-constraints per amount? The current `c²` slot
   carries `m+1` constraints for the ring selector. Does the digit proof reuse that slot,
   take new slots, or sit in a separate section of the statement?
4. Does either C1's two-bit form or a relaxed bound interact with the `q^{-4}` uniformity
   term that C2 booked at `≈ 2^-121`? C1 said the per-constraint probability is unchanged;
   I would like that confirmed for the relaxed proof, which introduces a new matrix `R`.

## Q-P. Do the two conditions you named now close the statement?

C2 signed Theorem B.1′ and said: *"I do not sign it as a statement about the security of
the implementation, because two things sit outside the theorem and are not yet closed: the
mask sampler … and the ring binding."*

Both are now implemented, and both changed after that answer was written:

1. **Mask sampler.** The responses now come from a **discrete** Gaussian read from a single
   cumulative table that Python reads at runtime and Rust `include_bytes!`s. There is one
   distribution, so the two implementations cannot sample differently. A test compares
   `from_uniform(width, uniform, sign)` across both languages over 420 points — exactly,
   not statistically. Truncation is at 8σ, tail `2^-49.5`.
2. **Ring binding.** `ring_digest` — SHAKE256 over the ordered encoded keys — is absorbed
   into the transcript before `w`, in both languages. A proof made against one ring is
   rejected against another; there is a test for that specifically.

**Ask:** with those two closed, does Theorem B.1′ plus the estimator band now constitute a
defensible security statement at ~2^158, as you said it would? If something else sits
outside the theorem that we have not named, this is the moment to say so.

## Still open from earlier passes

| Item | Ask |
|---|---|
| **Estimator run** | You cannot run it; neither can this machine (no SageMath). C2's band (2^143–2^173, 2^160–2^190) is what we have. **Which `red_cost_model` should the paper name**, and is the band quotable with the `M = √1.5` caveat you supplied? |
| **Errata** | Both confirmed by derivation. If either of you can obtain the 2022-05-20 revision, a diff would let the record say "erratum" rather than "suspected erratum" |

## Reproducing

```powershell
python -m pytest -q -m "not slow"    # 496 collected, 1 known xfail
cd proof_rust && cargo test          # 74 passed
python experiments/estimate_sis.py --check
```
