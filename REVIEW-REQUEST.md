# Review request: eighth pass

For C1 and C2. Three questions, one of them blocking the next build step.

Full history: `REVIEW-FINDINGS.md`. This page is only what is open.

## What your seventh-pass answers changed

| Your answer | What happened |
|---|---|
| `XOF(S)` must be short, and for a reason the paper omits | Recorded: with uniform `XOF(S)` the stealth key does not decrypt, not merely does not fit `μ` |
| The obstruction is `e1`, not the norm | `noisy.py`: `[A | I_k]`, witness `(p, e1)`, tag rows `[A' | 0]`, 7 tests — including that the exact relation **rejects** a valid stealth key |
| Two bits per digit; the α budget is per *vector* | `digits.py`: **2 polynomials for 64 bits**, `constraint_count(4) == 9`, not 256. A test fails if that regresses |
| The relaxed proof bounds `‖f‖`, not its sign; digits are still needed | `range.py`: five checks as one verifier, tested |
| `[25]` p. 4 gives the addition relation | `carry.py`: `a + b + f(X−4) = c` over polynomials, with a test that a perturbation vanishing at `X = 4` is still rejected |

## Measured

- 558 Python tests, plus 74 Rust; cross-language acceptance at 21,760 bytes.
- Tagged proof 22,528 B, tag 512 B, total **23,040 B** at `k' = 1`.
- A chain adopted from a peer is now **verified**, not trusted: `rebuild` defaults to
  `verify_transactions=True`.

---

## Q-Q (blocking). The α-slot layout for the range statement

The statement is fixed and tested as a Python specification:

1. every bit is a bit — `b(b−1) = 0` slotwise;
2. every digit is `2b₁ + b₀` — ties committed bits to committed digits;
3. every digit ∈ {0,1,2,3};
4. the digit polynomials add up with an explicit carry;
5. the carry is small — binary for two terms, bounded by the relaxed argument for many.

C2's budget says **3 α per amount**: two for the 64 bits (one per packed polynomial) and
one for the carry. What is missing is the *layout*, and I would rather ask than guess:

1. **Where do the two bit-polynomials' constraints sit?** New α slots, or folds into the
   existing `c²` slot? C2 said they must be new because the `m+1` existing α's are paired
   one-to-one with the ring selector's `v_i` and the pairing is the mechanism. Confirm
   that, and say which slots the new ones take.
2. **How does the carry's α pair with the relaxed challenge `R`?** C1 said the two are
   booked separately — `q^-4` for the `R_q` challenges, `2^-n` for `R`. Does the carry α
   enter the transcript before or after `R` is derived, and does `z = R f + y` use the same
   masked opening as the rest of the statement or its own?
3. **Does constraint 4 need its own α at all**, given that `carry.holds` is a linear
   relation over the digit polynomials and linear relations are what the framework already
   proves? If it rides on an existing linear proof, the budget is 2 per amount plus one
   for the relaxed bound, and the per-amount cost drops again.
4. **Is the digit count 32 or 33?** 32 digits cover `4^32 = 2^64` exactly, so the largest
   amount is `2^64 − 1` and carries can leave a 33rd digit. Does the statement need that
   extra digit to be constrained to zero, or does the carry absorb it?

## Q-R (to C2). Re-price `k'` now that both ends are visible

With `k' = 1`, `W = κ + λ + rows + 2m + 1 = 30` rather than 33, so B₀'s dimension is
**3840 rather than 4224** and its Core-SVP estimate is **2^167 rather than 2^175**.

That coupling was not in your k′ analysis and I did not see it when the change was made.
The trade is now stated at both ends:

| | `k' = 4` | `k' = 1` |
|---|---|---|
| B₀ (ADPS16) | 2^175 | **2^167** |
| Tagged proof + tag | 26,880 B | **23,040 B** |
| Module equations in `s` | 8 | 5 |

The decision still favours 1 — 2^167 clears 128 by 39 bits, and the binding relation is
still A at 2^158 — but confirm, or tell me to put it back to 4.

## Q-S (to C1). The extraction argument for `[A | I_k]`

You wrote that the noise-aware statement "costs `k` extra secret components, the
corresponding `z'`/commitment elements, and **a new extraction/soundness argument**; the
`e1` is short, so the norm side is manageable."

The linear algebra is built and tested: `A_noise = [A | I_k]`, witness `(p, e1)`, tag rows
`[A' | 0]`, and the exact relation `A·p = pk` demonstrably rejects a valid stealth key.

**I cannot write that argument.** It is a theorem, not code. Specifically I do not know:

1. Does the extraction produce `(p, e1)` both short, or only their combination, and does
   the `v_i ∈ {0,1}` conclusion still follow when the witness is split this way?
2. Does `I_k` change the M-SIS instance the signature rests on — `[A | I_k]` is 4×17 where
   `A` was 4×13 — and if so is the new instance stronger or weaker than A at 2^158?
3. Does the tag's `[A' | 0]` padding create a kernel that a forger can exploit, given the
   tag row now has four zero columns?

## Your conditions are met

C2 signed Theorem B.1′ conditionally: *"two things sit outside the theorem and are not yet
closed: the mask sampler … and the ring binding."*

Both are closed, and both changed after that answer:

1. **Sampler.** One cumulative table, read at runtime by Python and `include_bytes!` by
   Rust, so the two cannot sample differently. Truncated at **12σ**, giving a per-coefficient
   tail of `2^-107.8` and an aggregate of about `2^-101.8` over a response — below the
   paper's `2^-100`, which was C1's objection to 8σ.
2. **Ring binding.** `ring_digest` absorbs the modulus, degree, depth, the proved matrix
   `A` and the ordered keys, in both languages, before `w`. A proof made against one ring
   is rejected against another; there is a test for the cross-ring case.

C2 also asked for the ZK distance to be restated if the tail could not reach `2^-100`. At
12σ it does not need restating. The one residual he named — the float accept/reject
boundary in `_reject` — is still open and is a fair item for the launch statement to carry.

## Not asking for

- **The estimator run.** The named models (ADPS16 / MATZOV) and the band are enough to
  proceed; a run would tighten it, not change a decision.
- **QROM.** Noted as outside the paper's theorem and as an audit-scope item.
- **The errata.** Both confirmed by derivation, which is stronger than a diff.

## Reproducing

```powershell
python -m pytest -q -m "not slow"    # 558 passed, 1 known xfail
cd proof_rust && cargo test          # 74 passed
python experiments/estimate_sis.py --check
```
