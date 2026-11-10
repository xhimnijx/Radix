# The α-slot range proof: change specification

> **STATUS 2026-11-10: steps 1-4 and 6 are implemented in both languages.** The range
> constraint runs inside the proof: two alpha challenges per amount appended after `alpha_m`
> and drawn after `h` before `c`, bit polynomials committed and never transmitted, a slot
> holding 2 refused by the proof, and a 22,784-byte proof accepted by both implementations.
> Steps 5 (the relaxed carry bound) and 7-8 (fixtures, re-measure) are outstanding.
>
> **One prediction in this document was wrong and is corrected below:** `W` does not grow.
> A range row is an ordinary BDLOP row of width `W` reusing the same randomness, so adding
> one costs a commitment component and changes neither `W` nor the Gaussian tables. The
> measured cost is **512 bytes per bit polynomial**, not the ~42 KB this document estimated.

This is the plan for the largest remaining piece of mainnet readiness. It exists because
starting that change without it produced three failed attempts, each discovering the next
type or arity only after the previous one was fixed.

Read this before touching `setmembership.py`.

## The layout, confirmed by both reviewers

Two α challenges per amount, appended after `α_m` and drawn **after `h`, before `c`**.

```
α₀(Σ y_j + g − h) + Σ_i α_i v_i(v_i − 1)
  + Σ_amounts [β_{a,0} · f_{a,0}(b) + β_{a,1} · f_{a,1}(b)]
```

where `f_a(b) = b·(b − 1)` on the packed bit polynomial.

**Why they must be separate α's** (C2, and the reason is decisive): folding a bit polynomial
into an existing α gives `α(v² − v + b² − b) = 0`, which a prover satisfies with
`v² − v = −(b² − b) ≠ 0` and thereby breaks the ring selector. The pairing is the mechanism.

**What needs no α at all:** the digit relation `d = 2b₁ + b₀` and the addition relation
`a + b + f(X−4) = c`. Both are linear in committed values and ride on the existing masked
opening. The carry's smallness is a norm check on the relaxed proof's `z`, not a quadratic.
The budget is therefore **2 α per amount**, not 3.

## The relaxed carry bound

Its own challenge matrix `R ∈ {0,1}^{n×k}`, drawn **after** the carry commitment and `h`,
**before** `c`. Derived from the transcript and expanded by XOF: only a seed goes in the
proof. The expansion must be **bit-identical in Python and Rust** — the same portability
discipline as the Gaussian table, applied to a matrix.

`z = R·f + y` uses the same masked opening as everything else: one more `f_j = ⟨b_j,z⟩ − c·t_j`
relation and one more row, not a second σ. It adds `z ∈ Z_q^n` (256–512 B) to the proof.

## The order of work, which matters more than any single step

Each of these changes the wire format, so they must be done together or not at all.

1. **Extend the commitment arity.** `κ + rows + 2m + 1` gains the message count for the range
   data: two bit polynomials per amount, plus one carry polynomial.
   **Measured: `W` stays at 30.** The rows are added as `Keys.range_rows`, each an ordinary
   BDLOP row of the existing width reusing the same randomness, so the mask, the response and
   every Gaussian table are untouched. The cost is one commitment component each: 512 bytes.
2. **Extend `masking_width`** accordingly, and regenerate the Gaussian tables for every width
   the code now uses. The sampler **fails loudly** on an unknown width — which is what you
   want, and it will tell you exactly which tables are missing.
3. **Draw the β challenges.** After `h`, before `c`, appended to the existing `alphas`
   tuple. Both implementations must draw the same number in the same order.
4. **Add the ψ/ω terms.** `ψ += Σ β_b · a_b · (1 − 2b)` and `ω += Σ β_b · a_b²`, mirroring
   `psi_bin`/`omega_bin` exactly with `v` replaced by `b`.
5. **Draw `R` and add the carry row.** After the carry commitment and `h`, before `c`.
   **Outstanding.**
6. **Extend the verifier.** Recompute the same terms from the transmitted polynomials, and
   check the carry bound against the transmitted `z`.
7. **Regenerate both cross-language fixtures** and re-verify acceptance in both directions.
8. **Re-measure.** Measured so far: 22,784 bytes with two range messages, against a
   21,760-byte baseline — 512 bytes each, as above. The security line is still set by `A` at
   2^158, and `B0` is unaffected by range rows at all.

## What must be true when this lands

- The five checks in `range.verify` are reproduced by the proof, not merely by the checker.
- An amount out of range is rejected **by the proof**, not by a clear-text check.
- A proof with a consistent range witness verifies; one with an inconsistent witness does
  not, even when every other element is honest.
- Both languages agree, at the new size.
- `docs/PAPER.md` §8 loses the "amounts are visible" limitation.

## The soundness question this does not answer

C1's extraction argument for `[A | I_k]` is unwritten, and the α-slot soundness rests on
C2's per-constraint accounting (`q^-4` for the `R_q` challenges, `2^-n` for `R`, booked
separately). **A range proof with an unwritten soundness argument is not shippable**, which
is why this becomes the goal's blocker once the wiring lands rather than before it.

Building it is not blocked. Shipping it is.

## Why three attempts failed, so the fourth does not

1. `ell = 17` could not be constructed — `Parameters` and `Statement` both validated against
   `SMILE.matrix_cols` rather than their own width. Fixed.
2. `Parameters` did not carry its `SmileParameters`, so every module touching the matrices
   guessed which type it held. Fixed.
3. The Gaussian sampler has no table for the new widths and refuses rather than substituting
   a neighbouring distribution. That is correct behaviour; it means step 2 above is not
   optional and must be done before anything can be measured.
