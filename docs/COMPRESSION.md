# Compression: what is left, and why it stops here

Two steps are done and measured: bounding the responses at `12σ` and storing them as
16-bit centred values took the proof from **32,512 B to 21,760 B** (‑33.1%). The paper's
figure for a bare ring signature at the same ring size is 17.27 KB (p. 48), so ~4 KB
remains.

This document records why the remaining steps are **not taken**, with the evidence.

## Where the remaining bytes are

An untagged proof at the test rig's shape (κ = 10, rows = 4, ℓ = 13, W = 29):

| Component | Polynomials | Bytes | Share |
|---|---|---|---|
| Commitment `t` | 19 | 9,728 | **45%** |
| `h`, `ω` | 2 | 1,024 | 5% |
| `response_prime` (`z'`) | 13 | 3,328 | 15% |
| `response` (`z`) | 29 | 7,424 | 34% |
| Challenges | — | 256 | 1% |
| **Total** | | **21,760** | |

The two responses are already as small as a fixed-width field allows. The commitment is
**45% of the proof** and is untouched — and it is the only remaining object large enough
to close the gap.

## What the paper says (p. 55)

> "the auxiliary commitment ... it is not necessary to transmit the full top part `t'₀`
> and it suffices to send the rounding with respect to some power-of-two, i.e. the
> quotient modulo `2^D`. This is known as the Dilithium public key compression technique.
> Moreover, the MLWE error for the top part doesn't have to be explicitly opened and no
> masked copy of it has to be included in `z`. Then only a rounding of `w'` with respect
> to a divisor `2γ₂` of `q − 1` is transmitted and the remainder serves as a masking
> vector for the MLWE error where **another rejection sampling step is necessary**."

Three things are being compressed at once: `t'₀`, the MLWE error (not opened at all),
and `w` (rounded). They are not separable.

## Why this is a change of statement, not of encoding

The goal for this item said: implement it if it is an encoding change, and stop and
record it if it requires a change of statement. It requires a change of statement. The
evidence is in this repository, not in a reading of the prose:

**1. The challenge is derived from the exact commitment.** `setmembership.py` absorbs
`proof.commitment[:head_length]` into the transcript before drawing `c'`
(`setmembership.py`, the `_head` call inside `verify`). A rounded commitment produces a
different `c'`, so the prover and verifier must agree on *which* representation is
absorbed — and every other proof that absorbs `t` changes with it.

**2. The verifier multiplies the commitment by the challenge, exactly.**

```python
ring.dot(row, proof.response, sm)
for row in keys.rows0
```
against
```python
ring.mul(proof.challenge, poly, sm)
for poly in proof.commitment[: sm.challenge_dim]
```

If `t₀` is only known to within `2^D`, then `c·t₀` is only known to within `c·2^D`, and
the equation cannot be checked exactly. The low bits must be *absorbed* — which is what
the rounded `w` is for — and absorbing them requires the prover to prove that no carry
occurred, which is the extra rejection step.

**3. The rejection loop changes.** The prover currently retries only on the response
bound (`Rej1`). Rounding introduces a second, independent rejection condition on whether
the rounding of `t'₀` and `w` is consistent. A prover that skips it produces proofs the
verifier rejects at a non-negligible rate, and no amount of encoder work fixes that.

None of these can be expressed as a byte-packing change. They change what is proved, what
is hashed, and what the prover must retry.

## What would have to be specified before implementing

Named, not guessed:

1. **The exact value of `D`** and the rounding convention (floor, nearest, symmetric).
2. **The value of `γ₂`** and how it relates to `σ` — p. 55 says the aim is
   `2γ₂ ≈ 12σ`, which ties it to the infinity-norm bound added earlier.
3. **The second rejection condition**, precisely: what the prover checks before
   accepting an attempt.
4. **The verifier's check in the rounded domain**, including what bound it applies to the
   remainder.
5. **Whether `c'` is absorbed over the rounded or the true `t`** — and, if rounded, what
   this does to the extraction argument, which is a question for C1 and C2 rather than
   for the implementer.

Items 1–4 are in Figure 12 of the paper and in the Dilithium and Bai–Galbraith
references; item 5 is a soundness question this project should not answer alone.

## The decision

**Not implemented.** Two steps were taken because they were provably safe: bounding the
responses and packing them. The third step would change the statement, and doing it
without items 1–5 settled would produce a proof that is smaller *and* unanalysed, which
is the worst possible trade in this project.

The ~4 KB stays until the specification is complete and reviewed.

## What remains available that is still safe

Small, and worth stating so the option is not invisible:

- **Packing the ternary challenges.** They cost one byte per coefficient, 256 B total; at
  `log2(3) = 1.585` bits they could be ~51 B each. Saves ~150 B. Not worth the
  complexity alone.
- **True entropy coding of `z` and `z'`** rather than 16-bit fields: about 13.4 bits per
  coefficient against 16, saving ~1.4 KB. Requires a range coder in both languages and a
  decoder that cannot desynchronise — a real risk for a 6% gain.

Neither is taken. Both are recorded in case the balance changes.

## Related

- [`CONFIDENTIAL-TRANSACTIONS.md`](CONFIDENTIAL-TRANSACTIONS.md) — the same commitment
  structure, and the construction that would use these compressions
- [`../PERFORMANCE.md`](../PERFORMANCE.md) — the measured sizes
- [`../REVIEW-REQUEST.md`](../REVIEW-REQUEST.md) — where the open questions go
