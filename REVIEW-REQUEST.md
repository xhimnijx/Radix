# Review request: fifth pass

For C1 and C2. The fourth pass answered the blocker and changed the picture:

| | fourth pass | now |
|---|---|---|
| Q-A | "the parameters are not priced" | **answered: ~2^157 (A) and ~2^174 (B0). Not short.** My dimensions were wrong; corrected below |
| Q-B | restate Theorem B.1 | answered: signable with four edits; C2 added the split-regime objection |
| Q-C | discrete Gaussian | answered: required, and the decisive reason is portability |
| Q-D | does the tag weaken M-SIS | answered: it strengthens it; `k' = 1` is sufficient |
| Q-E | run it | answered: **the spend layer was still on the withdrawn tag — fixed** |

What remains is narrower and more concrete. Five items, in priority order.

## The corrected numbers, for the record

My Q-A inputs mixed two conventions: 1664 is the full solution lattice of `A`
(`ell*d`), but 2944 is `23*d` where 23 is the **commitment arity**, not the width. The
width is `W = 33`, so `W*d = 4224`.

| relation | n | `det^{1/n}` | target | delta | block | Core-SVP |
|---|---|---|---|---|---|---|
| `A`, untagged, k = 4 | 1664 | `2^9.85` | `2^17.56` | 1.003218 | 541 | **`2^157`** |
| `A`, tagged, k + k' = 8 | 1664 | `2^19.69` | `2^17.56` | < 1 | n/a | beyond the model |
| `B_0`, W = 33 | 4224 | `2^9.70` | `2^27.90` | 1.002992 | 598 | **`2^174`** |

The binding relation is the untagged base at about `2^157`. The "3.6 bits of slack"
framing was backwards: targets *below* the reachable norms mean a stronger reduction
is required, not a weaker one.

**Nothing is being changed on the strength of these numbers**, because they are a
delta-heuristic sanity check, not an estimator run.

---

## Q-F. Ring-pool binding — both of you called this the most serious item outside Q-A

The proof binds the message, `w`, the commitments, `h`, `omega` and `c`. It does **not**
bind the ring. The verifier rebuilds the ring from its own pool, so today it is sound
only because prover and verifier are the same process.

Both of you propose the same cheap fix: absorb a ring digest as a transcript label
beside the message, with the anchor committing to the pool root. Zero proof bytes.

**Questions:**

1. **Where exactly** should the digest be absorbed — inside `_head`, before `message`,
   or as a separate label immediately after? Does the placement interact with the
   extraction's transcript rewinding?
2. The digest is over the **ordered** key list. Does the order need to be canonicalised
   (e.g. sorted, or by pool index) or is any order fine as long as prover and verifier
   agree?
3. Does this change any soundness constant? My reading is no — it only removes the
   trusted-pool assumption — but say so if that is wrong.

## Q-G. The discrete Gaussian — which one, and at what precision

Both of you require a discrete sampler before the rejection argument can be invoked.
C2's decisive point is portability: if both languages round floats, `libm` disagreement
makes them *different distributions*, and the analysis applies to neither.

**Questions:**

1. Which construction, concretely, for a **32-bit-ish q** and `sigma ~ 2^11`:
   Folláth–Peikert inversion, Peikert's rejection sampler, or a CDT with a fixed tail
   cut? The cost is irrelevant next to a 9 ms multiplication, so the criterion is
   simplicity and cross-language reproducibility.
2. What **precision** is sufficient — how many bits of the cumulative distribution, and
   what tail cut — such that the statistical distance to `D_{Z,sigma}` is negligible?
3. Is there a test we can write that would catch the two implementations drifting?

## Q-H. The confidence gap at `ord_256(q) = 4`

C2's note: the hardness proofs for module-LWE in the literature are stated for
`q = 1 mod 2n`. At `ord_256(q) = 4` we have the same lattice (the coefficient embedding
depends only on `log q`) but not the theorem.

**Question:** is there a published result covering this modulus class, or are we
correctly recording it as a conjecture in `SECURITY-NOTES.md`? If a result exists, cite
it and we will stop hedging; if not, we will keep the hedge.

## Q-I. Where do the 110 ms actually go? (C2's suggestion)

C2 guessed the CRT glue and re-encoding dominate, and that both are recoverable without
cryptographic change. This project measured that batching has nothing to amortise
(every stage depends on the proof's own challenges) and that parallelism gives 4.22x on
8 cores.

**Question:** is that profile worth chasing, or is 110 ms simply what a 32 KB lattice
proof of this shape costs? If the glue is the cost, is there a representation change
worth making — or does that reopen the coefficient-basis questions in `Q-C`?

## Q-J. `k' = 1` or `k' = 4` — a decision, not a question

Both of you now say `k' = 1` is sufficient (C2: 85 bits of margin on the collision
instance; the tag strengthens the signature either way). The implementation defaults
to 4.

**Question:** confirm 1 is acceptable, and we will drop it — 4.6 KB and a fifth of the
set-matrix work per tagged proof. If there is a reason to keep 4 that the collision
estimate does not capture, say so.

## Smaller items, still open

- **The errata.** Both confirmed the `e_1` double count and the eq. (24) index by
  derivation, not by a later revision. If either of you can obtain the 2022-05-20
  version, a diff would let the record say "erratum" instead of "suspected erratum".
- **The `q^-4` constant.** C1: the relevant distribution is the *difference*
  (coefficients in `-2..2`), so `q^-4` is an approximation that must be computed
  rather than assumed. Worth a worked line in the restatement.

## What changed in the code since the fourth pass

- **The withdrawn tag path is gone** (`74f68ae`): `spend.build_spend`/`verify_spend` no
  longer accept `tag_keys`, `Spend.tags` returns `None` and says why, and
  `setmembership.prove`/`verify` **raise** if `tag_keys` is supplied. The old
  tagged-spend tests were replaced by guards that the path is gone.
- The dangerous docstring sentences are corrected: "No rejection sampling" and "the
  `c^1` part cancels identically".
- `cli --backend rust` exists and works; the node reports `backend=rust` when selected.
- Wallet portability: a BIP-39 phrase, a versioned derivation tag, and refusals when the
  phrase is corrupt or missing beside an existing chain.
- Parallel verification: `verify_many`, 4.22x on 8 cores.

## Reproducing

```powershell
python -m pytest -q -m "not slow"        # 435 passed, 1 xfailed
cd proof_rust && cargo test              # 70 passed
python experiments/verify_rust_proof.py  # Rust proof -> Python verifier
cd proof_rust && cargo run --release --bin bench_batch   # the 4.22x
```

The suite has one known flake: `tests/test_nonce_multiprocess.py` fails roughly once in
a full run under concurrency and passes 6/6 in isolation. It is Candidate-A legacy and
unrelated to the lattice work, but it is recorded rather than hidden.
