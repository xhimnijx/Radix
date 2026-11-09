# Review request: the lattice ring signature

> **Answered on 2026-11-08, in two rounds.** Round one: the tag was forgeable and
> was withdrawn; one transcription gap (the `c`/`c'` unit checks) was found and
> fixed; the parameters do not achieve 128 bits. Round two: the tag was rebuilt as
> a same-witness extension (`A_ext = [A; A']`, 38.7 KB at `k' = 4`), the
> challenge-difference term was identified as capping soundness at ~24 bits, and a
> second hole was found in the extraction chain (the extracted `v_i` is a
> 128-coordinate idempotent, not a 32-entry one-hot vector). The record is
> `REVIEW-FINDINGS.md`.
>
> **For a second review, the live questions are:**
>
> - **Q3' — the modulus and the challenge space.** Is an irreducible-quartic `q`
>   (`q = 1 mod 64`, `q != 1 mod 128`) plus the quartic-CRT multiplier the right
>   trade, or is there a cheaper route to a `c - c~`-invertible challenge space?
> - **Q5' — the mask.** Restore Gaussian masks with `Rej0`/`Rej1`; what `beta` and
>   `beta'` does this construction need, and do they price at 128 bits?
> - **Q6 — slot-constancy.** `v_i` arrives as an idempotent of `R_q`, so anything
>   that consumes it stops parsing. What is the cheapest sound way to add the
>   linear condition, given the `c^2` slot already carries `m+1` constraints and
>   has no spare `alpha`?
>
> Q4 below is answered and no longer needs review: the separate tag proof is
> withdrawn and replaced.

For the cryptographer. This is a brief, not a paper. It says what the code does,
what we want answered, and what we already know is wrong, so no time is spent
rediscovering the parts we have written down.

**What we are asking for:** a written opinion on the questions in section 4.
Severity and reasoning matter more than fixes. A memo with "sound / unsound / can't
tell, because X" per question is exactly the deliverable.

**What we are not asking for:** consensus, networking, economics, code style, or a
review of the archived Candidate-A work.

## 1. Orientation

This is a research prototype of a Monero-style ring signature built on lattices
instead of elliptic curves, i.e. post-quantum. It implements the one-out-of-many
proof of **SMILE, ePrint 2021/564** (Figs. 7-9 on pp. 26-28 of the full version;
the PDF is not redistributed here, it is downloadable from eprint.iacr.org).

The whole reviewable surface is `radix_core/candidate_b/lattice/`, 3,333 lines of
Python:

| File | Lines | What it is |
|---|---|---|
| `setmembership.py` | 685 | **the protocol**: Fig. 7 prover, Fig. 8 recursion, Fig. 9 verifier |
| `aggregation.py` | 424 | Fig. 5, `k` commitments folded into one (used for context, not by the signature) |
| `recursion.py` | 254 | eq. (7): the tenor reduction, `P' = [γᵀP_1 ; …]` |
| `tag.py` | 243 | **the addition**: a linking tag, not in the paper |
| `spend.py` | 243 | transaction plumbing: message binding, balance, tag set |
| `bdlop.py`, `sigma.py` | 355 | the commitment and its opening proof (Fig. 5's `pi`) |
| `subring.py`, `ntt.py`, `ring.py` | 517 | `R_q`, the NTT, the quartic slot decomposition (`M_q`) |
| `params.py` | 154 | the parameter manifest and its provenance |
| `tensor.py`, `transcript.py`, `quadratic.py`, `ring_signature.py` | 458 | indexing, Fiat-Shamir, the p. 23 quadratic form, the API |

Two documents to read before the code:

- `AUDIT-PACKET-LATTICE.md` - layer map, deviations, gaps, and the review questions.
- `ARCHITECTURE-DECISION.md` sections 8 and 8.2 - what the measurements say, and
  how the tag came to exist (including a construction we tried and **disproved**).

Status, plainly: no audit, no security claim, not the paper's modulus, not one
composed proof. Everything below is written by someone learning this material, and
the deviations exist because the paper's text and the code disagreed in three
places.

## 2. What it does, in protocol terms

For a ring of `n = l^m = 1024` public keys `pk_j = A·s_j`:

1. prover commits to the index bits `v_1..v_m` (one-hot), the masked secret `w'`,
   the recursion intermediates `x_2..x_m`, a garbage polynomial `g`, and `psi`;
2. it proves that the tensor `v_1 ⊗ … ⊗ v_m` selects a column of the set matrix
   `P = [NTT(-c'·pk_j)]`, which is equivalent to knowing one `s_j`;
3. `h = g + Σ y_j` carries the vanishing conditions; a single quadratic equation in
   the challenge `c` forces each `v_i` binary;
4. Fiat-Shamir over the transcript, message absorbed into `c'`.

Proof: 32,512 B. With the tag: 51,584 B. About 20 s to prove and 20 s to verify in
CPython at that ring size.

## 3. Read in this order

1. `AUDIT-PACKET-LATTICE.md` sections 3 and 5 (deviations, and what to check).
2. `setmembership.py` module docstring, then `prove` (line 291) and `verify` (line 497),
   side by side with Figs. 7 and 9.
3. `tag.py` module docstring and `prove_tag` (line 161).
4. `params.py` for the parameters and their provenance.

## 4. The questions

### Q1. Is the line-13 check's decomposition right? *(the load-bearing one)*

`setmembership.py` line 599 and the check at the end of `verify`.

Our claim: in `α₀(Σ F_j − c·f_{k+2m} − c²h) + Σ α_i(f_i² + c·f_i) + f_{k+2m+1} = ω`,
the `c⁰` coefficient is pinned by `ω` (committed before `c` exists), the `c¹`
coefficient is absorbed by `ψ` (committed after `α`, before `c`), and the `c²`
coefficient carries the constraints. That coefficient is
`α₀(Σⱼ yⱼ + g − h) + Σᵢ αᵢ vᵢ(vᵢ−1)`; with the `α` drawn before `c` it forces both
binaryness *and* `h = g + Σ yⱼ`, the latter being what joins the committed `vᵢ` to
the sent `h`.

**Answer we need:** does that decomposition hold, and does it therefore give the
soundness the paper claims? If it does not, the protocol proves nothing and
everything downstream is void.

### Q2. Is our `e_1` placement defensible?

`setmembership.py` line 25 (deviation 2) and line 599.

Fig. 9 line 12 puts `−e_1·Σγ` at order `c`. Fig. 7's `y_m` carries it in the `c²`
coefficient. Both cannot hold. Because only the `c²` coefficient is checked, we
place it at `c²`; with the printed placement the honest prover **cannot** pass,
which we verified experimentally before changing it.

**Answer we need:** is our reading correct, or have we mis-transcribed `F_m` in a
way that removes a constraint? This is a transcription dispute, not a design
choice, and it needs a second opinion.

### Q3. Does masking without rejection sampling hold?

`sigma.py`, `setmembership.py` (masks uniform in `[-2²⁰, 2²⁰]`), deviation 1.

We skip `Rej0`/`Rej1`. The response is `z = y + c·r` with `‖c·r‖` at most a few
thousand, dwarfed by the mask, so `z` is statistically independent of `r`.

**Answer we need:** is the cruder distributional argument sufficient for
honest-verifier zero knowledge, and what does it cost in soundness (if anything)?
The paper's Theorem B.1 uses Gaussian sampling and we do not.

### Q4. Is the tag sound, and what is its assumption?

`tag.py`, whole file; `ARCHITECTURE-DECISION.md` section 8.2.

The tag is **not in SMILE.** We tried the obvious construction first and
`experiments/linear_tag_soundness.py` shows it is forgeable: `τ = A'y'` is
uncommitted, so any tag can be produced. The fix commits to the mask and proves a
BDLOP opening to zero under the derived key `b' = Σ_j A'_j·b^m_j`, which forces
`c'(T − ⟨A',s⟩) = 0`; `invertible()` (line 59) checks `c'` is a unit of `R_q` via
its NTT, and we believe that check is exact for this modulus because the quartic
factors split completely.

**Answer we need:** (a) is that sound, including the `c'`-invertibility step and
the case where it fails; (b) the tag is one polynomial, so the linear map has a
large kernel — what Module-SIS parameters does tag-collision resistance actually
require, and does it meet ~128 bits at ring size 1024? This is the assumption we
have not priced.

### Q5. Parameters and the `m ≥ 2` restriction

`params.py`; `ARCHITECTURE-DECISION.md` section 8.

`q = 4,294,962,689` is a prototype prime of the right size, **not** SMILE's
(`MODULUS_FROM_PAPER = False`). `m = 1` (a 32-member ring) is refused because the
block matrix of eq. (23) does not have the shape the formulas assume when `k > 1`.

**Answer we need:** what breaks at this `q`, what would a correct parameter set
look like for ~128-bit security, and is refusing `m = 1` the right call?

## 5. Known and accepted; do not spend time here

- No rejection sampling, no bimodal Gaussian, no Dilithium-style compression of
  `t_0`: proofs are larger than the paper's 18.7 KB, by design.
- The tag is a second proof bound to the signature by `c'` and `t_0`, not one
  shared witness. Composition is milestone R1 and is not attempted.
- No range proofs; amounts are public. The spend layer uses equal-value rings.
- `m = 1` unsupported. Ring size is 1024.
- The protocol is not constant-time and is not a production implementation. It is
  a reference for the mathematics.
- Candidate A (a STARK design) was retired on measured memory grounds and lives in
  `archive/`. It is not part of this review.

## 6. Running it

```powershell
python -m pip install -e ".[test]"
python -m pytest -q -m "not slow"     # 373 tests, ~16 s
python -m pytest -q                   # 404 tests, ~7 min (real proofs)
```

The slow tests are slow because they run the protocol rather than mocking it. If
you want to see a single honest proof end to end:

```powershell
python -m pytest tests/test_candidate_b_setmembership.py -q
```

## 7. What an answer could look like

Per question: **sound / unsound / cannot determine**, one paragraph of reasoning,
and any concrete counterexample. If Q1 or Q4 comes back unsound, say so plainly —
we would rather retire the design than defend it. There is a stated rule for this:
`ROADMAP.md` lists the conditions that would reopen the archived fallback.

## 8. What we are not claiming

Not a coin. Not audited. Not constant-time. Not proven. Not the paper's
parameters. The launch gate in `radix_core/launch.py` is closed and opens only on a
signed decision.
