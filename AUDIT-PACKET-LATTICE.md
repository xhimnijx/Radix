# Audit packet: Candidate-B lattice layer

> **Superseded in part on 2026-11-08.** Two reviews are recorded in
> `REVIEW-FINDINGS.md`. The Fig. 7-9 implementation held up; the **tag is
> withdrawn** as forgeable; the parameters do not achieve 128 bits; and the
> missing `c`/`c′` unit checks are fixed in code. Read the findings first, then
> this packet for the layer map.

Scope: everything under `radix_core/candidate_b/lattice/`. This is the
post-quantum half of Candidate B. The classical half (`group.py`, `lsag.py`,
`protocol.py`) is a separate, older prototype and is **not** covered here.

Status in one line: the SMILE one-out-of-many proof of ePrint 2021/564
(Figs. 7-9) is implemented and tested end to end for `m >= 2`, behind a
ring-signature API and a spend layer. **No security claim is made.** The
deviations below are the review surface.

## 1. What is implemented

| Layer | File | Tests |
|---|---|---|
| Parameters, provenance, size model | `params.py` | 17 (`test_candidate_b_lattice.py`) |
| Negacyclic ring `R_q` | `ring.py` | (same file) |
| Negacyclic NTT, exact integer | `ntt.py` | 11 |
| Quartic slot decomposition (`M_q`) | `subring.py` | 12 |
| BDLOP commitment, single and multi-message | `bdlop.py` | 5 |
| BDLOP opening proof (Fig. 5 `pi`) | `sigma.py` | 10 |
| Aggregation of `k` commitments (Fig. 5) | `aggregation.py` | 14 |
| Set-membership recursion, eq. (7) | `recursion.py` | 13 |
| Constraint predicates on `v` | `recursion.py` | (same) |
| Domain-separated Fiat-Shamir transcript | `transcript.py` | 10 |
| p. 23 quadratic form | `quadratic.py` | 4 |
| **Set membership, Figs. 7-9** | `setmembership.py` | 8, plus the unit checks added after review |
| **Ring-signature API** | `ring_signature.py` | 8 |
| **Spend layer** | `spend.py` | 5 |

Measured at `m = 2` (a 1024-member ring, `n = 32^2`): proof **32,512 B**,
prove **21 s**, verify **20 s**, single-threaded CPython 3.14. Those times are a
Python artifact, not an algorithmic statement; the NTT is `O(d log d)`.

## 2. Mapping to the paper

* `t = (t_0, t_1 .. t_{k+2m+1})` is one BDLOP commitment to
  `(0_kappa, v_1..v_m, w', x_2..x_m, g, psi)` under a single randomness `r`.
* `P`'s `j`-th column is `NTT(-c' * pk_j)` (eq. 31), so membership is
  `P(v_1 (x) ... (x) v_m) = x_1`.
* The Fig. 8 recursion reduces that relation one tensor factor at a time,
  emitting `x_{j+1}`, `y_j` and a commitment `t_{m+k+j}` per level.
* `h = g + y_1 + ... + y_m`; the verifier checks its zero prefix (Fig. 9 line 15)
  and the quadratic equation (line 13), which forces the `v_i` binary.
* Fiat-Shamir follows p. 43: `c'` binds `(t, w, message)`, the `gamma` challenges
  are drawn level by level, `alpha` after `h`, and `c` last.

## 3. Deviations, and what each risks

1. **No rejection sampling.** Masks are uniform in `[-2^20, 2^20]` rather than
   Gaussian with `Rej0`/`Rej1`. The response `z = y + c r` is statistically close
   to uniform because `||c r|| <= 5120` is dwarfed by `2^20`, so the transcript
   does not depend on `r`; the cost is size (the `z` block is `W = 29` full
   elements at `m = 2`). *Risk:* larger proofs, and the fine-grained
   distributional argument in the paper's Theorem B.1 is replaced by a simpler,
   cruder one that a reviewer should sanity-check.
2. **`e_1` term of `F_m` at order `c^2`, not `c`.** Fig. 9 line 12 places
   `-e_1 sum gamma` inside the bracket multiplied by `c`; Fig. 7's `y_m` has it
   in the `c^2` coefficient. Only the `c^2` coefficient is checked, so the
   `<1, v_i> = 1` constraint is only enforceable at `c^2`. With the printed
   placement the honest prover cannot pass. *Risk:* a transcription dispute, not
   a soundness gap, but it must be confirmed against the authors' reference
   implementation.
3. **`m >= 2` only.** The block matrix of eq. (23) is `(m+1)l x ml`, which does
   not match `P_1`'s `kl` rows when `m = 1` and `k > 1`; the paper's formulas
   assume the recursive case. `depth = 1` is refused rather than mis-proved.
   *Risk:* the smallest ring (32 members) is unavailable.
4. **Message bound into `c'`.** The paper hashes the message in `G`; this
   implementation absorbs it as the first transcript label, which is equivalent
   but not byte-identical.
5. **The ring is not hashed.** It does not need to be: `P` is derived from it and
   the recursion aggregates every column, so replacing or reordering a member
   breaks verification (two tests in `test_candidate_b_ring_signature.py`). This
   is a property to be checked by a reviewer, not an assumption.

## 4. Gaps that make this *not* a transaction layer

* **No nullifier proof.** SMILE's ring signature is anonymous but not linkable.
  Nothing in Figs. 7-9 yields a per-note tag. A tag was attempted (`tag.py`) and
  **withdrawn on review**: it binds only one derived row, so it is forgeable
  without a key (`experiments/tag_forgery_repro.py`, recorded in
  `REVIEW-FINDINGS.md`). Double spending is therefore still unprevented, and the
  single largest gap is unchanged.
* **Amount commitments and the range constraint.** The range constraint is in the proof
  in both languages (two alpha challenges per amount, non-binary bits refused, 22,784-byte
  cross-verified proof); the value commitment and the relaxed carry bound are not. The spend
  layer still uses
  equal-value rings, so the balance check is sound without them, but the value is
  public per input.
* **No linkable variant**, no key-image analogue, no multi-input aggregation in
  the lattice layer (`aggregation.py` implements Fig. 5, but the ring signature
  does not yet use it).

## 5. What a reviewer should check first

1. That the `c^0`/`c^1`/`c^2` decomposition of the line-13 check is right: the
   `c^0` part is pinned by `omega` (committed before `c` exists), the `c^1` part
   cancels identically, and only `c^2` carries constraints. This is the load
   bearing argument for the whole protocol.
2. The `e_1` placement question of deviation 2.
3. That the extractor's relaxed relation carries over with the masking used here
   (deviation 1) rather than the paper's Gaussian.
4. The parameter choice: `q = 4,294,962,689` is a prototype prime of the right
   size, **not** the paper's modulus (`MODULUS_FROM_PAPER = False`). Every
   M-LWE/M-SIS estimate depends on this.

## 6. How to reproduce

```powershell
python -m pytest tests/test_candidate_b_setmembership.py -q   # ~84 s
python -m pytest tests/test_candidate_b_ring_signature.py -q  # ~80 s
python -m pytest tests/test_candidate_b_spend.py -q            # ~41 s
python -m pytest -q                                            # 603 passed, ~11 min
```

The slow tests are slow because they run the real protocol: a 128 x 1024 matrix
over `M_q`, the recursion, and 19 polynomial commitments per proof.
