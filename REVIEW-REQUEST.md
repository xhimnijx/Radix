# Review request: fourth pass

For C1 and C2. Round one found the tag forgeable and the parameters unpriced; round
two settled the modulus; round three is now closed out — the Rust port is finished and
cross-verified, and the app is packaged.

This brief says what changed, what is implemented, and the **five questions that
remain**, in priority order. The first one is the only blocker.

**Status:** research prototype. No audit, no security claim, no value. The Candidate-A
track is archived in `archive/` and is not part of this review.

---

## What changed since the third pass

| Item | Then | Now |
|---|---|---|
| **Rust prover/verifier** | arithmetic layer only | **complete**; Python proof accepted by Rust, Rust proof accepted by Python |
| Rust tests | 0 for the protocol | **69**, every layer with a known-answer value from Python |
| Prover cost | projected 0.47 s / 37 ms | **measured 496 ms prove, 110 ms verify**, 9.75 attempts |
| Android wallet | none | native APK, 24 KB, framework-only, on the releases page |
| Deployable node | localhost only | `--host 0.0.0.0` documented with the LAN exposure warning |
| Codec defect | commitment arity wrong in both languages | fixed; the port found it in the Python |

**Two defects were found by porting, not by reading.** Both are recorded because they
are evidence about how much checking the code had actually had:

1. The commitment arity was `κ + λ + m + 1`; the correct count is `κ + rows + 2m + 1`.
   The two agree only when `rows = 8` — the *tagged* shape — so the wrong formula passed
   every test in both implementations and was wrong for every untagged proof.
2. The zero prefix of `g` was applied to the first `d/l` **slots** instead of the first
   `d/l` **coefficients**. Every stage of the proof still passed; only the `h`-prefix
   check catches it.

Neither was a cryptography problem. Both were caught by an independent implementation,
which is the only argument for writing one that has ever held up.

---

## Q-A. The estimator run — the only blocker

This is the single thing between "the proof verifies" and "the parameters are secure".
Everything below is measured or derived; none of it has been run through an estimator.

### Exact inputs

```
scheme          module-SIS / module-LWE over R_q = Z_q[X]/(X^128 + 1)
q               4,294,966,337           (= 2^32 - 959, prime, ord_256(q) = 4)
d               128
l               32                      (slots per polynomial)
k               4                       (rows of A)
ell             13                      (columns of A)
kappa           10
lambda          10
mu              5                       (secret coefficient bound)

masks           s   = 2,666   (2^11.4)   for z    (W = 33, tagged)
                s'  = 1,673   (2^10.7)   for z'   (ell = 13)
responses       beta  = 244,992  (2^17.9)  = s  * sqrt(2*W*d)
                beta' =  96,512  (2^16.6)  = s' * sqrt(2*ell*d)

relation A      M-SIS_{k, 2*beta'}       target 2^17.6   dimension 1664
relation B0     M-SIS_{kappa, 8*d*beta}  target 2^27.9   dimension 2944
```

### Questions

1. **What are the Core-SVP costs** for those two instances, using the two target
   conventions the paper uses (`2β′` because the extractor subtracts two responses, and
   `8dβ` for the commitment rows)?
2. **Is `q = 4,294,966,337` acceptable**, or does `ord_256(q) = 4` (irreducible quartics,
   no 128-point NTT) cost anything in the LWE/SIS estimates relative to a split modulus?
3. **What is the smallest change that reaches 128 bits** if we are short: larger `q`,
   larger ring (`μ`), smaller `β`, or larger `ℓ`? Please give the trade in proof bytes.
4. **Is `β` or `β′` binding?** At `δ = 1.0042` the reachable norms are `2^21.2` and
   `2^31.7`, giving ~3.6 and ~3.8 bits of slack — which is not a security level. Say so
   if the heuristic is the wrong tool here.

**What counts as an answer:** a number, or a clear statement that these inputs are
insufficient. An opinion is not usable; a table is.

---

## Q-B. Restate Theorem B.1 for the irreducible modulus

The paper's soundness analysis defines its constant `p` via `c mod X^{d/l} − ζ^{2j+1}`,
which presupposes `ζ ∈ Z_q` — that is, the **split** case, which we no longer use.

C2's earlier answer was that the extraction skeleton is ring-generic and needs three
edits (`p` redefined over `F_{q^4}`, `c̄` invertibility as an explicit hypothesis, and
the slot-constant property attributed to the modulus). That answer is accepted but
**has not been written down**, and `REVIEW-FINDINGS.md` is a record, not a proof.

**Question:** is that restatement correct, and would you sign it? Specifically: does
the `q^{-4}` bound really become exact in the field regime, and does the induction get
shorter as expected rather than merely differently shaped?

---

## Q-C. The discrete Gaussian

`setmembership._gaussian` draws a **continuous** Gaussian and rounds to integers, in
both implementations. Lemma A.6 is stated for a discrete Gaussian.

The difference is `O(1/s)`, so about `2^-11` in statistical distance at these widths.

**Question:** is that acceptable with the caveat recorded — the honest position today —
or is a discrete sampler required before the rejection argument may be invoked at all?
If a sampler is required, say which one; the port must use the same distribution, so
this decides whether the Rust code changes too.

---

## Q-D. Does the same-witness tag weaken M-SIS?

C1 proposed the extension and it is implemented and tested:

```
A_ext = [A ; A']          T = A' s          ring = { (pk_j, T) } for all j
```

so the existing proof over `A_ext` forces `T = A'·s` from the same witness. `k' = 4` was
chosen on C2's collision estimate, not on a soundness argument.

**Question:** does adding `k'` rows to the proved matrix change the M-SIS instance that
the *ring signature* rests on — the `A` relation at `k = 4` becomes `k + k' = 8` — and if
so, is the tag's collision margin the binding constraint or is the signature's soundness?
In other words: **was `k' = 4` chosen for the right reason?**

C2 also said `k' = 1` is defensible under `A_ext`; C1 recommended 4. The implementation
defaults to 4. If 1 is sufficient, say so and we will reprice it.

---

## Q-E. Run it, then tell us what breaks

Releases, including the Android APK:
**<https://github.com/xhimnijx/Radix/releases>**

```powershell
python -m pip install -e .
python -m radix_testnet                       # node + wallet UI on localhost
python -m radix_testnet.cli node --host 0.0.0.0   # reachable from other devices
```

The Rust backend makes a send take about a second instead of two minutes:

```powershell
cd proof_rust && cargo build --release --bin prove_request
python -m radix_testnet.cli --backend rust ...
```

Reviewers find more when they can run the thing. Two of the four defects in
`REVIEW-FINDINGS.md` came from someone trying an attack, not from reading.

---

## Smaller questions, if you have time

- **The paper's errata.** The `e₁` double count in Fig. 9 line 12 and the sum index in
  eq. (24) should be checked against the later ePrint revisions (up to 2022-05-20)
  before the paper is recorded as wrong.
- **Ring-pool binding.** Rings travel as indices into the node's pool, and the proof
  does not commit to the pool. The verifier rebuilds the ring from its own copy, which
  is correct only because prover and verifier share one process. On a real network the
  pool would have to be committed to by the anchor, or a proof would not bind to the
  ring it was made for. Is that right, and what is the cheapest fix?
- **Verification cost.** 110 ms measured against a 100 ms target. Batch verification is
  the obvious answer and is unmeasured; if you have a preferred construction for these
  proofs, say which.

---

## What we are not asking

Consensus, peer-to-peer networking, economics, or the archived Candidate-A work. There
is no network and no value; `radix_core/launch.py` is closed by design.

## Reproducing

```powershell
python -m pytest -q -m "not slow"        # 413 passed, 1 xfailed
cd proof_rust && cargo test              # 69 passed
python experiments/verify_rust_proof.py  # Rust proof -> Python verifier
python experiments/mask_calibration.py   # the mask numbers above
python experiments/slot_constancy_probe.py   # the modulus table
```

Every number in this brief is reproducible with those commands. If one is not, that is
a defect in the brief and we would rather hear about it than have it quoted.
