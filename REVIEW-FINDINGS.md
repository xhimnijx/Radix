# Review findings, 2026-11-08

Two independent cryptographers reviewed the lattice ring signature against
`REVIEW-REQUEST.md`. This is the record of what they said, what I reproduced
myself, what has been changed, and what is now open. Where they disagreed, the
disagreement is stated rather than smoothed over.

**Headline:** the Fig. 7-9 implementation survived review as a correct
transcription. The **tag is withdrawn** (forgeable, reproduced here). The
**parameters do not achieve 128 bits** — the masking deviation moved the security
parameter from the secret bound `μ = 5` to the response bound `2^20`. One
transcription gap (missing unit checks) is fixed in code.

## The verdicts

| Question | Reviewer 1 | Reviewer 2 | After reproduction |
|---|---|---|---|
| Q1 line-13 decomposition | sound as a decomposition; not 128-bit | sound; **my statement of it was wrong** | sound; statement corrected, unit checks added |
| Q2 `e₁` placement | sound, code is right | sound, paper is internally inconsistent | sound; my reading stands |
| Q3 masking without rejection | **unsound** | **unsound**, worse than they first said | **open, blocking** |
| Q4 tag | **unsound** — gave a forgery | sound, conditional | **unsound. Reproduced. Withdrawn.** |
| Q5 parameters, `m ≥ 2` | unsound at this `q` | can't tell; `q` is load-bearing | **open**; `m = 1` refusal is right, for a stronger reason |

## Q4 — the tag is broken, and I reproduced it

Reviewer 1's claim: `verify_tag` binds only the derived row
`u_der = ⟨A′,u⟩ − message`, never the individual `u_j`. So a forger picks any
tag, any short `r_m`, sets `t = B₀^m r_m`, and chooses `u` with
`⟨A′,u⟩ = ⟨b′,r_m⟩ + message`; then `u_der = ⟨b′,r_m⟩`, which the forger can open
honestly because it chose `r_m`. No secret is used.

`experiments/tag_forgery_repro.py` reproduces it:

```
honest verifies: True
u_der == <b', r_m>: True
forged tagged proof verifies: True
forged tag differs from the real one: True
forger used the secret: False
```

Reviewer 2 read the same code and called it sound, on the assumption that the
opening binds `r_m`. It does bind `r_m` — the forger just chooses it. The
difference is that reviewer 1 ran the attack. **The tag is withdrawn**:

- `tag.py` now opens with `KNOWN BROKEN - DO NOT USE`;
- `tests/test_candidate_b_tag.py::test_a_forged_tag_does_not_verify` asserts the
  property we want and is marked `xfail(strict=True)`, so a future fix fails the
  suite until the marker is removed;
- `spend.TagSet` and the tagged path remain in the tree but are not a security
  claim of any kind.

It is the same free-response failure as the crude construction it replaced, one
level down: it binds one derived row instead of the `ell` committed values. A
sound tag must commit the individual `u_j` and prove `⟨A′,u⟩` against them.

Reviewer 2's Q4(b) is a separate question — collision resistance of the 1 × 13 map
— and they estimate ≈ 2^200 Core-SVP, while reviewer 1 estimates it below 128 bits.
It is moot while the tag is forgeable, and it must be settled with a real lattice
estimator before any tag is shipped.

## Q3 — the masking deviation is a soundness failure, not a size cost

Both reviewers, independently: the uniform `2^20` mask does not make the response
independent of the randomness at cryptographic precision. Reviewer 2's sharper
form: the verifier's bound `MAX_RESPONSE_NORM = 2^20 + 8192` is what bounds the
witness the extractor obtains, so the relation actually proved is
`∃ s, As = pk, ‖s‖∞ ≤ 2^20` — not `‖s‖ ≤ μ = 5`. Substituting that into the two
M-SIS assumptions of Theorem C.4 puts the key instance at roughly `2^50`
Core-SVP. Reviewer 1 put the same failure at `M-SIS_{κ,8dβ}` being false outright.

They also agree on the zero-knowledge side: the statistical distance between the
uniform mask and the shifted distribution is about `2^-10.2`, not negligible, and
pushing it below `2^-40` needs `B ≈ 2^50`.

This is not fixable with a one-line change. It needs the paper's Gaussian masks
with `Rej0`/`Rej1`, and `β`, `β′` re-derived and then fed to a lattice estimator.
**Nothing may claim 128 bits until that is done.**

## Q1 — the decomposition holds; my description of it was wrong and dangerous

Reviewer 2: the `c²` coefficient is **not** `Σ αᵢ vᵢ(vᵢ−1)`. It is

```
α₀(Σⱼ yⱼ + g − h) + Σᵢ αᵢ vᵢ(vᵢ−1)
```

Because the `α` are drawn before `c`, vanishing forces *both* binaryness and
`h = g + Σ yⱼ`. The second is the only thing joining the committed `vᵢ` to the
sent `h`, so the check is **stronger** than the brief said, not weaker. The brief
has been corrected. Anyone who "simplifies" the `α₀` slot out on the strength of
the old wording would make the scheme trivially forgeable; that sentence is now
removed.

Reviewer 1's separate gap is real and is now fixed in code: `verify` never checked
that `c` and `c′` are units. Because this modulus splits completely,
`R_q ≅ Z_q^128`, a unit is exactly a polynomial with no vanishing NTT coordinate,
and a non-unit `c` leaves a coordinate where the `c²` constraint is vacuous —
grindable at about `2^24`. `setmembership._is_unit` is now checked in `verify` and
enforced in `prove`, with tests in `test_candidate_b_unit_checks.py`.

## Q2 — confirmed, from both directions

Both reviewers: the code's `e₁` placement is right and the paper double-counts.
Reviewer 2 adds that the paper's own soundness proof relies on the version that
holds, so the paper is inconsistent exactly where the repair was made. Reviewer 2
also flags that later ePrint revisions (up to 2022-05-20) could not be retrieved and
should be checked before recording the paper as wrong.

## Q5 — `q` is load-bearing, and `m = 1` is worse than the docstring says

Reviewer 2 corrected their own first answer: the `q^{-4}` term is a rejection
probability, and the extraction threshold is `32p^{d/l} + q^{-d/l}`, dominated by
`32p^{d/l} ≈ 2^-8`. So `q ≈ 2^32` is necessary but not what delivers 128 bits; the
128 bits are entirely the two M-SIS assumptions, which are functions of `β` and
`β′` — the same numbers the masking deviation broke. Q3 and Q5 are one question.

On `m = 1`: refusing it is right, but for a stronger reason than the docstring
gives. At `m = 1` there is no `B` block, so `⟨1, vᵢ⟩ = 1` is never proved at all —
the scheme would be unsound, not merely mis-shaped. Fig. 11 of the paper lists
`m = 1` with `k = 4`, which is itself inconsistent with eq. (23).

## Also found

- **Two challenge distributions are live.** `sigma.py` draws uniform-over-`{−1,0,1}`
  (`value % 3 - 1`); `setmembership.py` draws the paper's ½/¼/¼. They are different
  proofs, but nothing states which applies where. It needs fixing one way.
- Reviewer 1 confirmed `tag.invertible()` is exact for this modulus (all 128 NTT
  coordinates, and the quartic constants are fourth powers), and that the
  quartic factors split completely because `q ≡ 1 mod 512`.

## What this means

- **Fig. 6's machinery is not the problem.** Two reviewers independently checked
  the recursion, the line-13 decomposition and the `e₁` repair, and it held. The
  implementation is a faithful transcription with one documented repair.
- **The security claim is the problem.** `β`, `β′`, the mask distribution and the
  challenge space are not the paper's, and at the current numbers the core is
  roughly `2^50`, not `2^128`.
- **The tag does not exist** in any usable form.

## Next, in order

1. Redesign the tag around a commitment to the individual `u_j` — or drop
   linkability from the design and say so.
2. Restore the paper's masking: Gaussian masks, `Rej0`/`Rej1`, `β` and `β′`
   re-derived, then priced with a lattice estimator. Until then the core is a
   correct transcription at unproven parameters.
3. Unify the challenge distribution.
4. Check the later ePrint revisions of the `e₁` issue.
5. Re-review: the brief is `REVIEW-REQUEST.md`; Q3 and Q5 have now changed enough
   to warrant a second pass on their own.

## Resolution (same day): the tag is rebuilt as a same-witness extension

C1's follow-up rejected the obvious repair and gave the right one. Committing the
individual `u_j` would bind the *mask*, not the secret: a cheating prover can use
a different `y'` for `u` than the one behind `z'`, and the verifier cannot tell.
The fix is to stop proving a separate relation at all.

**Adopted design.** Let `A_ext = [A; A']` over `R_q^{(k+k') x ell}` and
`T = A' s`. The spender publishes `T`; the verifier builds the extended ring
`{(pk_j, T)}` -- the *same* `T` in every member, so the index stays hidden -- and
runs the unchanged Fig. 7-9 proof over `A_ext`. One proof, one witness, no second
sigma, and no free response to forge. The proof forces
`A_ext s* = c* (pk_iota, T)`, so `s*/c*` is a preimage of both.

Implemented as `ring_signature.setup(..., tag_rows=1)` plus `sign_tagged` /
`verify_tagged` / `tag_of`. The proof machinery was parameterised by the height of
`A` (`setmembership.masking_width` now takes a row count) rather than changed.

| Shape | Size | vs base |
|---|---|---|
| untagged (k = 4) | 32,512 B | 1x |
| **extended, k' = 1** | **33,536 B** | 1.03x |
| extended, k' = 4 (not built) | ~38.7 KB | ~1.2x |
| the withdrawn separate proof | 51,584 B | -- |

Six tests: it verifies, the tag equals `A' s`, two signatures of one note over the
same ring carry the **same** tag while the proofs differ, a modified tag is
rejected, the untagged API refuses tagged parameters, and the size matches.

**k' = 1 vs k' = 4.** k' = 1 gives same-note linkability only. C1's estimate is
that a 1 x 13 `A'` is *not* 128-bit collision-resistant for distinct notes (kernel
shortest ~60 in l2 against an allowed secret difference of ~408), and that k' = 4
puts the kernel shortest at ~2^17, far above the ~2^8.7 target. The code takes
`tag_rows` as a parameter; the default and the tests use 1, so the B3
"distinct notes never collide" property is **not** claimed. That is a parameter
decision to be priced with an estimator, and it is now a one-argument change.

## Two corrections from C2, applied

1. **`invertible()` is exact for any valid SMILE modulus, not because of this `q`.**
   Every valid `q` forces the quartics to split, because the constant term
   `r_i = (zeta^{2i+1})^4` is an explicit fourth power. The docstring attributed it
   to "this modulus", which would mislead anyone who later swaps `q`. Fixed.
2. **The number to quote is `beta' = 2^25.4`, target `2^26.35`.** C2's conversion:
   the verifier's per-coefficient bound `2^20 + 8192` over `ell*d = 1664`
   coefficients gives `beta' = 2^25.36` worst case, `2^24.57` typical, and the
   extractor takes a difference, so the M-SIS target is `2*beta' = 2^26.35`. Every
   reading lands between `2^47` and `2^72` Core-SVP; the paper's Gaussian
   `beta' ~ 2^11` sits below the Gaussian heuristic and is unreachable by this
   bookkeeping. The other relation, `M-SIS_{kappa, 8d beta}` at `beta = 2^25.94`,
   lands at ~`2^91`, so the key relation is the weak one.

## A caveat C2 raised that is not yet handled anywhere

Because every valid `q` splits completely, `v(v-1) = 0` in `R_q` means binary at
each of the 128 evaluation points -- not "binary on the 32 slots with constant
entries". The extracted object is therefore a 128-coordinate binary vector, not a
32-entry one-hot vector. This is equally true of the paper. It matters only if the
`v_i` arriving from the extractor must be slot-constant, which the tag extension
does not need but a future composed proof (B5) might. **Not currently addressed in
code, in the brief, or in the paper.**

## k' = 4 adopted, and the work multiplier corrected

C1: k' = 4 is the first row count with a comfortable distinct-note collision
margin (kernel shortest ~2^17.3 against a target of ~2^8.7; k' = 2 is marginal and
k' = 3 is borderline), and it matches A's shape, so the tag reuses `M-SIS_{4,13}`
rather than introducing a weaker instance. My earlier "x1.2 work" was wrong: that
was k' = 1. Measured here:

| Shape | Wire size | Prove | Verify | Work |
|---|---|---|---|---|
| untagged | 32,512 B | ~21 s | ~20 s | 1x |
| k' = 1 | 34,048 B | 24.1 s | 23.8 s | ~1.15x |
| **k' = 4** | **38,656 B** | **39.1 s** | **38.3 s** | **~1.86x** |

C1's arithmetic reproduces exactly, including that my `tagged_size_bytes` had
omitted the tag polynomials themselves (it counted 36,608 B; the tag adds 2,048 B).
Fixed, and the tagged tests now run at k' = 4.

## The challenge-difference gap: the unit checks are necessary but not sufficient

C1's second answer is the one that changes how this project may describe itself.
Checking that `c` and `c'` are units closes the `c^2` zero-divisor attack on the
final equation. It does **not** close the extractor: extraction needs `c - c~`
invertible, and at a split modulus the difference of two units can still be a zero
divisor. At one scalar slot that happens with probability `p ~ 2^-31.4`, and over
128 slots the soundness error is about `2^-24.4`. Restricting the challenge space
to units does not help: a set with pairwise-difference units in the split ring has
size at most `q`, so its error is at least `1/q ~ 2^-32`.

**The fix is the modulus.** With `q = 1 mod 64` and `q != 1 mod 128`, the quartic
factors `X^4 - r_i` are irreducible, a nonzero quartic residue is a unit of a field,
and the difference of two ternary challenges vanishes in a factor only with
probability `q^-4 ~ 2^-128`. The unit checks then cost nothing (failure `2^-123`).

**What it costs.** With irreducible quartics there is no 128-point NTT, because
that needs `256 | q - 1`. `ntt.supports()` goes false, `ring.mul` falls back to
`mul_naive` at `O(d^2)`, and a 20 s proof becomes minutes. Keeping performance
means implementing the **quartic-CRT multiplier**: 32 slots, each a 4x4 product
(`subring.quartic_multiply`), about 512 coefficient products per ring
multiplication — competitive with the NTT. `subring.slot` already computes residues
directly, so only `glue` (currently NTT-driven) and the root search need to move to
a 64th root. In Rust this is routine; in Python the slot/glue overhead must be
measured before committing.

Until that lands, the honest statement is: **soundness is about 24 bits at this
modulus**, not 128, and the unit checks must be described as closing one concrete
attack rather than as repairing the argument.

## The slot-constant hole: an undefined term, not a weaker bound

C2's answer is sharper than the question deserved. The worry was that a future
composed proof might need the extracted `v_i` to be slot-constant. C2: a composed
proof cannot proceed at all, because the statement **stops parsing**. The whole
downstream structure is indexed by `l^m = 1024`: `P` has 1024 columns, the ring has
1024 positions, and `v_1 (x) ... (x) v_m` lives in `Z_q^{32^m}`, which is only
defined when each `v_i` is 32 scalars. A 128-coordinate binary object selects no
column, so "which key am I spending" has no answer.

And no modulus rescues it. `v(v-1) = 0` in `R_q ~ Z_q^128` says `v` is an
idempotent, i.e. the indicator of an arbitrary subset of the 128 evaluation points;
slot-constant means that subset is a union of the 32 four-point groups. That would
follow only if `M_q` were a product of fields, whose only idempotents are 0 and 1 —
and it is never a product of fields, because `r_i = (zeta^{2i+1})^4` is an explicit
fourth power for every valid `q`.

What the constraints actually deliver: 128 binary evaluations, plus
`sum_j (v_i)_j = 1` as an `M_q` element — which is only four `Z_q` coordinates,
because `B` in eq. (23) has exactly one nonzero row. Whether the spurious binary
solutions can be excluded is a four-equations-over-128-bits question that neither
the paper nor this code settles.

**Severity:** a hole in the extraction chain at the last step — not a forgery by
itself — and it belongs next to Q3, not in a footnote.

**Why it must be fixed before anything composes with `v_i`.** The `c^2` coefficient
is the only unabsorbed slot (`c^0` is absorbed by `omega`, `c^1` by `psi`), and it
carries exactly `m+1` constraints through `m+1` independent `alpha`s: one `alpha_0`
for `h = g + sum y_j`, one per level for `v_i(v_i-1) = 0`. There is no spare
`alpha`. Slot-constancy is a *linear* condition (a rank-96 projection), and only
*quadratic* terms sit at `c^2`. Enforcing it therefore means either folding a
linear condition into an `alpha` slot, which needs an extra committed message and
challenge to pair with, or extending to `m+2` `alpha`s — a protocol change that
touches the `alpha_0` term, the very term a maintainer was recently about to
delete.

There is a structural tension worth recording so nobody tries to retune it away:
the `q^-4` soundness of the vanishing checks comes from `d/l = 4` coefficients per
slot, and that same 4 is what allows four independent binary coordinates per slot
instead of one. Shrinking `d/l` loses the `q^-4`.

**What B5 must say, in these words:** the extractor returns `v_i in Z_q^l`, not
merely an idempotent of `R_q`; and the proof carries an explicit linear condition
fixing `v_i` under the slot-constant projection, with the `alpha` slot it consumes
named.

**What is unaffected:** the tag. `T = <A', s>` is linear in `s` and never touches
`v`. But anything that consumes the extracted `v_i` — a range proof, conservation,
composition — hits this, which means it arrives at B2 rather than B5.

## Candidate moduli for the irreducible-quartic set

`experiments/irreducible_modulus_search.py` checks the criterion rather than
asserting it: `X^128 + 1` is the 256th cyclotomic polynomial, its irreducible
factors over `F_q` all have degree `ord_256(q)`, so they are quartics exactly when
`q = 1 mod 64` and `q != 1 mod 128`.

| `q` | `q - 2^32` | `ord_256(q)` | quartics |
|---|---|---|---|
| 4,294,966,337 | -959 | 4 | irreducible |
| 4,294,965,313 | -1,983 | 4 | irreducible |
| 4,294,964,929 | -2,367 | 4 | irreducible |
| 4,294,960,321 | -6,975 | 4 | irreducible |
| 4,294,958,401 | -8,895 | 4 | irreducible |
| **4,294,962,689** (prototype) | -4,607 | **1** | **splits into linear factors** |

The prototype's `ord_256 = 1` is the mechanical reason for the ~24-bit cap: every
quartic splits completely, so `R_q ~ Z_q^128` and a challenge difference can vanish
in any of the 128 scalar slots.

Choosing one of these is not a drop-in: the M-LWE and M-SIS estimates have to be
re-derived for the chosen `q`, the quartic-CRT multiplier has to replace the NTT,
and `subring.glue` has to be driven by a 64th root rather than the 256th.

## An open question for both reviewers: one modulus may close both holes

C2 argued the slot-constant hole cannot be fixed by any modulus, "because
`r_i = (zeta^{2i+1})^4` is an explicit fourth power for every valid `q`". C1's
proposed `q` leaves the regime where that is true, and the consequence may be that
C1's change also closes C2's hole.

`experiments/slot_constancy_probe.py` checks it directly:

| `q` | `q mod 128` | `ord_256` | `r_i` that are fourth powers | slots |
|---|---|---|---|---|
| 4,294,962,689 (prototype) | 1 | 1 | **32 of 32** | `Z_q^4`; idempotents are arbitrary subsets |
| 4,294,966,337 (candidate) | 65 | 4 | **0 of 32** | `F_{q^4}`; idempotents are only 0 and 1 |

If the candidate's slots are fields, then `v(v-1) = 0` forces every slot residue to
be 0 or 1, i.e. the extracted `v_i` **is** a 32-scalar binary vector and
slot-constancy is automatic -- the `alpha`-slot problem C2 described would not
arise. The `sum_j (v_i)_j = 1` condition also becomes stronger, because it is then
an equality of quartics rather than of four `Z_q` coordinates.

This is my reading plus a computational check, not a reviewer's conclusion, and the
two answers conflict on scope. It needs adjudication before anyone plans around it:

- **to C1:** was the idempotent consequence of the irreducible-quartic `q`
  intended, and does it remove the need for a separate slot-constant constraint in
  a composed proof?
- **to C2:** does the argument above survive, or is there a reason a product of
  degree-4 field extensions does not deliver slot-constancy?

If it holds, two of the three open items collapse into one decision, and the only
independent work left is the masking.
