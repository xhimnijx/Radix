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

**Struck 2026-11-09: this paragraph was wrong, and C2 says so.** It recorded
their first-round "correction" that the extraction threshold `32p^{d/l} + q^{-d/l}`
is dominated by `32p^{d/l} ≈ 2^-8`, and concluded that the 128 bits come entirely
from the two M-SIS assumptions and that "Q3 and Q5 are one question".

The error was in reading `p`. `p` is the maximum point mass of a **coefficient of
`c`'s reduction**, not of `c` itself. A sum of 128 ternary terms against powers of
`ζ` is essentially uniform in `Z_q`, so `p ≈ 1/q` and `p^{d/l} = q^{-4} ≈ 2^-128`;
the paper's own juxtaposition `2p^{d/l} + q^{-d/l}` only makes sense when the two
terms are the same order. So the threshold is ≈`2^-123` at `q = 2^32`, the
challenge space **does** contribute `q^{-4}`, and the split modulus is capped at
~24 bits by the **c̄-inversion** term, not by this threshold. Q3 and Q5 are *not*
one question.

Kept visible rather than deleted: a wrong number in an audit record should be seen
to be wrong. The corrected position is in the second-review section below.

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

# Second review, 2026-11-09: convergence

Both reviewers re-read the brief and answered the live questions. **C1 is right and
C2 says so explicitly.** The adjudication that was open at the end of the first
round resolves in favour of the modulus change, and it closes two holes at once.

## C2's retraction, in their words

> My statement was "no modulus rescues it, because `r_i = (zeta^{2i+1})^4` is an
> explicit fourth power for every valid `q`". That premise silently assumes a
> 256th root of unity exists in `Z_q` -- i.e. `256 | q - 1` -- which is exactly
> the condition for the split regime.

The criterion is `ord_256(q)`, the multiplicative order of `q` modulo 256, because
`X^128 + 1 = Phi_256` and its irreducible factors over `F_q` all have degree
`ord_256(q)`. `experiments/slot_constancy_probe.py` verifies the classification on
one prime per row:

| `v2(q-1)` | `q` | `ord_256` | factors | `M_q` | idempotents/slot | slot-constancy |
|---|---|---|---|---|---|---|
| 9 | 4,294,962,689 (prototype) | 1 | 128 linears | `Z_q^128` | 16 | **fails** |
| 7 | 4,294,966,657 | 2 | 64 quadratics | `(F_q^2)^32` | 4 | **fails** |
| 6 | 4,294,966,337 | 4 | 32 quartics | `(F_q^4)^32` | 2 | **holds** |

C2's sharpening is also verified: `r_i` is a square exactly when `128 | q - 1`
(`r_i^((q-1)/2) = (-1)^((q-1)/64)`), and the "is it a fourth power" proxy cannot
separate `ord = 1` from `ord = 2` -- both show 32/32 squares. The earlier probe was
right for the wrong reason. Only the order test decides.

## What this means

**Q3' and Q6 are one decision.** With `q = 1 mod 64`, `q != 1 mod 128`:

- a nonzero quartic difference is a unit of `F_{q^4}`, so the extraction's
  `c - c~` fails only with probability about `q^-4` -- the ~24-bit cap becomes a
  ~123-bit margin, and the unit checks cost nothing;
- `v_i(v_i-1) = 0` forces every quartic residue to be 0 or 1, so the extracted
  `v_i` is a **32-scalar binary vector**; `sum_j (v_i)_j = 1` is then an equality
  in `F_{q^4}` and, since `32 < q`, exactly one coordinate is 1. Slot-constancy is
  automatic and **no extra `alpha` slot is needed**;
- with the split modulus, four 1s in different scalar slots can satisfy the four
  `Z_q`-coordinate sums, so the extracted `v_i` selects no column and the statement
  stops parsing. That was the hole.

**Q5' is the only independent blocker.** Both reviewers agree it is arithmetic
rather than research, and C1 gives the thresholds: at root-Hermite `1.0042`,
`s' <~ 2^14.3` and `beta' <~ 2^20.2` for the `A` relation, `s <~ 2^15.2` and
`beta <~ 2^21.7` for the `B_0` relation. The paper's own `s ~ 2^10.5` sits well
inside. ~~C1 suggests `s, s' ~ 2^13-14`, `beta ~ 2^20-21`, `beta' ~ 2^19-20`, with
rejection rate `M ~ 1.2-1.5`.~~ **Superseded 2026-11-09:** C1 recalculated and
withdrew this. At `s, s' = 2^13-14` the per-step rejection rate is
`M ~ 1.005-1.02`, not 1.2-1.5, because that width is 4-8x above `T`; the paper's
`M = sqrt(3/2)` sits at `s ~ 1.57 T`, about `2^10.5-11`. Going to `2^13-14` buys
near-zero rejection but grows `beta` and `beta'` and thins the M-SIS margin to
0.4-2.2 bits, which is not defensible. Corrected guidance at the end of this file.

C2 adds the trap that makes it unanswerable by choosing a number: deriving `s` from
the max norm (`s ~ 11 d mu = 7040`) instead of the standard deviation gives
`beta' = 2^18.6` and drops the key instance to ~`2^113`, fifteen bits short. **The
two conventions differ by about 150 bits.** The fix is to derive `beta, beta'` from
an explicit `Rej0`/`Rej1` with a stated tail bound, then run an estimator, and to
quote the pair together. If it comes out short, the lever is `mu`, not the modulus.

## Work items this creates, none of them protocol changes

1. **Quartic-CRT multiplier.** `ntt.supports()` must go false at the new `q`; ring
   multiplication becomes 32 slotwise 4x4 products. `subring.roots` currently
   derives the quartic constants from a 256th root via `ntt.transform()`; it must
   find a 64th root directly (`r_i = eta^(2i+1)`), and `subring.glue` must be
   rebuilt on the quartic CRT. The slot *order* may permute, so the tests that
   compare against the NTT convention must be re-baselined.
2. **`_is_unit` must change meaning**: at the new `q` it is "all 32 quartic
   residues nonzero", not "all 128 NTT coordinates nonzero". The current
   implementation uses `ntt.forward` and will not run at the new `q` at all.
3. **A real l2 check.** C1: `MAX_RESPONSE_NORM` is an `l_inf` bound but the paper's
   `beta`, `beta'` are `l2` bounds, and `ring.l2_squared` returned a residue. The
   residue bug is fixed; the verifier still needs an `l2` check against `beta`.
4. **Theorem B.1's constant `p` must be redefined.** C2: `p` is defined via "the
   coefficients of `c mod X^{d/l} - zeta^{2j+1}`", which presupposes
   `zeta in Z_q` -- i.e. the paper's own analysis is written for the split case
   that is capped at ~24 bits. Adopting the irreducible modulus moves outside the
   paper's analysis, and it must be redone with field residues. It comes out
   better, but it is work.
5. **One challenge distribution.** `sigma.py` drew uniform over `{-1,0,1}` while
   `setmembership.py` drew the paper's 1/2, 1/4, 1/4. Fixed: both now use the
   paper's distribution.
6. **Price the tag with an estimator.** C2's correction: under `A_ext` the
   instance is `(4+k') x 13`, not `1 x 13`, so even `k' = 1` has a Gaussian
   shortest vector about two orders of magnitude above the collision target.
   `k' = 4` is cheap insurance and shape-matching, **not** forced by the estimate.
   `k' = 1` would be defensible.
7. **Check the later ePrint revisions** before recording the paper's `e_1`
   double-count and sum index as errata.

## C2 on Theorem B.1 under the irreducible modulus

Asked whether the extraction argument survives the modulus change, C2 answers:
**salvageable, with three edits to the statement and none to the argument.**

The skeleton is ring-generic. Four transcripts, `c̄ = c - c~`, divide, extract
`r*, y*` and the messages, expand `f_j`, read the `c²` coefficient, induct down the
levels, collision step. Nothing in it evaluates at points in `Z_q`; it uses only
that `M_q` is 4-dimensional over `Z_q`, that `g` is `Z_q`-linear, and that the
"first `d/l` coefficients" map is a `Z_q`-linear bijection `M_q -> Z_q^4`. All three
hold for `M_q ≅ F_{q^4}`.

**Edit 1 — redefine `p`.** It is defined via `c mod X^{d/l} - ζ^{2j+1}`, which
presupposes `ζ ∈ Z_q`. Replace it with the max point mass of `c`'s image in
`F_{q^4}`. Bookkeeping only: `p` enters through the success threshold in Lemma B.2
and the base case. It also *improves* — a field has no zero divisors, so "if the
relation fails, the first block is uniform, hence hits a fixed value with
probability `q^{-d/l}`" becomes exact rather than conservative.

**Edit 2 — make `c̄` invertibility an explicit clause.** `r* = c̄^{-1}(z - z~)` is
the extractor's first move and Theorem B.1 never states that `c̄` is a unit. Add
either a hypothesis on `C` ("`c - c~` is a unit for `c ≠ c~`") or an error term.
Same four transcripts, same division, one named failure probability — `~2^-24` at a
split `q`, `~2^-123` at an irreducible-quartic `q`.

**Edit 3 — the conclusion is repaired, not salvaged.** "A binary vector
`v = v_1 (x) ... (x) v_m` with one 1 in some `ι`-th position" is not well-typed in
the split ring: there `v_i` is an idempotent of `R_q ≅ Z_q^128` with 128 binary
evaluations, and "one 1" has no referent. That is exactly the missing
slot-constancy lemma. In the irreducible regime `v_i ∈ F_{q^4}^32` with residues in
`{0,1}`, so it *is* a 32-entry binary vector and the sentence means what it says.
**The modulus change is what makes the theorem's statement true** — the "one
modulus, two holes" result, now at theorem level. A free strengthening comes with
it: the `B`-block condition becomes `(Σ_j (v_i)_j - 1)·γ_0 = 0` with `γ_0` a nonzero
field element, so it is exact rather than a 4-of-4-coordinate condition.

What must be *rewritten*, though not restructured: binaryness lands directly in
`{0,1}^32`, so one-hot follows from `Σ_j (v_i)_j = 1` immediately — the induction
gets **shorter** — and the several "uniform in `M_q`" sentences must be re-justified
by "multiplication by a nonzero field element is a bijection".

### What this does to the code estimate

C2, on scope: `subring.slot` computes `y mod (X^4 - r_i)` by Horner, which is valid
whether the quartic is irreducible or split, and `quartic_multiply` is unchanged —
field multiplication is the same routine. **Only `glue` (and `from_constants`, which
calls it) must move off `ntt.inverse` to a 32-way CRT, and the root search must find
a 64th root instead of a 256th.** So `slot`, `slots`, `g`, `pairing`,
`quartic_multiply` and the whole recursion layer are untouched.

The corrected work estimate for adopting the modulus:
1. `subring.glue` / `from_constants` -> 32-way CRT (the one real piece of new code).
2. `subring.roots` -> find a 64th root directly instead of deriving it from the NTT.
3. `ring.mul` -> quartic-CRT (32 slotwise products) instead of the 128-point NTT.
4. `_is_unit` -> "all 32 quartic residues nonzero".
5. Re-derive the M-LWE/M-SIS estimates at the chosen `q`.
6. Restate Theorem B.1 with the three edits above.

Nothing in items 1-4 is a protocol change.

## C1 on the mask, measured here

C1's third-round answer, and a measurement that reproduces it.

**The irreducible ring does not change `M`.** Split or irreducible is a change of
CRT basis, not of ring multiplication: both compute the same negacyclic
convolution in `Z_q[X]/(X^128 + 1)`, and SMILE's rejection sampling is defined on
that coefficient vector (Lemma A.5's inner product is over coefficients). So
`T = ||c r||_2` and `M = exp(T^2 / 2 s^2)` are unchanged for the same `c`, `r`.

**The trap this creates for the port.** The quartic-CRT multiplier must glue back
to the coefficient basis *before* any norm or rejection check. A norm taken in the
quartic-slot basis is a different quantity -- the CRT is not an isometry -- and the
paper's `M` would no longer apply. This is an implementation requirement now, not
an observation.

`experiments/mask_calibration.py` measures it on the code's own distributions
(ternary 1/2, 1/4, 1/4 for `c`; uniform on `[-5,5]` for `r`):

| quantity | model | measured |
|---|---|---|
| coefficient variance of `c r` | `128 * E[c^2] * E[r^2] = 640`, `sigma = 25.3` | **627, sigma = 25.0** |
| `T` for `z` (W = 33), 99th percentile | ~1.7k | **1701** (`2^10.7`) |
| `T'` for `z'` (ell = 13), 99th percentile | ~1.1k | **1081** (`2^10.1`) |
| `s` giving `M = sqrt(3/2)` | `1.57 T` | **2671 (`2^11.4`), 1698 (`2^10.7`)** |

The rejection curve matches C1's table to three digits: `M = 1.41` at `2^11`,
`1.09` at `2^12`, `1.02` at `2^13`, `1.005` at `2^14`.

**Calibrated parameters, from the measured `T`:**

| mask | `T` | `s = 1.57 T` | `beta` | target | reachable at `delta = 1.0042` | margin |
|---|---|---|---|---|---|---|
| `z` (W = 33) | 1700 | 2666 (`2^11.4`) | 244,992 (`2^17.9`) | `2^27.9` | `2^31.7` | **3.8 bits** |
| `z'` (ell = 13) | 1072 | 1673 (`2^10.7`) | 96,512 (`2^16.56`) | `2^17.6` | `2^21.2` | **3.6 bits** |

So the paper's own regime -- `s ~ 1.57 T`, `M = sqrt(3/2)`, overall `2M^2 ~ 3` --
is the right choice, and it leaves about 3.7 bits of root-Hermite margin. The
reachable norms are C1's heuristic values at `delta = 1.0042`; **a lattice
estimator must confirm them before any security claim.**

What this does *not* settle: whether 3.7 bits of RHF margin is 128 bits. That is
the estimator's job, and it is the last open question in the parameter set.


# Fourth review, 2026-11-09: the answer to the blocker was "you are not short"

Both reviewers answered the five questions. The headline is that Q-A's premise was
wrong: the parameters are **not** short. That is the most consequential result of the
whole project so far, and it came with a correction to my own numbers.

## Q-A — the estimator question, answered

**My inputs mixed two lattice-dimension conventions.** For `A` I used 1664, which is
the full solution-lattice dimension `ell*d`. For `B_0` I used 2944, which is
`23*d` — and `23` is the **commitment arity** `kappa + rows + 2m + 1`, not the width.
The width is `W = 33`, so the correct dimension is `W*d = 4224`.

That is the *same class of error* as the commitment-arity defect the Rust port found:
the arity and the width agree in one configuration and differ in every other.

Recomputed with consistent conventions (`delta_b(n)` inverted for the target, Core-SVP
`2^{0.292 b}`):

| relation | n | `det^{1/n}` | target | delta | block | Core-SVP |
|---|---|---|---|---|---|---|
| `A`, untagged, k = 4 | 1664 | `2^9.85` | `2^17.56` | 1.003218 | 541 | **`2^158`** |
| `A`, tagged, k + k' = 8 | 1664 | `2^19.69` | `2^17.56` | < 1 | n/a | beyond the model |
| `B_0`, W = 33 | 4224 | `2^9.70` | `2^27.90` | 1.002992 | 598 | **`2^175`** |
| `B_0`, at the wrong 2944 | 2944 | `2^13.91` | `2^27.90` | 1.003299 | 523 | `2^152` |

**Both clear 128 bits with 25-47 bits to spare.** The binding relation is the untagged
base `A` at `k = 4`, at about `2^158`.

### The framing error was mine as well

I reported "3.6 and 3.8 bits of slack" by comparing targets to reachable norms at
`delta = 1.0042` and concluded the parameters were unproven. The comparison is
backwards: because the targets sit **below** the reachable norms, the required `delta`
is *smaller* than 1.0042, which means the reduction needed is *stronger* than the
heuristic assumed. C2's conversion: one bit of target is worth roughly 33 bits of
Core-SVP near this boundary, so the `A` margin is about 76 bits, not 3.6.

### What this changes

Nothing needs to change. The levers, if a real estimator disagrees, in order of
bits per byte: `k += 1` (+110 bits for 512 B), `log q` 32 -> 40 (+109 bits for +25%
bytes), halving `beta'` (+34 bits, no bytes, but weakens M-LWE). `ell` and the ring
size are not the levers.

**Two things that must not be overclaimed:**

1. `2^158` is the cost of the **assumption**, not the bit-security of the scheme. The
   extractor is a four-transcript rewinding argument, so a forger's advantage crosses
   the reduction with a polynomial loss. Quote it as "the assumption is ~2^158".
2. At `ord_256(q) = 4` the module-LWE hardness proofs in the literature, which are
   stated for `q = 1 mod 2n`, do not apply: the modulus size and the lattice are
   unchanged (the coefficient embedding of `A` depends only on `log q`), but we hold a
   conjecture rather than a theorem. That belongs in `SECURITY-NOTES.md`.

## Q-B — signable, with four edits and a sharper reason for the modulus

C2 added a fourth edit: the `q^{-d/l}` uniformity step must be restricted to the field
regime, and in the split regime it is not merely undefined but **unjustified** — a
nonzero failure witness can be a zero divisor, so the product is confined to a
1-dimensional submodule and the hit probability degrades from `q^-4` to `q^-1`. The
split modulus was worse than the `2^-24` challenge-difference cap suggested, which is a
better reason for the change than the one I had.

C1's caveat: `q^-4` is the uniform-field approximation; the relevant distribution is
the *difference* (coefficients in `-2..2`), so the exact constant must be worked out
rather than assumed. The field property makes "nonzero iff unit" exact, not the
probability.

Both agree the induction loses one structural step (the idempotent-to-slot-constant
lemma) and is not shorter in depth.

## Q-C — a discrete sampler is required, and the reason is portability

C2's correction to my estimate: rounding a continuous Gaussian differs from the
discrete one by `1 + O(1/sigma^2)` pointwise, not `O(1/sigma)`, so about `2^-22.8` per
coefficient and `2^-16.8` over the 4224-coefficient response — not the `2^-11` I quoted
(per coefficient). C1's `sqrt(N)/s ~ 2^-5.4` is the coarser union bound.

The decisive argument is the one neither of us had made clearly: a rejection argument
compares the sampled distribution to a fixed one, and if Python and Rust both round
floats, `libm` disagreement makes them *different distributions*, so the analysis
applies to neither and `verify_rust_proof.py` is a weaker test than it looks. The fix
is a table-driven discrete Gaussian driven from an integer RNG, identical in both
languages. Cost: one lookup per coefficient, negligible.

## Q-D — the tag strengthens the signature; k' = 1 is sufficient

Both agree, and both correct my framing:

- `A_ext` at `k + k' = 8` gives `det^{1/n} = 2^19.69`, above the target, i.e. beyond
  what the delta model can price. **The tag strengthens the signature.**
- C2: the tag's own collision instance at `k' = 1` is a 1x13 with block 729, about
  `2^213` — 85 bits of margin. **`k' = 1` is sufficient**; `k' = 4` is
  over-provisioned but harmless, and it does match `A`'s shape.
- The binding instance in the whole system is the untagged base relation at `k = 4`,
  which no choice of `k'` touches.

So `k' = 4` was chosen for the right *property* (distinct-note collision) but the
estimate does not require it. Keeping 4 is cheap insurance; the claim that it is
"required" is wrong.

## Q-E — what running it found, and what was fixed

C1 found the concrete integration break, and it was real:

> the spend layer is still wired to the withdrawn tag.

`spend.build_spend` passed `tag_keys` into `RS.sign`, reaching `tagmod.prove_tag`; and
`Spend.tags` read `signature.tag_proof`, which the same-witness extension never
populates, so a tagged spend built the new way would have reported `None` and a ledger
doing `if tags is None: skip` would have skipped its tag checks.

**Fixed by removal and refusal** (commit `74f68ae`): the argument is gone from
`build_spend`/`verify_spend`, `Spend.tags` returns `None` and says why, and
`setmembership.prove`/`verify` **raise** if `tag_keys` is supplied, naming it
WITHDRAWN. The old tests were replaced by guards that the path is gone. The two
dangerous docstring sentences ("No rejection sampling", "the `c^1` part cancels
identically") are corrected.

## The most serious item outside Q-A: ring-pool binding

Both reviewers agree, and it is my own finding from writing the vault: the proof binds
the message, `w`, the commitments, `h`, `omega` and `c` — **not the ring**. The verifier
rebuilds the ring from its own pool, so it is sound only because prover and verifier
are one process.

The fix they both give is the same and is cheap: absorb a ring digest (over the ordered
public keys, or a pool Merkle root) as a transcript label beside the message, with the
anchor committing to the pool root. Zero proof bytes. It changes the transcript, so
Python and Rust must change together — the same portability discipline as Q-C.

## Errata, confirmed by derivation

Both hold in the 12 Aug 2021 PDF, per C2's derivation rather than a later revision:

1. The `e_1` double count between Fig. 9 line 12 / eq. (27) and eq. (24).
2. The sum index in eq. (24): the printed `sum_i gamma_{m,i}` must be
   `sum_i gamma_{m,i+1}`, because the inner product pairs `e_1` with
   `gamma_{m,2}..gamma_{m,m+1}`. The code uses the latter and is the consistent choice.

Neither reviewer could retrieve the 2022-05-20 revision, so both stay "suspected
erratum in the 2021 PDF".

## Verification cost

C1: batching does not transfer from Schnorr. C2: the all-linear part can be batched,
but that does not remove the set-matrix cost, and the 110 ms is better attacked by
measuring where it goes. Both align with what this project measured independently:
algebraic batching has nothing to amortise, and parallelism gives 4.22x on 8 cores.
C2's suggestion to profile the CRT glue and re-encoding is the next useful measurement.


# Ring-pool binding, 2026-11-09: implemented

Both reviewers called this the most serious item outside Q-A, and both gave the same
fix. It is now in the code.

## The defect

The proof bound the message, `w`, the commitments, `h`, `omega` and `c` — but **not the
keys**. The verifier rebuilds the ring from its own pool, so the scheme was sound only
while prover and verifier were the same process. On a network they are not: the node
chooses a ring by pool index, and a proof made against a different pool would have
verified against the node's.

## The fix

A digest of the ordered ring keys, absorbed into the transcript **before** `w`:

```
Transcript(PROOF_TAG)
    .absorb(b"message", message)
    .absorb(b"ring",    ring_digest(statement))   <- new
    .absorb(b"w",       ...)
    .absorb(b"t",       ...)
```

`ring_digest` hashes `SHAKE256(b"radix/ring/v1", pk_0 || pk_1 || ... )` over the encoded
keys in order and squeezes 32 bytes.

Properties worth stating:

- **Zero proof bytes.** The proof is still 32,512 B. The digest moves the challenge; it
  does not add a field.
- **No new check to get wrong.** A prover working from one ring derives a different `c`
  from a verifier holding another, so the proof simply fails. There is no digest
  comparison that could be skipped or miswritten.
- **Implemented in both languages**, in `setmembership.ring_digest` and
  `statement::ring_digest`, with the same framing. The cross-language fixtures were
  regenerated and acceptance holds in both directions.

## Tests

- `test_a_proof_does_not_transfer_to_a_different_ring` — a valid proof, verified against
  a ring with one public key swapped, is rejected.
- `test_the_ring_digest_changes_with_the_keys` — a digest that ignored the keys would be
  decoration.
- `the_head_binds_the_ring_digest` in Rust — different digests give different challenges.

## Still open on this item

Q-F asks the reviewers to confirm the placement and whether the key order needs
canonicalising. The implementation absorbs the digest immediately after the message,
which is the placement both suggested in prose. If a reviewer wants it elsewhere, it is
a one-line move on each side — but the ordering requirement is now recorded: **any
change to this must be made in both implementations at once**, or the cross-language
tests start comparing different protocols.


# Compression, step one, 2026-11-09: `z` is now bounded and packed

The paper's ring signature is 17.27 KB for ring size 1024; ours was 32,512 B. The first
step toward closing that gap does not touch the protocol at all.

## What changed

`z` is the only large vector whose coefficients are provably small: the verifier rejects
any coefficient above `12 * sigma`, which for `sigma = 2665.5` is 31,986 and fits a
signed 16-bit integer. It was being written as a 32-bit residue modulo `q`, which spends
four bytes to carry a value that needs two.

- **The infinity-norm check is now explicit in both verifiers.** The paper requires it
  and this implementation did not do it. Adding it is a tightening, not a change of
  meaning: a proof whose `z` exceeds the bound was already outside the distribution the
  soundness argument covers.
- `Proof.encode` writes `z` as signed 16-bit centred values; the decoders in
  `radix_testnet/codec.py` and `proof_rust/src/codec.rs` read them back and reduce into
  `[0, q)`.

## Measured

Both responses are bounded this way, so the same treatment applies to `z'` with its
own sigma (`12 * 1673 = 20,076`, also 16 bits).

| | before | after |
|---|---|---|
| untagged proof | 32,512 B | **21,760 B** (‑33.1%) |
| tagged proof | 36,608 B | **24,832 B** |
| tagged total with tag | 38,656 B | **26,880 B** |

Verified rather than assumed: the reduced proof still verifies; it round-trips through
the decoder with an identical `response` vector; both cross-language fixtures were
regenerated and each implementation accepts the other's proof at the new size; the Rust
suite is 70 green and the Python fast suite 447.

**What this is not.** It is not the paper's entropy coding. A Gaussian of standard
deviation `sigma` costs about `log2(sigma * sqrt(2*pi*e))` bits per coefficient, roughly
13.4 bits here, and 16 bits is what a fixed-width field gives. It is also not the two
larger wins the paper describes: compressed public keys (`t0` rounded modulo `2^D`) and
Bai-Galbraith compression of the MLWE error. Those change the shape of the statement and
are the next steps, not this one.


# Sixth pass, 2026-11-09: [25] identified, the theorem signed, k' settled

Both reviewers answered. Three results change the code or the plan.

## Reference [25] is identified

**Lyubashevsky, Nguyen, Seiler. "Practical Lattice-Based Zero-Knowledge Proofs for
Integer Relations." CCS 2020, pp. 1051-1070. ePrint 2020/1183.** The same authors as
SMILE, so it is the direct predecessor and where the addition proof, the carry vector and
the approximate-shortness argument live.

C1's structural answer: the carry is **more message rows in the existing `B'0`**, so it
shares the rejection step rather than needing a second protocol — but `B'0` must be
regenerated with those rows, which is a parameter change. The exact rejection algorithm
and constants still need the paper.

## One-time addressing: my proposed repair is a deanonymisation

I had suggested carrying the shift `H` as a public scalar. C1 showed it fails: with `H`
public, anyone computes `pk_out - H*P_view = P_spend`, recovering the spend key and its
tag image and collapsing the anonymity set to one. The secret-shift version requires a
multi-witness relation — both secrets short, `H` as a witness, set matrix `[A, H*A]` — a
research milestone rather than a parameter change.

A published family does exist: ePrint 2025/112, *Post-Quantum Stealth Address Protocols*
(Mikic, Srbakoski, Praska), LWE/Ring-LWE/Module-LWE with Kyber as the KEM. Preprint, not
peer reviewed, and the property to check first is that the sender must not learn the
one-time spend secret.

## Theorem B.1' is signed, with one new lemma

C2 wrote it out in full under four edits (E1 `p` over `F_{q^4}`; E2 `c-bar`
invertibility as an explicit clause; E3 typing the conclusion as `v_i in {0,1}^l`; E4 the
uniformity step restricted to the field regime) and signed it as a correct rendering of
Appendix B. The one genuinely new piece of mathematics is a lemma: `p_Delta <= q^-4
(1+o(1))` for the centred difference of two ternary draws.

C2 signs the theorem but **not** a security claim, because two things sit outside it: the
mask sampler and the ring binding. **Both were closed after that answer was written** —
the discrete Gaussian now comes from one table shared by both languages, and the ring
digest is bound into the transcript. That is worth telling them.

C2 also quantified the estimate instead of running it: A is 2^143-2^173 and B0 is
2^160-2^190, both clearing 128 at the pessimistic end, with the band set by beta' and
sensitivity of about 15 bits per half-bit of target. And a correction worth keeping: M is
a dial, not an uncertainty — the measured 9.75 attempts imply an effective M of about
3.1, well above the sqrt(1.5) in the code, so the claim should read "2^158 at
M = sqrt(1.5)" with M recorded alongside the number.

## k' = 1, implemented

C2 gave three reasons: the collision instance is 2^213 at k' = 1 (85 bits over target);
k' = 4 puts the target below det^(1/n), paying for margin already held; and fewer rows
means fewer module equations in `s` on top of `pk = A s`, which *helps* hiding. The
implementation now uses 1.

| | k' = 4 | k' = 1 |
|---|---|---|
| Tagged proof | 24,832 B | **22,528 B** |
| Tag | 2,048 B | **512 B** |
| Total | 26,880 B | **23,040 B** |

That exposed `tagged_size_bytes`, which still returned the old 38,656: it counted four
bytes per response coefficient after they had been compressed to two, and it ignored the
row count the caller actually uses. It now matches the measured sizes exactly at both
k' values.


# The k' reduction cost 8 bits, 2026-11-09

Found by running `experiments/estimate_sis.py --check` after the k' change, which is the
argument for pinning a check to the current parameters instead of to a remembered number.

`W = kappa + lambda + rows + 2m + 1` and `rows = k + k'`, so reducing k' from 4 to 1
shrinks the commitment width from 33 to 30. B0's dimension is `W*d`, so it fell from 4224
to 3840, and its Core-SVP estimate fell from **2^175 to 2^167**.

C2 priced the tag's own collision instance (2^213 at k' = 1) and the module equations, and
concluded k' = 1 was the better point — but the coupling between k' and B0's width was not
in that analysis, and neither of us noticed it when the change was made. It is a real
trade: k' = 1 gives 8 fewer bits on B0 in exchange for 2 KB per proof and one fewer module
equation in s.

The decision stands — 2^167 clears 128 with 39 bits to spare, and the binding relation is
still A at 2^158 — but the number reported for B0 was wrong for several rounds and is now
corrected here and in `SECURITY-NOTES.md`.

Worth putting to C2: whether the k' trade should be re-priced now that both ends of it are
visible — 8 bits of B0 against 2 KB and a fifth of the set-matrix work per tagged proof.


# Ninth pass: the encoding is coefficient-domain, and the reviewers disagree on the shortcut

C1 answered **(a)**: the paper's `ǎ` is a coefficient-domain polynomial whose coefficients are
the base-4 digits; the carrying identity is coefficient-domain; the slot-constant packing is a
different subspace that cannot enforce the amount range. The range layer should be rebuilt
coefficient-wise. `LinearRelation`, the carry identity and the digit encoding survive. The
evidence he cites is the paper's own proof-size formula (p. 55), where the auxiliary
commitment and `z` carry an extra `m(2r-1)` terms -- a coefficient-wise bit/carry
decomposition, not two slot-constant bit polynomials per amount.

C2 also answered (a) and withdrew his earlier budget answer, saying he had not checked that
binaryness and carrying live in the same subspace. He then supplied an argument for a cheaper
route he called (b): keep the slot-constant digits, drop `(X-4)` entirely, and pair the digit
polynomial against a public element `w4` whose slot-`i` residue is `4^i`, so that the pairing
recovers the integer directly, with balance as one relation. The catch he named is the modulus:
the pairing is computed in `Z_q`, so amounts must stay under `q/2` -- about 2^29 for 2-in-2-out
with 15 base-4 digits -- which needs no carrying at all.

C1 rejects slot-wise carrying outright: "You would need a new theorem connecting the slot sum
to the integer identity, and the paper does not provide one. Do not invent it." Note that C1 is
rejecting slot-wise *carrying*, which is not what C2's construction does -- C2's route avoids
carrying because the pairing yields the integer directly.

## What a numerical check establishes

C2's identity, tested directly at the current parameters: with `w4` slot-constant at `4^i` and
`m` slot-constant at the digits `d_i`,

    sum of slot values of (w4 * m)  =  4^i * d_i summed   EXACTLY
    any single coefficient of (w4 * m)  =  no match
    is (w4 * m) slot-constant?  =  no

So the identity holds for the **trace** (the sum of the CRT slot values), not for the ring
product, and the product leaves the slot-constant subspace -- the same phenomenon that killed
the `(X-4)` balance relation. `w4` is public and the sum is linear in `m`, so the trace can be
applied by a verifier; but a `LinearRelation` currently compares *polynomials*, so expressing
this needs one extension: an optional scalar **trace mode**, where the check becomes
`trace(sum_j w_j m_j - k) = 0` rather than the polynomial equality. The residual argument is
unchanged, because the trace is `Z_q`-linear.

That is a small, checkable extension rather than a second proof system. It is the reason (b)
may be viable where C1 expected it not to be -- and equally the reason it cannot be called
sound until C1 has seen the trace form rather than the carrying form he rejected.

## Where this leaves the range layer

Both reviewers agree the current slot-constant alpha-slot range layer is **wrong for the amount
path** and should be retired rather than extended. Both agree `LinearRelation`, the
coefficient-domain carry identity and the base-4 digit encoding are reusable. What is unsettled
is whether the amount path goes through the paper's coefficient-wise subsystem (C1) or through
the trace pairing with a documented supply cap (C2).

## A consequence of the modulus worth recording

C2's observation, and it is the third time this modulus choice has decided something: choosing
`ord_256(q) = 4` to get the `q^-4` challenge-difference bound is what makes slot-constant
binaryness sound (each residue is an idempotent of a field), and simultaneously what makes the
Hadamard product coordinatewise-inexpressible (the ring product is quartic, not coordinatewise).
Slot constancy, the challenge difference, and now the range layer are all consequences of one
parameter.


# C1's verdict: the trace pairing is sound for balance, under three conditions

Answered directly, and it unblocks the balance argument without `[25]`'s carry/addition vector
layer:

    Tr(w4*m_in) = Tr(w4*m_out) + fee   (mod q)

holds, so the integer difference is a multiple of `q`. If both totals stay under a supply cap
`C < q/2`, the integer difference has absolute value below `q`, so the only multiple of `q` it
can be is zero, and integer balance follows. This is a **different trade-off** from the carry
identity `a + b + f(X-4) = c`: the carry proves polynomial addition over `Z` and gives 64-bit
no-wrap without a cap, while the trace pairing proves the evaluation at `X = 4` modulo `q` and
buys the integer conclusion with the cap.

Three conditions, and all three are now recorded in code rather than prose:

1. **A coefficient-wise range proof is still required.** The trace pairing is an evaluation, not
   a range check. It assumes the coefficients are digits, so it does not substitute for proving
   them in `{0,1,2,3}`. This is the remaining work on the amount path.
2. **The cap must be a consensus rule.** A documented cap is not a proof. `check_supply` is
   called on every block, `Chain.minted` accumulates, and exceeding the cap raises rather than
   returning a verdict. Six tests in `tests/test_testnet_supply_cap.py`.
3. **`C < q/2`.** Measured: the emission schedule totals **570,093,820 atoms** = 2^29.1, a factor
   of 7.5 below `q/2 = 2^31`. The cap is a property the schedule already had.

## What this settles and what it does not

Settled: balance needs no carry vector, the `(X-4)` path is retired rather than extended, and the
`LinearRelation` primitive is exactly the mechanism -- once it gains a scalar trace projection.

Not settled: the coefficient-wise range proof. C1 confirms `[25]`'s bit/relaxed layer is a
candidate, and that the trace pairing is not a substitute for it. So the amount path is: digits
committed coefficient-wise, range proven coefficient-wise, balance by trace pairing under the cap.

Also confirmed in my favour: because range rows reuse `r` and do not move `W`, C2's feared +2.6
bits per message on B0 does not bite. The estimate stands at A 2^158 / B0 2^167 with the range
machinery inside the proof.


# The trace pairing does not survive being turned into a scalar check

C1's identity is right at the statement level: `Tr(w4*m_in) = Tr(w4*m_out) + fee` modulo `q`, and
with every total under `q/2` the integer difference is zero. I verified the functional itself
before building on it -- `trace(w4 * m) == sum 4^i d_i` for arbitrary digit vectors, five trials,
exact.

What does not work is checking it as a **scalar** inside this proof, and the reason is short:
**`trace` is not multiplicative.** The prover would send `s = Tr(sum_j w_j a_j)` and the verifier
would compare it against `Tr(sum_j w_j f_j) + Tr(c * k)`. But `f_j = a_j - c*m_j`, so
`Tr(sum_j w_j f_j) = s - Tr(c * sum_j w_j m_j)`, and the challenge enters as a **ring product**.
`Tr(c * k)` is not `c * Tr(k)`, so the two sides do not cancel into `Tr(rho) = 0`. The check that
comes out is `Tr(c * rho) = 0`, which does not imply `Tr(rho) = 0`.

Measured, so this is not a derivation I might have got backwards: prover sent 810,038,648 against
a verifier value of 2,690,466,006 from a masked trace of 1,584,030,714 -- not reconcilable by any
scalar factor of `c`.

## What would work instead

Commit the **paired value** `A_j = w4 * m_j` directly as the message, so the relation
`sum_j sign_j * A_j - k = 0` is a polynomial equality and `LinearRelation` applies exactly, as C1
said it would. The difficulty moves rather than disappearing: the range proof then has to say
something about `A_j`, which is not digit-shaped, so the digit range and the committed amount are
two different objects and need a link. That link is the same bridge C2 identified as not
`R`-linear.

So the honest position: the statement is sound, the primitive is right, and the bridge from a
committed digit polynomial to its paired value is the remaining piece -- the same bridge, in a
different place.

The trace code was written, measured, found not to give the conclusion, and reverted rather than
shipped. `LinearRelation`, the trace functional and the pairing element are sound as utilities;
the scalar check built on them was not.
