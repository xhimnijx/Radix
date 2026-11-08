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
