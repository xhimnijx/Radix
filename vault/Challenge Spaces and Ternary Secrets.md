---
title: Challenge Spaces and Ternary Secrets
tags: [mathematics, protocol]
---

# Challenge spaces and ternary secrets

A zero-knowledge proof is a conversation where the verifier picks a random
**challenge** and the prover must answer it correctly. Everything depends on the
challenge being unpredictable and small.

## The challenge set `C`

Radix uses ternary challenges:

$$C = \{-1, 0, +1\}^{128}, \qquad P(0) = \tfrac12,\; P(+1) = P(-1) = \tfrac14$$

Three properties are wanted:

1. **Small coefficients** so that products `c · s` stay short (important because the
   response must be bounded).
2. **Invertible with high probability** — the soundness argument divides by `c` or by
   `c − c̃`.
3. **Hard to guess** — the prover must not be able to predict `c` before committing.

## Why `P(0) = 1/2` and not uniform

Uniform ternary (`1/3` each) and the `½, ¼, ¼` distribution give the same support, but
different norms: the `½` distribution has `E[c²] = 1/2` rather than `2/3`, so products
are about 15% shorter, which makes the masking parameters slightly better. The paper
uses `½, ¼, ¼`; Radix uses it everywhere.

> [!note] A real inconsistency that was fixed
> `sigma.py` originally drew uniform `{-1,0,1}` while `setmembership.py` drew
> `½, ¼, ¼`. They are different distributions, and having two protocols in one
> codebase draw from different challenge spaces is a bug waiting to happen. Both now
> use the paper's distribution.

## The invertibility problem, and why `q` decides it

The extraction argument needs `c − c̃` to be a **unit** of `R_q`. As explained in
[[The NTT and the Quartic Decomposition]]:

- if `X^4 − r_i` splits into four linear factors, the slot is `Z_q⁴` and a unit needs
  all four coordinates non-zero. Over 32 slots that is 128 coordinates, giving a
  failure probability ~`2^-24.4`;
- if `X^4 − r_i` is irreducible, the slot is a field and any nonzero element is a
  unit. Failure probability `q^-4` per slot, `~2^-123` overall.

So "is `q` chosen correctly" is the same question as "is the soundness error 24 bits
or 123 bits". This is the single most important parameter decision in the project.

## What the verifier actually checks

`setmembership._is_unit` is modulus-aware:

```python
if ntt.try_transform(...) is not None:      # split regime
    return all(coord != 0 for coord in ntt.forward(poly))
return all(residue != (0,0,0,0) for residue in subring.slots(poly))   # field regime
```

Both are exact *in their own regime*, and using the residue test in the split regime
would silently admit zero divisors. There is a test for exactly that
(`test_candidate_b_unit_checks.py`).

## Why the secret is small

The secret `s` has coefficients in `[−μ, μ] = [−5, 5]`. Two reasons:

- the public key `A·s` must be hard to invert *for a short s*; a large `s` would be
  recoverable by linear algebra;
- the response `z = y + c·s` must satisfy the verifier's bound, which is easier with a
  small `s`.

`μ = 5` is the paper's value and is part of the parameter set in
[[The Parameters and Where Every Number Comes From]].

## The three uses of a challenge in one proof

1. `c′` — binds the prover to the commitments and the response `z′`
   ([[The Set Membership Proof]]).
2. `γ` at each recursion level — the recursion's coefficients.
3. `c` — the final challenge that `h` and `ω` are checked against.

Each is derived from the transcript ([[Fiat-Shamir and the Transcript]]) so the prover
cannot choose them.

## Next

[[Norms and Why They Matter]] — the numbers that decide whether the mask hides the
secret, including the rejection sampling that makes it possible.
