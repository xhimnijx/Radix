# Confidential transactions: what the paper actually specifies

A plan, sourced from `studies/2021-564.pdf`. Every claim below carries a page number.
Where the paper is silent I say so rather than filling the gap.

> Status: **plan only, nothing implemented.** Today every output value is a plain
> integer in the clear. This document is what it would take to hide it.

## 1. The data model (p. 52)

A **public key** is a module-LWE vector

```
pk = u = B₀ · s            s ∈ R_q^{λ+κ+1},  B₀ ∈ R_q^{κ×(λ+κ+1)}
```

with serial number `sn = ⟨b₁, s⟩`. `B₀` is a BDLOP commitment matrix and `s` is the
secret key, including one error polynomial used only for the serial number.

A **coin** is a BDLOP commitment to a single polynomial `ǎ`:

```
t  = t₀ ‖ t₁
t₀ = B₀ · r                r ∈ R_q^{κ+λ+1}   (the coin key)
t₁ = ⟨b₁, r⟩ + ǎ
```

and `ǎ` encodes an amount as **base-4 digits**: its coefficient vector has entries in
`{0, 1, 2, 3}` and represents `amt` in base 4 over `[0, 2^64 − 1]` (p. 52). Sixty-four
bits is therefore **32 digits**, so only 32 of the 128 coefficients carry information.

That encoding is the whole trick. **The range proof is not a bit-decomposition — it is a
digit-membership proof**: each of the 32 coefficient positions must lie in `{0,1,2,3}`.
This codebase already has machinery that proves membership in a small set (the `α`
slots), which is why the construction is a plausible fit rather than a rewrite.

## 2. The statement (p. 52-53)

For `m` inputs `(u_i^(in), t_i^(in))` and `n` outputs `(u_i^(out), t_i^(out))`, the
sender proves knowledge of every coin key `r_i^(in), r_i^(out)` and every input secret
key `s_i^(in)`, and proves:

1. each input's `u_i^(in)` opens to `s_i^(in)`, and the serial number is correct (p. 53);
2. each coin opens to its `ǎ` (p. 52);
3. the amounts balance — inputs equal outputs plus the fee (p. 54);
4. each output amount is in range (p. 52, via the digit encoding);
5. the input accounts are hidden — the one-out-of-many proof replaces each input's
   `u_i^(in)` and `t_i,0^(in)` with a matrix built from the whole ring (p. 52-53).

## 3. The matrices

| Matrix | Shape | Role | Page |
|---|---|---|---|
| `B₀` | `κ × (λ+κ+1)` | commits to keys and coin randoms | 52 |
| `B'₀` | wider extension of `B₀` | commits to all secrets at once, plus amount recommitments | 52 |
| `U_i^(in)` | `κ × l_r` | ring of public keys, the real one in one column | 52 |
| `T_i^(in)` | `(κ+1) × l_r` | ring of coins, the real one in one column | 52 |
| `P_{1,i} = α_i U_i^(in) + β_i T_{i,0}^(in)` | `κ × l_r` | committed form of the linear combination | 53 |

`l_r` is the ring size — `32^depth` here, 1024 at depth 2.

## 4. One masked opening, amortised (p. 52)

Rather than one opening per secret, the sender produces a single masked vector:

```
z = y + Σ_{i=1..m} α_i s_i^(in)
      + Σ_{i=1..m} β_i r_i^(in)
      + Σ_{i=1..n} γ_i r_i^(out)
      + c · r'
```

with independent challenge polynomials `α_i, β_i, γ_i, c`, where `y` is the mask and
`r'` is the auxiliary commitment randomness. Shorter vectors are zero-padded to the
length of `r'` (p. 52).

The equation the verifier checks:

```
B'₀ z = w + Σ α_i u_i^(in) + Σ β_i t_{i,0}^(in) + Σ γ_i t_{i,0}^(out) + c · t'₀
```

and in committed form, with the ring folded in (p. 52-53):

```
B'₀ z = w + Σ P_{1,i} v_i + Σ γ_i t_{i,0}^(out) + c · t'₀
```

`w` is not sent in the clear — it is committed inside the auxiliary commitment `t'`.

## 5. How balance is enforced (p. 53-54)

This is the part that is easy to get wrong, and it is **not** a simple sum.

1. **Recommit the amounts** inside `t'`, at offsets `k+1 … k+m` for inputs and
   `k+m+1 … k+m+n` for outputs, with `k = 7` concretely (p. 53):

   ```
   t'_{k+i}       = ⟨b'_{k+i},   r'⟩ + ǎ_i^(in)
   t'_{k+m+i}     = ⟨b'_{k+m+i}, r'⟩ + ǎ_i^(out)
   ```

2. **Prove the recommitments match the coins.** The paper combines the amortised opening
   with the auxiliary openings, which produces an opening of the differences with
   *quadratic* challenges `c·β_i`; a second garbage commitment `t'₂ = ⟨b'₂, r'⟩ + ⟨b'₁, y⟩`
   removes the remaining `c` dependence (p. 54). The resulting equation is printed in
   full on p. 54 and is the one to implement.

3. **Prove the addition with carries.** The amounts are base-4 digit vectors, so summing
   them needs a **carry vector**, and carrying is where the difficulty lies: with many
   integers the carry is no longer binary, and a non-binary carry *cannot* be proven
   small by algebraic techniques alone (p. 54).

   The paper's resolution is to cite the multiplication proof from reference **[25]** and
   use an "approximate shortness proof" for the carry vector, described as having
   "negligible additional cost" (p. 54).

> [!note] Reference [25], identified by both reviewers (2026-11-09)
> **Lyubashevsky, Nguyen, Seiler. "Practical Lattice-Based Zero-Knowledge Proofs for
> Integer Relations." CCS 2020, pp. 1051-1070. ePrint 2020/1183.** The same three
> authors as SMILE, so it is the direct predecessor. C1 adds the structural answer:
> the carry is simply more message rows in the existing `B'0`, so it needs **the same
> rejection step**, not a second protocol -- but `B'0` must be regenerated with the
> carry rows, which is a parameter change rather than an algebraic incompatibility.
> The exact rejection algorithm and constants still need the paper in hand.

> [!note] Resolved: the carry proof is the *relaxed* range proof, and it is cheap
> **Lyubashevsky, Nguyen, Seiler. "Practical Lattice-Based Zero-Knowledge Proofs for
> Integer Relations." CCS 2020, pp. 1051-1070. ePrint 2020/1183** — the same three authors
> as SMILE, now in `studies/2020-1183.pdf`.
>
> The carry never needs a bit-decomposition. [25] p. 5 rests on one observation:
>
> > for `f in Z^k` and masking `y in Z^n`, over a random `R in {0,1}^{n x k}`, the
> > probability that `max(Rf + y mod q)` is at least half of `max(f)` is at least
> > `1 - 2^-n`.
>
> So **if `Rf + y` is small then `f` was small.** The prover sends `z = Rf + y`, applies
> rejection sampling to hide `f`, and proves with a linear argument that `z = Rf + y`.
> The verifier checks one norm bound. That is the "negligible additional cost" SMILE
> means, and it is one masked opening rather than `k` binary proofs.
>
> Also worth recording from [25] p. 4: for **addition** the carry *is* binary, and the
> relation is `a + b + f·(X - 2) = c` with `M` the `(k+1) x k` matrix of `-2` on the
> diagonal and `1` below it. The carry only stops being binary when summing **many**
> integers, which is exactly the multi-input case SMILE has.

**Measured here** (`radix_core/candidate_b/lattice/relaxed.py`, 5 tests): with 64 columns,
128 rows and a mask width of 64, an honest carry peaks at about 417 against a verifier
bound of 576, a single coefficient inflated by 40x is caught **50 times out of 50**, and a
coefficient inflated to `q/3` is caught 50 out of 50. An honest carry is rejected 0 times
out of 50.

The first version of that module used a *uniform* mask, which makes `z` uniform and
rejects every honest proof — 200 out of 200. The mask has to be bounded for the check to
mean anything, which is the same reason lattice signatures reject rather than sample.

## 6. Size accounting (p. 54-56)

The proof consists of three things (p. 54): the auxiliary commitment `t'`, the masked
opening `z`, and one polynomial `h₂`. Challenges are expanded from a seed and cost
nothing.

| Object | Size | Page |
|---|---|---|
| Public key | 3.28 KB | 54 |
| Coin | 3.78 KB | 54 |
| **Full CT proof, 2-in/2-out, ring 1024** | **26.49 KB** | 55 |
| Full CT proof, 100 inputs, ring 1024 | 344.26 KB | 56 |

For comparison, this implementation's proof for a **much smaller** statement (one input,
no amounts) is **21,760 B**. The paper's ring-signature-only figure at the same ring size
is 17.27 KB (p. 48). So the confidential transaction costs roughly **+9 KB over a bare
ring signature**, and we are about **+4 KB over** the bare figure because of two
compressions not yet done (see `STATUS.md`).

## 7. What the plan does not settle

Named rather than guessed:

1. **Reference [25]** — the addition proof with carries. Not available here. Required.
2. **The exact `B'₀` layout.** The paper says it is "an extension of `B₀`" and gives the
   offsets `k`, but not the full matrix; it must be reconstructed from Figure 12.
3. **The auxiliary commitment's message count.** Depends on `m`, `n`, the recommitments,
   `w`, and the garbage commitments; Figure 12 is the authority.
4. **The digit-membership proof for outputs.** The paper says the amount is in
   `{0,1,2,3}^{32}` (p. 52) and that outputs are minted in the protocol (p. 54), but the
   concrete constraint for *new* outputs is in Figure 12.
5. **The fee.** Visible or hidden? The paper's balance equation (p. 54) implies the fee
   enters as a known constant; not stated explicitly.

## 8. What is already built

`radix_testnet/amounts.py` implements step 3 of the order below, in its carry-free form:
a commitment `C = G·a + B·r` over `R_q` that is additively homomorphic, with a balance
check `sum(inputs) = sum(outputs) + fee` that verifies on commitments alone. Nine tests,
including one that asserts the gap it leaves open.

**What it is not.** Two limits, both tested:

1. Amounts must be below `q` (about `2^32`), because the amount is one coefficient. The
   paper's base-4 digits cover 64 bits precisely because they avoid that ceiling — and
   they are also why it needs a carry proof.
2. **No range proof**, so a negative amount is representable and indistinguishable. Until
   the digit-membership proof exists, this makes balance checkable and does not make
   value safe.

## 9. Implementation order, if this is pursued

1. **Obtain [25].** Nothing about balance can be built or verified without it.
2. **Transcribe Figure 12** into a statement specification, with the matrix layouts
   written out. No code.
3. **Digit encoding and commitment** — `ǎ` from an integer, `t = B₀r ‖ ⟨b₁,r⟩ + ǎ`, with
   tests that two different amounts give different coins and the same amount with
   different `r` gives different coins.
4. **Digit membership** — reuse the `α`-slot machinery to prove each digit ∈ {0,1,2,3}.
   This is the piece most likely to fit this codebase well.
5. **Balance**, once [25] is in hand.
6. **Measure** against the paper's 26.49 KB.

## Related

- [`../REVIEW-REQUEST.md`](../REVIEW-REQUEST.md) — the open questions this raises
- `vault/Amount Confidentiality.md` — why Bulletproofs are the wrong answer here
- `docs/CONSENSUS.md` §1 — the chain-growth arithmetic the sizes feed
- `../STATUS.md` — where this sits in the order of work
