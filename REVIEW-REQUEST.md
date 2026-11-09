# Review request: sixth pass

For C1 and C2. Three questions are now blocking, and for the first time they are
blocking a *build*, not a claim: the chain has proof of work, rewards and a two-node
network, and the owner wants amounts hidden **from launch**.

The full history of what was asked and answered is in `REVIEW-FINDINGS.md`. This page is
only what is open.

## Where the project is

- Set-membership proof (SMILE Figs. 7–9) implemented twice, cross-verified both ways,
  **21,760-byte** proofs (down from 32,512 after bounding and packing the responses).
- Real proof of work: per-block target, LWMA-90, 2× clamps, MTP-11.
- Block rewards: 20 units decaying to a 0.6-unit tail, 10% treasury, 100-block maturity.
- Two nodes agree: linear sync, fork reconciliation by work, deterministic ties.
- Android app, wallet with a BIP-39 phrase, deploy kit.

No security claim. No value.

---

## Q-K. Reference [25] — blocking half of hidden amounts

SMILE §E.1 (p. 54) says balance in the confidential-transaction construction is proven
with "the addition proof from [25]", that the technique extends from binary to base-4, and
that the difficulty is the **carry vector**: with many integers it is no longer binary and
"can not be proven to be small with algebraic techniques", resolved with "an approximate
shortness proof" said to have negligible cost.

**Asks:**

1. **What is [25]?** The exact citation. This single document is the difference between
   "hidden amounts are specified" and "hidden amounts are a sketch".
2. Does the approximate-shortness argument for a non-binary carry need its own rejection
   sampling, and if so what is rejected?
3. Is the carry proof compatible with the same `B′₀` we already use, or does it need a
   second commitment matrix?

`docs/CONFIDENTIAL-TRANSACTIONS.md` §5 and §7 record exactly where this stops.

## Q-L. One-time addressing — blocking *launch*, in two places

This was "the other research risk". It is now on the critical path twice over.

The problem: the tag is `T = A'·s`, a function of the secret, so **one keypair is
spendable exactly once**. A wallet needs a fresh key per output. The natural lattice
construction — publish `P_spend = A·s_spend` and `P_view = A·s_view`, let the sender pick a
scalar `r` and set `pk_out = P_spend + H(r)·P_view` — works algebraically and the sender
cannot spend it, but it **fails on the norm**: keeping `s_out = s_spend + H(r)·s_view`
inside `‖·‖∞ ≤ μ = 5` forces `H(r)` to be a small, guessable scalar, which collapses the
privacy.

**Ask:** is there a published lattice stealth-address construction without a
Diffie–Hellman-like operation?

If the answer is "no, and the norm bound is the obstruction", the follow-up is the one
that would actually help: **can the proof be made to tolerate a large shift in `s_out`**,
for example by proving shortness of `s_spend` and `s_view` separately and carrying the
shift as a public scalar? That would repair the natural construction, and it is the only
route I can see to an ordinary address format.

Two places it now bites:

- **Wallets** hold a handful of notes, not thousands (`vault/One-Time Addressing.md`).
- **Block rewards cannot accumulate.** Output identity is the hash of `(key, value)`, so
  two rewards to one key with the same value are one output — and the tag makes that key
  spendable once anyway. A miner reusing one key earns one reward, not *n*. There is a
  test asserting this (`tests/test_testnet_rewards.py`).

## Q-M. Is set membership the right primitive for digit ranges?

The paper encodes an amount as 32 base-4 digits in `{0,1,2,3}` (p. 52), so an in-range
output is one whose every digit is in a four-element set. This codebase already proves
"one of these 1024 keys" — the `α`-slot construction.

**Ask:** does the extraction argument survive when the set is the four *field elements*
`{0,1,2,3}` rather than a ring of public keys? Specifically:

1. The extraction produces a one-hot selector over the ring. Does a four-element set give
   the same `v_i ∈ {0,1}` conclusion, or does the argument need the set to have a
   particular size or algebraic structure?
2. The digit proof must be **per coefficient position** (32 of them), not per key. Is that
   a different statement type, or the same tensor decomposition applied differently?
3. Does the `q^{-d/l}` uniformity step (C2's Q-B edit) behave the same way at set size 4?

This is the piece I believe is buildable without [25], so knowing early whether it is
sound changes what gets written next.

---

## Still open from earlier passes

| Item | Ask | Status |
|---|---|---|
| **Estimator run** | `docs/ESTIMATOR.md` has the commands; needs SageMath on Linux. Or confirm the delta-model figures (2^158 / 2^175) are close enough to rely on | open |
| **Theorem B.1 restatement** | C2's four edits accepted — would you sign the restatement? | open |
| **`k′` = 1 or 4** | C2 says 1 is sufficient (2^213 collision margin); C1 recommended 4. The implementation defaults to 4 | open |
| **Errata** | Both confirmed the `e₁` double count and the eq. (24) index by derivation. A later ePrint revision would let the record say "erratum" | open |

## What would change the plan

- **[25] says the carry proof is impractical at these parameters** → hidden amounts need
  a different design, and we would rather know now.
- **One-time addressing has a known solution** → the wallet and reward limitations both
  disappear, and the launch path shortens by months.
- **Digit membership does not transfer from key sets** → the range proof needs a
  different primitive, and the timeline changes.

## Reproducing

```powershell
python -m pytest -q -m "not slow"   # 490 passed, 1 xfailed
cd proof_rust && cargo test         # 74 passed
python experiments/estimate_sis.py --check
```
