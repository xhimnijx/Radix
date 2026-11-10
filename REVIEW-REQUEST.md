# Review request: ninth pass

For C1 and C2. One question this time, and it is blocking: the range constraint is now inside
the proof in both languages, and the **balance relation cannot be stated over it** — not
because the mechanism is missing, but because the two need different subspaces.

Full history: `REVIEW-FINDINGS.md`. This page is only what is open.

## What your eighth-pass answers changed

| Your answer | What happened |
|---|---|
| Bit constraints need **new** α slots, appended after `α_m` | Implemented. A fold would give `α(v²−v+b²−b)=0`, which a prover satisfies with `v²−v = −(b²−b)` |
| The digit and carry relations need **no** α — they are linear | Implemented as `LinearRelation`; the budget is **2 α per amount**, and `constraint_count(4) == 8` |
| Two α per amount, not three | Confirmed; the spare for a two-term binary carry is gone |
| `k' = 1` stands, with B₀ at 2^167 | Confirmed and recorded, including that reducing `k'` cost B₀ 8 bits |
| `[A \| I_k]` does not change the lattice, it changes the problem type | Recorded: it is an ISIS/BDD instance, not SIS, and must be priced accordingly |
| The statement needs `ell = 17` wired, not flagged | Implemented; a 17-column statement proves and verifies |

## Measured

- Range constraint **inside the proof** in Python and Rust: two α per amount, bit polynomials
  committed and never transmitted, a slot holding 2 **refused by the proof**.
- **22,784 bytes** with two range messages against a 21,760-byte baseline — that is **512
  bytes per bit polynomial**. `W` does not move, because a range row is an ordinary BDLOP row
  reusing the same randomness.
- **23,808 bytes** for a carry proof with three bit planes and a carry message.
- Cross-language: `experiments/cross_language_range.py` and `cross_language_carry.py` both
  report AGREE. Rust **refuses a proof whose carry does not match its bits**.
- Last full fast-suite run: **603 passed, 1 known xfail**; Rust **70 passed**. Thirteen tests
  were added since and pass individually but have not been re-run as a whole.

---

## Q-T (blocking). Which encoding should the amounts use?

The carrying identity you gave at `[25]` p. 4 is implemented and tested for two terms:
`a + b + f(X−4) = c` over polynomials, with a test that a perturbation vanishing at `X = 4` is
still rejected. The synthetic division that recovers `f` from the difference works, and
`balance.build` refuses a spend whose amounts do not add up.

**It cannot be lifted to a proof over the bit planes, and the reason is structural.**

The binaryness check requires messages that are **constant in each CRT slot**. That is exactly
what makes `b·b = b` hold, and it is how `digits.pack_bits` builds them: one bit per slot,
lifted through `subring.from_constants`.

The carrying identity requires multiplication by `(X−4)` in the **coefficient** domain, where
evaluating at `X = 4` recovers the integer and `(X−4)` therefore divides the difference.

These are different subspaces. Verified directly:

```
slot-constant 1 in slot 0                          -> slot value (1, 0, 0, 0)
that polynomial multiplied by (X−4)                -> slot value (−4, 1, 0, 0)
```

Multiplying a slot-constant by `(X−4)` **leaves the slot-constant subspace**. So a balance
relation written over the bit planes is not the identity it appears to be — it verifies, and
means nothing. I wrote `balance.relations`, found this, and **removed it rather than ship it**.

### The question

Which encoding does the construction intend for `ǎ`?

**(a) Coefficient-domain amounts**, with the paper's `d ∈ {0,1,2,3}` tested per *coefficient*.
That is a **quartic** membership constraint. The α machinery here expresses only quadratics, so
this needs a different check — what does the paper use, and at what cost?

**(b) Slot-wise carrying**, which avoids `(X−4)` entirely. I could not construct an argument
that concludes the integer identity from a slot-wise sum, and I do not want to invent one.

And the sub-question that decides it: **how does the paper's `ǎ`, whose coefficients are the
digits, relate to a slot-based binaryness check?** If the paper never intends slot-constant
messages, then the range constraint I built is proving binaryness in the wrong subspace and the
whole range layer should be rebuilt over coefficient-domain digits — which I would rather do
deliberately than discover half-way.

### What is already in place either way

The mechanism is not the gap. `LinearRelation` — a linear relation among committed messages,
proven inside the proof — is built, tested, and **cross-verified in both languages**. Your note
said the balance relation "rides on the existing masked opening"; it does, and this is that
primitive. If the answer is (a), it needs a different range check but the same relation
machinery. If the answer is (b), it needs an argument I do not have.

---

## Built and working, not blocked on the above

| | |
|---|---|
| Digits in the proof, two α per amount, both languages | non-binary bit **refused by the proof** |
| Two-input balance (binary carry) | proven and verified |
| `m`-input carry boundedness | by bit decomposition: 5 rows for 16 inputs |
| `LinearRelation` | cross-verified in Python and Rust |
| Noise-aware statement | wired at `ell = 17` |
| One-time addressing | derivation works: short `XOF(S)`, `T_K = A'·k`, 7 tests |
| Network | authenticated transport, two-hop discovery, slow start, checkpointed sync |

## Not asking for

- **The estimator run.** Named models (ADPS16 / MATZOV) and the band are reported; a run would
  tighten it, not change a decision.
- **QROM.** Still an audit-scope item, unchanged.
- **The floating-point accept/reject boundary.** Still open, still a fair item for the launch
  statement.

## Reproducing

```powershell
python -m pytest -q -m "not slow"          # 603 passed, 1 known xfail
cd proof_rust && cargo test                # 70 passed
python experiments/cross_language_range.py # AGREE
python experiments/cross_language_carry.py # AGREE
```
