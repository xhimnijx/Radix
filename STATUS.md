# Status — 2026-11-09

**One line:** the proof is finished, verified in two languages, and priced at about
**2^157** by a delta-model check that both reviewers agree is above 128 bits. What is
missing is no longer the cryptography of a single spend — it is the transaction model
(amounts are visible), one-time addressing, and a network that has more than one node.

> Research prototype. No audit, no security claim, no value, not a currency.

## What changed since 2026-11-08

The previous status said "no complete transaction proof exists". That is no longer true.

| Item | Then | Now |
|---|---|---|
| **Security pricing** | `2^50`, unpriced | **~`2^157` (A) and ~`2^174` (B₀)** by the delta model; both reviewers concur it clears 128. A real estimator run is still outstanding |
| **Rust port** | arithmetic layer only | **complete**, 70 tests, and it accepts Python proofs while Python accepts Rust proofs |
| **Prover cost** | projected | **measured**: 475 ms to prove, 105.8 ms to verify, 9.75 attempts, 32,512 B untagged |
| **Node verification** | 20–40 s (Python) | **0.44 s** through Rust — 91× on the tagged spend, the path a node actually uses |
| **Batch verification** | assumed to help | **measured**: it cannot; proofs share nothing but the statement. Parallelism gives **4.22× on 8 cores** |
| **Wallet** | hardcoded seed constant | **BIP-39 phrase**, versioned derivation, refuses a corrupt or missing phrase |
| **Tag** | forgeable; withdrawn | same-witness `A_ext`, and the broken path is now **unreachable** |
| **Android app** | none | native APK, 24 KB, on the releases page |
| **Stagenet** | localhost only | systemd unit, install script, `DEPLOY.md` |

## The security position, stated precisely

A delta-model sanity check of the two M-SIS instances:

| relation | n | target | Core-SVP |
|---|---|---|---|
| `A`, untagged, k = 4 | 1664 | `2^17.56` | **`2^157`** |
| `B₀`, W = 33 | 4224 | `2^27.90` | **`2^174`** |
| `A_ext`, tagged, k + k′ = 8 | 1664 | `2^17.56` | beyond the model (stronger) |

Two things this does **not** mean, both recorded in `SECURITY-NOTES.md`:

1. **It is the cost of the assumption, not the scheme.** The extractor is a
   four-transcript rewinding argument with polynomial loss.
2. **It is not an estimator run.** And at `ord_256(q) = 4` the published module-LWE
   hardness proofs, stated for `q ≡ 1 mod 2n`, do not apply — we hold a conjecture where
   a split modulus would have held a theorem.

Earlier in the project I made a dimension error that would have produced `2^152` for
`B₀`: I used `23·d`, where 23 is the commitment arity, instead of `W·d = 33·d`. That is
the same class of mistake as the arity defect the Rust port found, and it is recorded in
`REVIEW-FINDINGS.md` rather than quietly corrected.

## What is implemented and tested

- **Set-membership proof** (SMILE Figs. 7–9) over `R_q = Z_q[X]/(X^128+1)` with
  `q = 4,294,966,337`, `ord_256(q) = 4`, 32 irreducible quartic slots.
- **Gaussian masks** with `Rej1` and the ℓ₂ verifier bound; calibrated, not guessed,
  and drawn from a **discrete** Gaussian whose table both implementations share.
- **Same-witness tag**: `T = A'·s` proved inside the main relation.
- **Rust prover and verifier**: every layer with a known-answer value from Python;
  cross-language acceptance in both directions.
- **Parallel verification**: `verify_many`, 4.22× on 8 cores.
- **Wallet**: BIP-39 phrase (official test vectors pass), versioned derivation tag,
  a fingerprint rather than the phrase over HTTP, and two refusals that protect the user
  — a corrupt phrase file and a missing phrase beside an existing chain both stop the
  node.
- **Testnet**: node, miner, wallet UI, CLI, Rust backend, Android app, systemd deployment.
- **Tests**: 436 passing plus 1 xfail on the fast path; 70 Rust.

One known flake: `tests/test_nonce_multiprocess.py` fails roughly once per full run under
concurrency and passes 6/6 in isolation. It is Candidate-A legacy, unrelated to the
lattice work, and it is recorded rather than hidden.

## What is honestly not done

| Gap | Why it matters | Who unblocks it |
|---|---|---|
| **Amounts are visible and unproven** | The largest functional gap between this and a privacy currency | Design + range proofs, needs a cryptographer |
| **No one-time addressing** | One keypair is spendable once, so a wallet has four notes, not four thousand. `vault/One-Time Addressing.md` explains why the obvious construction fails on the norm bound | Research |
| ~~Discrete Gaussian not implemented~~ | **Closed 2026-11-09.** A table-driven discrete Gaussian, one binary file that Python reads and Rust `include_bytes!`s, so the two cannot sample different distributions. Truncation tail 2^-49.5 | done |
| **Ring not bound to the pool** | Sound today only because prover and verifier are one process | Cheap fix, changing the transcript in both languages |
| **No peer-to-peer layer** | Two nodes are two universes; the "stagenet" is one server with clients | Months of work |
| **No consensus** | Single miner, no difficulty adjustment, no fork choice | Months |
| **No audit** | Nothing here has been reviewed as a system | Money + time |
| **No estimator run** | `2^157` is a heuristic, not a number from `lattice-estimator` | C1/C2 |

## The launch gate

`radix_core/launch.py` ships **closed** and is checked by `tests/test_launch_gate.py`.
It refuses to advance until the items above are satisfied — it is a checklist with
teeth, not a banner. There is deliberately no flag that opens it.

## Review history

| Round | Found | Outcome |
|---|---|---|
| 1 | tag forgeable; parameters unpriced | tag withdrawn and rebuilt; masks recalibrated |
| 2 | modulus unsuitable | migrated to `q = 4,294,966,337` |
| 3 | residue questions | answered; brief rewritten |
| 4 | **inputs mixed dimension conventions; the spend layer still used the withdrawn tag** | dimensions corrected; the path removed and gated |
| 5 (open) | — | ring-pool binding, discrete Gaussian, `k′ = 1` vs 4, where the 110 ms goes |

## Pointers

- `README.md` — landing page
- `PERFORMANCE.md` — every measured number
- `REVIEW-FINDINGS.md` — the full record, including retracted claims
- `REVIEW-REQUEST.md` — what is being asked now
- `SECURITY-NOTES.md` — what the numbers do and do not mean
- `DEPLOY.md` — running a stagenet node
- `vault/` — 40 notes, from A-Level maths upward
