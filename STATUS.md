# Status â€” 2026-11-09

**One line:** the proof is finished, verified in two languages, and priced at about
**2^158** by a delta-model check that both reviewers agree is above 128 bits. What is
missing is no longer the cryptography of a single spend â€” it is the transaction model
(amounts are visible), one-time addressing, and a network that has more than one node.

> Research prototype. No audit, no security claim, no value, not a currency.

## What changed since 2026-11-08

The previous status said "no complete transaction proof exists". That is no longer true.

| Item | Then | Now |
|---|---|---|
| **Security pricing** | `2^50`, unpriced | **~`2^158` (A) and ~`2^175` (Bâ‚€)** by the delta model; both reviewers concur it clears 128. A real estimator run is still outstanding |
| **Rust port** | arithmetic layer only | **complete**, 70 tests, and it accepts Python proofs while Python accepts Rust proofs |
| **Prover cost** | projected | **measured**: 475 ms to prove, 105.8 ms to verify, 9.75 attempts, **21,760 B untagged** after compressing both responses |
| **Node verification** | 20â€“40 s (Python) | **0.44 s** through Rust â€” 91Ã— on the tagged spend, the path a node actually uses |
| **Batch verification** | assumed to help | **measured**: it cannot; proofs share nothing but the statement. Parallelism gives **4.22Ã— on 8 cores** |
| **Wallet** | hardcoded seed constant | **BIP-39 phrase**, versioned derivation, refuses a corrupt or missing phrase |
| **Tag** | forgeable; withdrawn | same-witness `A_ext`, and the broken path is now **unreachable** |
| **Android app** | none | native APK, 24 KB, on the releases page |
| **Stagenet** | localhost only | systemd unit, install script, `DEPLOY.md` |

## The security position, stated precisely

A delta-model sanity check of the two M-SIS instances:

| relation | n | target | Core-SVP |
|---|---|---|---|
| `A`, untagged, k = 4 | 1664 | `2^17.56` | **`2^158`** |
| `Bâ‚€`, W = 33 | 4224 | `2^27.90` | **`2^175`** |
| `A_ext`, tagged, k + kâ€² = 8 | 1664 | `2^17.56` | beyond the model (stronger) |

Two things this does **not** mean, both recorded in `SECURITY-NOTES.md`:

1. **It is the cost of the assumption, not the scheme.** The extractor is a
   four-transcript rewinding argument with polynomial loss.
2. **It is not an estimator run.** And at `ord_256(q) = 4` the published module-LWE
   hardness proofs, stated for `q â‰¡ 1 mod 2n`, do not apply â€” we hold a conjecture where
   a split modulus would have held a theorem.

Earlier in the project I made a dimension error that would have produced `2^152` for
`Bâ‚€`: I used `23Â·d`, where 23 is the commitment arity, instead of `WÂ·d = 33Â·d`. That is
the same class of mistake as the arity defect the Rust port found, and it is recorded in
`REVIEW-FINDINGS.md` rather than quietly corrected.

## What is implemented and tested

- **Set-membership proof** (SMILE Figs. 7â€“9) over `R_q = Z_q[X]/(X^128+1)` with
  `q = 4,294,966,337`, `ord_256(q) = 4`, 32 irreducible quartic slots.
- **Gaussian masks** with `Rej1` and the â„“â‚‚ verifier bound; calibrated, not guessed,
  and drawn from a **discrete** Gaussian whose table both implementations share.
- **Same-witness tag**: `T = A'Â·s` proved inside the main relation.
- **Rust prover and verifier**: every layer with a known-answer value from Python;
  cross-language acceptance in both directions.
- **Parallel verification**: `verify_many`, 4.22Ã— on 8 cores.
- **Wallet**: BIP-39 phrase (official test vectors pass), versioned derivation tag,
  a fingerprint rather than the phrase over HTTP, and two refusals that protect the user
  â€” a corrupt phrase file and a missing phrase beside an existing chain both stop the
  node.
- **Testnet**: node, miner, wallet UI, CLI, Rust backend, Android app, systemd deployment.
- **Tests**: 436 passing plus 1 xfail on the fast path; 70 Rust.

One known flake: `tests/test_nonce_multiprocess.py` fails roughly once per full run under
concurrency and passes 6/6 in isolation. It is Candidate-A legacy, unrelated to the
lattice work, and it is recorded rather than hidden.

## What is honestly not done

| Gap | Why it matters | Who unblocks it |
|---|---|---|
| **Amounts are visible and unproven** | A foundation now exists: `radix_testnet/amounts.py` commits to a value additively homomorphically over `R_q`, so `sum(inputs) = sum(outputs) + fee` is checkable without revealing any amount (9 tests). **It is not safe for value yet** — with no range proof, a commitment to `q-5` is indistinguishable from `-5` and a sender can mint money. That gap is asserted by a test rather than left in a comment. | The largest functional gap. `docs/CONFIDENTIAL-TRANSACTIONS.md` now specifies the paper's construction with page citations, and names the one document we do not have: reference [25], the addition proof with carries, without which balance cannot be built or verified. | `vault/Amount Confidentiality.md` surveys the options and says why **Bulletproofs are the wrong answer here** â€” they are curve/DLP-based and would silently make the whole protocol quantum-vulnerable | Design + range proofs, needs a cryptographer |
| **No one-time addressing** | One keypair is spendable once, so a wallet has four notes, not four thousand. `vault/One-Time Addressing.md` explains why the obvious construction fails on the norm bound | Research |
| ~~Discrete Gaussian not implemented~~ | **Closed 2026-11-09.** A table-driven discrete Gaussian, one binary file that Python reads and Rust `include_bytes!`s, so the two cannot sample different distributions. Truncation tail 2^-49.5 | done |
| **Ring not bound to the pool** | Sound today only because prover and verifier are one process | Cheap fix, changing the transcript in both languages |
| **No peer-to-peer layer** | ~~Two nodes are two universes~~ **A minimal layer exists** (`p2p.py`): hello, whole-chain sync, block push, 8 tests over real sockets. Fork reconciliation works: a diverged chain is replaced by replaying the winner from genesis, and ties break on the lower tip hash (11 tests). Still missing: discovery, gossip, authentication, checkpoints | Progress, not done |
| **No consensus** | Single miner, no difficulty adjustment, no fork choice | Months |
| **No audit** | Nothing here has been reviewed as a system | Money + time |
| **No estimator run** | `2^158` is a heuristic, not a number from `lattice-estimator`. **The blocker is mechanical, not intellectual**: the tool needs SageMath, and Sage does not run on Windows. `docs/ESTIMATOR.md` records the exact failures and the five-minute run on any Linux box | anyone with a Linux machine |

## The launch gate

`radix_core/launch.py` ships **closed** and is checked by `tests/test_launch_gate.py`.
It refuses to advance until the items above are satisfied â€” it is a checklist with
teeth, not a banner. There is deliberately no flag that opens it.

## Review history

| Round | Found | Outcome |
|---|---|---|
| 1 | tag forgeable; parameters unpriced | tag withdrawn and rebuilt; masks recalibrated |
| 2 | modulus unsuitable | migrated to `q = 4,294,966,337` |
| 3 | residue questions | answered; brief rewritten |
| 4 | **inputs mixed dimension conventions; the spend layer still used the withdrawn tag** | dimensions corrected; the path removed and gated |
| 5 (open) | â€” | ring-pool binding, discrete Gaussian, `kâ€² = 1` vs 4, where the 110 ms goes |

## Pointers

- `README.md` â€” landing page
- `PERFORMANCE.md` â€” every measured number
- `REVIEW-FINDINGS.md` â€” the full record, including retracted claims
- `REVIEW-REQUEST.md` â€” what is being asked now
- `SECURITY-NOTES.md` â€” what the numbers do and do not mean
- `DEPLOY.md` â€” running a stagenet node
- `vault/` â€” 40 notes, from A-Level maths upward

## Plan revision, 2026-11-09 (after the third work item)

Three items closed since the last status: the discrete Gaussian, the amount
confidentiality note, and the consensus specification.

**What the numbers said.**

- **The discrete sampler changed nothing about the parameters.** Calibration reproduces
  `T = 1700`, `s = 2665.5`, `beta = 244,992`, `T' = 1072`, `s' = 1673`, `beta' = 96,512`
  exactly, because it measures response norms at a fixed width and the sampler changes
  the shape of the mask, not its standard deviation. The tables add 207 KB of data and
  remove a portability defect.
- **Chain growth now binds the design.** At 38,656 bytes per tagged spend, ten
  transactions per 120-second block is 102 GB per year. That is the constraint that
  makes block time a latency decision rather than a throughput decision, and it is why
  the consensus spec refuses to trade block time for capacity.
- **Amounts are the next size pressure, not the next feature.** A range proof adds bytes
  to every transaction, and every byte is multiplied by the chain-growth arithmetic
  above.

**What was deliberately not done.**

- No range-proof implementation. The note says why: Bulletproofs are curve-based and
  would make the protocol quantum-vulnerable, and the post-quantum alternatives are not
  yet compared on SIZE, which is the binding constraint.
- No consensus code. Without peers, propagation latency and orphan rate cannot be
  measured, so Â§7 of the spec lists what is blocked rather than inventing parameters.

**What is next, in order.**

1. Read MatRiCT+ and extract its range-proof sizes. This is a reading task, not a coding
   one, and it decides whether amounts are feasible at all.
2. The estimator run (with C1 and C2). Everything else is downstream of it.
3. A peer-to-peer layer, without which Â§7 of `docs/CONSENSUS.md` stays empty and the
   difficulty parameters stay untested.

**What was not re-run, and why.** The Python and Rust suites last passed at 439 + 1 xfail
and 70 with the sampler change applied, and no code has changed since â€” only
documentation. Re-running them would produce the same result and is not evidence of
anything.

CI is green on `main`.

## Plan revision, 2026-11-09 (after the peer-to-peer layer)

Three items closed: the estimator was attempted, the amount question was answered from
the paper, and two nodes can now agree.

**What the work found.**

- **The estimator's blocker is mechanical.** `lattice-estimator` needs SageMath, Sage
  does not run on Windows, `fpylll` will not build without a C++ toolchain, and WSL is
  not installed. `docs/ESTIMATOR.md` has the commands and errors. **The oldest open item
  in the project is now a five-minute job for anyone with a Linux machine.**
- **Writing the fallback corrected my own arithmetic twice.** Relation `A` extracts
  against `2*beta'`, not `2*beta`; mixing them gave `2^125.9` instead of `2^158`. And
  the published figures were **truncated, not rounded** (`0.292*541 = 157.97`, printed
  as `2^157` by `%d`). Both reviewers had written `2^158` and `2^175`; they were right.
  Five documents corrected, and the check now fails if it drifts.
- **Amounts are affordable; our implementation is not efficient.** The paper's own
  confidential-transaction size is **26.49 KB** for 2 inputs and 2 outputs at ring
  1024 â€” smaller than our 31.75 KB for one input with visible amounts. The gap is
  compression, and page 55 names it: compressed public keys, Baiâ€“Galbraith, and entropy
  coding of `z`.
- **Two more defects found by making two nodes agree**, neither visible from reading:
  genesis was timestamped `int(time.time())`, so **no two nodes could ever share a
  chain**; and the genesis allocation is not in the genesis block, so a replica cannot
  reconstruct state from blocks alone.

**What is next, in order.**

1. **Compression.** Entropy-coded `z`, compressed keys, Baiâ€“Galbraith. Target: 31.75 KB
   to the paper's ~17 KB ring signature, then the 26.49 KB confidential transaction. This
   is the highest-value change available and it does not touch soundness.
2. **Fork reconciliation.** The chain has no undo journal, so a fork is refused rather
   than resolved. Until that exists, the p2p layer is a linear sync, not a network.
3. **Test architecture.** ~~Ten proof tests account for 285 of the 326 seconds.~~ **That was wrong**, and measuring it properly was the useful part: two tests in one file were 214 of the 320 seconds, because each built its own spend. Sharing one spend cut the fast suite to 227 seconds with no test removed. The remaining work is the default backend, not the tests.

**Not re-run, and why.** The Rust suite last passed at 70 and no Rust file changed since.
CI was re-checked because it runs on push.

## Plan revision, 2026-11-09 (round 3)

All three items are closed. What they actually produced:

| Item | Outcome |
|---|---|
| Compression | 32,512 -> **21,760 B** (-33.1%), both implementations, cross-language verified. Against the paper's 17.27 KB the remaining gap is ~4 KB |
| Fork reconciliation | by cumulative work, deterministic tie on the lower tip hash, reconciliation by replay from genesis. 11 p2p tests |
| Test architecture | fast suite **320 s -> 227 s** with no test removed; `--backend rust` is now the default in both entry points |

**Three claims of mine were wrong, and each was caught by measuring rather than
arguing.**

1. *"Ten proof tests are 285 of the 326 seconds."* That was a single file timed in
   isolation. The real answer was two tests at 117 s and 97 s, each building its own
   spend; sharing one took the suite to 227 s.
2. *The genesis hash identified the chain.* It did not: `Block.header()` covers the
   transaction **count**, not the allocation, so two networks with completely different
   initial ownership had the same genesis hash. Fixed by committing to the allocation in
   the genesis anchor.
3. *"Fork tests create forks."* The first version did not: both nodes mined the same
   deterministic timestamp and produced identical blocks.

**What is deliberately not done.** Compression steps 3 and 4 -- compressed public keys
(`t0` rounded modulo `2^D`) and Bai-Galbraith -- are protocol changes needing their own
soundness argument, not codec changes. They are the next ~4 KB and the next risk.

**The next three.**

1. **Compressed public keys and Bai-Galbraith**, one at a time, each measured, each with
   a written argument for why soundness is unchanged. Target the paper's 17.27 KB.
2. **The estimator run**, on any Linux machine with SageMath. `docs/ESTIMATOR.md`.
   Nothing else in the project is blocked on anything so cheap.
3. **Amount confidentiality**, now that the paper says a full 2-in/2-out confidential
   transaction is 26.49 KB -- smaller than our visible-amount proof was before
   compression, and comparable to what it is now.

## Plan revision, 2026-11-09 (confidential transactions, round 2)

Three items closed. What they produced, and what they cost.

**Item 1, the construction.** `docs/CONFIDENTIAL-TRANSACTIONS.md` specifies the paper's
confidential transaction with a page citation on every claim. The finding that changes the
plan: **the range constraint is a digit-membership proof, not a bit decomposition.** The
amount is 32 base-4 digits in `{0,1,2,3}` (p. 52), so proving an output is in range is
proving each digit is one of four values — the same shape as the `α`-slot set membership
this codebase already has.

**Item 2, value commitments.** `radix_testnet/amounts.py` commits to a value
additively homomorphically over `R_q`; balance is one vector equation; 9 tests. It is
**not safe for value**: with no range proof, `q-5` is indistinguishable from `-5`, and a
test asserts exactly that.

**Item 3, compressed public keys — stopped, with evidence.** The paper compresses `t'₀`,
the MLWE error and `w` together (p. 55), and requires a second rejection step. In this
code the verifier **absorbs the exact commitment into the transcript** before drawing
`c'`, and **multiplies it by the challenge** in the equation. Rounding either changes what
is proved. `docs/COMPRESSION.md` records the byte accounting (the commitment is 45% of
the proof), the five things that would have to be specified first, and the decision not
to force it.

**One process note.** The BOM guard caught `STATUS.md` after I appended to it with
PowerShell — the second time that one-line test has caught a real regression, and both
times the tool that wrote the file was mine rather than a contributor's.

**The next three.**

1. **Reference [25].** The addition proof with carries. Without it, balance cannot be
   built to the paper's specification; the current `amounts.py` is carry-free and
   therefore capped at `2^32`. This is a document to obtain, not code to write.
2. **Digit membership.** Prove each committed digit lies in `{0,1,2,3}` using the
   `α`-slot machinery, which is the one part of the construction that visibly fits this
   codebase. It does not need [25] and it is what makes committed value non-negative.
3. **The estimator run**, still. `docs/ESTIMATOR.md`; five minutes on any Linux box.


## Plan revision, 2026-11-09 (mainnet items 1-3)

| Item | Outcome |
|---|---|
| Real proof of work | Target in the header, LWMA-90 with 2x clamps, MTP-11 and a two-hour future limit. Difficulty holds at 2^50 with 120 s spacing and tightens 2^50 -> 2^46 in five 10-second blocks |
| Block rewards | Linear decay from 20 units to a 0.6-unit tail over 525,600 blocks, 10% treasury recorded per height, coinbase named in the header, 100-block maturity enforced by keeping immature keys out of the ring pool |
| Checkpoints | Snapshot and restore without replaying history. **1.1x at 200 empty blocks**, break-even about 73 transactions skipped |

**Four things measurement caught that reading would not.**

1. **The LWMA ratio was inverted.** Fast blocks multiplied the target, making a rush of
   blocks make the chain easier. The printout said "target 2^53 ... harder", contradicting
   itself in one line.
2. **The LWMA indices were off by one whenever the window was 1** -- the first adjustment
   on a two-block chain. Every solve time came out negative, clamped to one second, and
   the target tightened by the maximum factor every block: **the chain became unmineable
   within about twenty blocks.** It survived the synthetic tests because they only called
   `next_target` once the window was two or more, where the arithmetic happened to be
   right.
3. **A block reward to a reused key collapses.** Output identity is the hash of
   (key, value), so two rewards to one key with the same value are one output -- and the
   tag makes that key spendable once regardless. A miner reusing one key accumulates one
   reward, not n. **This is one-time addressing reappearing in the reward path**, and it
   moves that item from "later upgrade" to "launch dependency".
4. **Checkpoints are not the order-of-magnitude win I expected.** Restoring costs a fixed
   197 ms, almost all of it regenerating the 1024-key decoy pool, against 2.7 ms per
   transaction replayed. 1.1x on empty blocks. The honest statement is "pays off after
   73 skipped transactions, and the fixed cost is reducible by caching the decoy pool".

**One strategy change, recorded because it contradicts this goal's premise.** The owner
asked for amounts hidden **from launch**, not in a later upgrade. That removes the
Monero-style visible-amounts path and puts the range proof and the carry proof back on
the critical path. `docs/CONFIDENTIAL-TRANSACTIONS.md` is therefore not a later phase.

**The next three.**

1. **Digit membership** -- prove each committed base-4 digit lies in {0,1,2,3} using the
   alpha-slot machinery. Needs no external document and is half of hidden amounts.
2. ~~**Reference [25]**~~ -- **obtained and resolved.** It is the *relaxed* range proof
   (CCS 2020, p. 5): if `Rf + y` is small then `f` was small, so the carry needs one
   masked opening and a norm check, not a bit-decomposition. Measured at our parameters:
   honest carry rejected 0/50, inflated caught 50/50.
3. ~~**One-time addressing**~~ -- **derivation solved, compatibility open.** ePrint 2025/112 section 5.3 derives a stealth key as `P = XOF(rhoK)*XOF(S) + Decompress(tK)` with the secret `p = k + XOF(S)`, where `S` is a KEM shared secret. The sender can compute `P` but not `p`, which fixes the deanonymisation in the earlier proposal. The open question is whether `XOF(S)` is short: if it is uniform, `p` is uniform and SMILE cannot prove knowledge of it as a short vector.
