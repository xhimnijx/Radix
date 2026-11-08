# Radix — completion plan (G100 side project)

**Owner:** Maxim Gil · **Prepared:** 2026-11-08 · **Companion:** `STATUS.md`, `Radix-Workspace-Review.md`
**North star:** a value-bearing, permissionless, post-quantum private-payment L1.
**Deliverable of this plan:** the furthest *honest* milestone toward that north star, with every claim backed by a reproducible artifact.
**Reframed requirement (2026-11-08):** the code must not carry value now, but it must be **mainnet-switchover-ready** — a single, tested, fail-closed launch gate that a qualified cryptographer's signed review can open, with no code edits scattered across the tree.

---

## 0. The one boundary, stated once

This repository will not carry value, and it will not contain a token, genesis allocation, or anything that invites someone to put money into it. What it *will* do is make the switchover a **one-step operation with a lock**: one parameter file, one signed review manifest, one preflight function that refuses to start in mainnet mode until that manifest matches the exact consensus parameters under review.

That is the honest version of "one click when reviewed":

- **Locked by default.** `NetworkMode.MAINNET` is refused unless a signed `AuditManifest` covering the exact `parameters_hash()` is supplied together with a pinned reviewer key. There is no environment variable, flag, or code path that bypasses it.
- **One switch.** The switch is: add a reviewer public key to the trust set and drop in the signed manifest for the frozen parameter block. No cryptographic constant, cap, or proof profile is edited by hand at launch.
- **Nothing to weaken.** Switching modes may only *tighten* parameters (mainnet requires the production FRI profile, non-empty reviewer set, frozen genesis, and the audited proof profile). Attempting to switch to mainnet with test parameters is a hard error.
- **Reviewable before the switch.** `AUDIT-PACKET.md` lists exactly what a reviewer must see and sign; `MAINNET-SWITCHOVER.md` is the runbook a second operator can follow to verify the switch was done correctly.

If the review never happens, the gate stays locked and the project is a research artifact — which is the correct outcome.


---

## 1. Where the project actually is (2026-11-08)

| Facet | State |
|---|---|
| Version control | none (fixed in M0) |
| Python core | 3.3k LOC, 191/194 tests pass, one remotely exploitable wallet DoS, quadratic replay |
| Rust proof harness | 13.4k LOC, **does not compile**; flagship profile fail-closed by design; provers use a 2-query test config |
| Complete transaction proof | does not exist |
| Recipient privacy | unsolved (P0, acknowledged) |
| Node / network / PoW / wallet recovery | do not exist |
| Docs | excellent, but a dated append-only log that disagrees with the code |

The decisive fact: **the cost model says the current circuit architecture cannot fit its own device budget** (measured 9.5 GiB for the input half of one transfer against a 4 GiB gate). That is what M3 is for.

---

## 2. Milestones

Each milestone has an exit artifact. No milestone is "done" on schedule alone; it is done when the artifact exists and the check passes.

### M0 — Baseline and hygiene *(this week)*
Git repository with a baseline commit, `.gitignore`, `LICENSE` (MIT), pinned toolchain, CI, `STATUS.md`, this plan.
**Exit:** `git log` shows the broken snapshot as a distinct commit; CI file exists; `STATUS.md` is dated and matches reality.

### M1 — Green build and green suite *(this week)*
Fix the half-landed trace-width refactor (an accessor for the split key-schedule bank plus a column-disjointness test), pin the working toolchain, repair the stale static-audit tests, and make `cargo check`, `cargo test --no-run` and `pytest` all pass.
**Exit:** one command each for Python and Rust; both exit 0; the number of ignored tests and the number of skipped checks are recorded in `STATUS.md`.
**Why first:** nothing else is reviewable until HEAD builds. A red baseline also destroys the credibility of every measurement that follows.

### M2 — Close the verified safety defects *(this week)*
1. **Wallet scan poisoning (exploitable):** a crafted, authenticating-but-inconsistent output permanently stops a victim's scan. Contain per-output failures; add hostile-first/hostile-last regression tests.
2. Nonce-registry capacity that permanently breaks note creation.
3. `append_many` materialising an unbounded iterable before its capacity check.
4. Output creation accepting non-canonical ML-KEM viewing keys.
5. Keystore nonce-guard bypass via subclassing.
6. Unbounded `while` loop in the monetary schedule.
**Exit:** each item has a regression test that fails on the old code, plus a `SECURITY-NOTES.md` entry describing impact and fix.

### M2L — Launch gate: mainnet-switchover readiness *(this week)*
Add `radix_core/launch.py`:
- `NetworkMode` (`RESEARCH` / `TESTNET` / `MAINNET`), `LaunchParameters` (frozen, canonical, hashable), `AuditManifest` (signed review over `parameters_hash()`), and `assert_launch_ready(...)`.
- A **locked** mainnet gate: refuses without a manifest signed by a pinned reviewer key; refuses testnet FRI knobs in mainnet mode; refuses an empty reviewer set; refuses a mutated parameter block.
- A single `MAINNET_PARAMETERS` block that is the *only* place a launch changes values, plus `register_reviewer_key()` as the one-touch switch.
**Exit:** tests prove (a) mainnet is refused by default, (b) every parameter mutation invalidates the manifest, (c) mode escalation cannot weaken a control, (d) the switch is one function call plus one manifest. `MAINNET-SWITCHOVER.md` and `AUDIT-PACKET.md` written.

### M3 — The decisive experiment: is the lean relation feasible? *(executed 2026-11-08)*
The core of the project. Two candidate relations, priced:

- **R-fat:** the current composition (input+output KDF, AES-CTR, balance, path) — a
  4.77 GiB payload floor, fail-closed.
- **R-lean:** the same *safety* relation with in-circuit KEM/AEAD removed — a
  1.55 GiB floor, ~11.8 GiB predicted peak.

**Result (see `LEAN-RELATION.md`):** lean alone is necessary but not sufficient
(2.9x over the desktop gate). The binding cost is the 8,192 bit-sliced path
columns, not the crypto banks. Packing the path witness into 16-bit limbs predicts
**2.4 GiB**, which fits the desktop gate and still misses mobile. Decision:
NO-GO for the monolithic AIR as structured; implement R-lean + packed path next,
with a measured <= 4 GiB pass rule.

**Exit artifacts:** `LEAN-RELATION.md`, `MEASUREMENTS.md`,
`experiments/lean_relation_sizing.py`, `experiments/measure_rust_test.ps1`,
`STATUS.md` decision record. **Measured 2026-11-08** on the pre-rebuild harness
(single path proof 2.49 GiB / 17.9 s; composed multi-proof 8.61 GiB / 60.0 s).
**Still required for M3 to *pass*:** a measured single-proof peak for the
*packed-path* build with production FRI parameters. That needs a machine with a
working Rust linker (MSVC Build Tools or MinGW); it cannot run on this host.

### M4 — End-to-end non-value demo *(conditional on M3 passing)*
One 1-in/1-out shielded transfer: CLI wallet → real proof → `apply_block` → verify, on one machine, with a measurement table (prove time, verify time, peak RSS, proof bytes).
**Exit:** a script that reproduces the demo from a clean checkout, and `RADIX-PROOF-SCOPE.md` updated with evidence, not estimates.

### M5 — Non-value testnet skeleton *(out of scope for now; specified only)*
PoW, header chain, mempool, P2P, genesis, seed recovery, block wire format. This is 12–24 months of work for a small team and is **not** part of the G100 deliverable. `TESTNET-SCOPE.md` records what it would require so the plan is explicit rather than aspirational.

### M6 — Mainnet gates *(not a deliverable; checklist only)*
`MAINNET-GATES.md` maps the charter's Gate 0–6 exit criteria to the evidence that would be required, so the gap is visible and auditable. No token, no genesis, no launch.

---

## 3. The decision rule for the whole project

The project has exactly two honest terminal states, and M3 chooses between them:

| M3 outcome | Project status | Next action |
|---|---|---|
| R-lean fits desktop, soundness note survives review | **Conditional GO** to a non-value testnet | M4, then peer review, then M5 scoping |
| R-lean does not fit, or the soundness note fails | **Research NO-GO** for Candidate A as specified | publish the negative result; pick recursion/zkVM/algebraic-hash/lattice-LRS with numbers before writing more code |

There is no third state in which the project "keeps adding components until it works". That is the state it is in now, and it is why the repository is broken and the suite is red.

---

## 4. What is genuinely needed for a value-bearing mainnet (for the record)

1. A complete transaction relation with a written soundness/ZK/QROM argument and **two independent reviews**.
2. A prover that fits a user device, or a privacy-preserving delegation/recurse scheme, plus a proof/block budget that yields usable throughput.
3. A key-private post-quantum recipient-discovery construction (the current one fails the charter's own privacy game).
4. A consensus implementation with reproducible state transitions, an adversary-tested PoW/P2P layer, and cross-implementation vectors.
5. Seed-based wallet recovery, a human address format, and an audited custody path.
6. Legal review for the intended jurisdictions, a published distribution policy, and an incident-response plan.
7. Funding and a team. The roadmap's own estimate is 2–4+ years for a staffed project, with an explicit possibility of never clearing the gates.

Nothing on that list is delivered by a side project, and pretending otherwise is how people lose money. The G100 project's value is in making items 1–2 *decidable* rather than assumed.

---

## 5. Working agreement

- Every claim in a document is marked **measured**, **derived**, or **assumed**. No triangulating.
- The suite and the build are green before any new feature is started; a red HEAD is a stop-the-line event.
- Each milestone lands as one or more reviewable commits with a message that says what changed and why.
- If a test is skipped, the reason is in `STATUS.md`, with a date and a re-enable condition.
- If any part of this is submitted for assessment, follow the university's policy on AI assistance and be able to explain and defend every line. The design decisions are the assessable part; the typing is not.

---

## 6. Immediate sequence (next 10 working days)

| Day | Work | Artifact |
|---|---|---|
| 1 | M0: git, licence, CI, toolchain, `STATUS.md`, this plan | baseline + plan commits |
| 1–2 | M1: Rust accessor + disjointness test; stale tests repaired | green `cargo check`, green `pytest` |
| 3 | M2.1–M2.2: wallet DoS + nonce registry, with regression tests | `SECURITY-NOTES.md` |
| 4 | M2.3–M2.6: remaining safety fixes | green suite |
| 5–9 | M3: soundness note, sizing harness, measured verdict | `LEAN-RELATION.md`, `experiments/` |
| 10 | Decision record + project report | `STATUS.md` + `VERDICT.md` |

That is the plan. Execution starts at M0, and M0–M2 are tractable in this session.
