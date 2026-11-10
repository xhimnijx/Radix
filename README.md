# Radix

**A post-quantum, privacy-preserving payment protocol — research prototype.**

> [!WARNING]
> **Not a cryptocurrency. No value. No security claim. Not audited.**
> The mainnet gate in `radix_core/launch.py` is closed by design and no flag or
> environment variable opens it. Nothing here should be deployed or assigned value.

Radix implements [SMILE (ePrint 2021/564)](https://eprint.iacr.org/2021/564), a
lattice-based ring signature with set membership, and builds a complete local testnet
around it: chain, node, miner, wallet, CLI, GUI, packaged desktop app. The prover and
verifier are implemented twice — in Python as a reference and in Rust for speed — and
**each implementation verifies the other's proofs**.

The goal is Monero's privacy properties without elliptic curves, so that a future
quantum computer running Shor's algorithm does not break it.

---

## Try it

**Prebuilt binaries:** <https://github.com/xhimnijx/Radix/releases> — desktop apps
for Windows, macOS and Linux, plus an **Android APK**.

Releases are built by CI on native runners — the Windows `.exe` on Windows, the macOS
binary on macOS, the Linux binary on Linux, because PyInstaller cannot cross-compile.
Download the one for your platform, run it, and your browser opens the wallet.

**From source:**

```powershell
git clone https://github.com/xhimnijx/Radix.git
cd Radix
python -m pip install -e .
python -m radix_testnet          # starts the node and opens the wallet
```

Python 3.12+. The first `Send` takes **1–2 minutes** on the reference backend; see
[the fast backend](#the-fast-backend-rust) to make it ~0.5 s.

## What it does

| | |
|---|---|
| **Private** | A spend proves "I own one of 1024 keys" without revealing which one |
| **Double-spend proof** | A linkable tag `T = A'·s` is a deterministic function of the secret, so a repeat is detectable |
| **Post-quantum** | Security rests on module-SIS / module-LWE, which have no known efficient quantum attack |
| **Fast enough** | 496 ms to prove, 110 ms to verify, 32 KB proofs (Rust, measured) |
| **Runnable** | A desktop app with a wallet UI, or a CLI |

## How it works, in one paragraph

Transactions live in `R_q = Z_q[X]/(X^128+1)` with `q = 4,294,966,337` chosen so that
`X^128+1` factors into 32 **irreducible** quartics — which is what makes the challenge
differences invertible and the extracted index genuinely one-hot. The prover commits to
a one-hot index vector, links it to the ring's public keys through a matrix, and forces
binaryness with a quadratic relation, all masked so nothing leaks. Recursion over the
tensor structure makes a 1024-key ring cost about the same as a 32-key one.

For the full treatment — from A-Level maths upwards — see the **[vault](vault/)**.

## The fast backend (Rust)

```powershell
cd proof_rust
cargo build --release --bin prove_request
cd ..
python -m radix_testnet.cli --backend rust ...
```

| | Python (reference) | Rust |
|---|---|---|
| prove | 1–2 min | **496 ms** |
| verify | 20–38 s | **110 ms** |

If the binary is missing, `--backend rust` refuses rather than silently falling back.

## Verification

The strongest claim in this repository:

> A proof produced by the Rust prover is accepted by the Python verifier, **and** a
> proof produced by the Python prover is accepted by the Rust verifier.

Both directions are tested and the fixtures are committed:

```powershell
python -m pytest -q -m "not slow"                 # 606 passed, 1 xfailed (~11 min)
python -m pytest -q tests/test_testnet_end_to_end.py   # real proofs (~6 min)
cd proof_rust && cargo test                       # 70 passed
python experiments/verify_rust_proof.py           # Rust proof -> Python verifier
```

Every layer of the port has a known-answer value taken from the Python reference
(SHAKE256, transcript, codec, BDLOP, quadratic, tensor, recursion, `set_matrix`, and the
full prover). See [`proof_rust/PORTING.md`](proof_rust/PORTING.md).

## Repository map

| Path | What |
|---|---|
| `vault/` | **The documentation.** 38 notes, A-Level → protocol internals |
| `radix_core/candidate_b/lattice/` | The Python reference implementation |
| `radix_testnet/` | Chain, node, miner, wallet, GUI, packaging |
| `android/` | A native Android wallet app (framework-only, 24 KB APK) |
| `proof_rust/` | The Rust implementation and the porting record |
| `experiments/` | Measurements, cross-checks, the modulus search |
| `archive/` | Two abandoned tracks, kept for honesty |

Root documents:

- [`STATUS.md`](STATUS.md) — dated single source of truth: tests, measurements, what is broken
- [`PERFORMANCE.md`](PERFORMANCE.md) — measured timings, not projections
- [`REVIEW-FINDINGS.md`](REVIEW-FINDINGS.md) — what two independent reviewers found, retractions included
- [`REVIEW-REQUEST.md`](REVIEW-REQUEST.md) — the brief for a third review
- [`docs/CONSENSUS.md`](docs/CONSENSUS.md) — block time, difficulty, reward, fork choice
- [`docs/ESTIMATOR.md`](docs/ESTIMATOR.md) — the outstanding security estimate, and what blocks it
- [`docs/CONFIDENTIAL-TRANSACTIONS.md`](docs/CONFIDENTIAL-TRANSACTIONS.md) — hiding transaction amounts, in detail
- [`docs/COMPRESSION.md`](docs/COMPRESSION.md) — what is left of the 4 KB, and why it stops there
- [`docs/PAPER.md`](docs/PAPER.md) — an implementation-study draft, with the claims and the limitations
- [`docs/ALPHA-SLOTS.md`](docs/ALPHA-SLOTS.md) — the change specification for the range proof
- [`DEPLOY.md`](DEPLOY.md) — running a stagenet node on a second machine
- [`TESTNET.md`](TESTNET.md) — how to run and build the app
- [`PLAIN-ENGLISH.md`](PLAIN-ENGLISH.md) — the same story without jargon

## What this is not

- **Not audited.** Two informal reviews found four real defects; that is not an audit.
- **Not 128-bit secure.** No lattice estimator run has been done, so no security level
  may be claimed. The parameters are priced in `PERFORMANCE.md`, not proven.
- **Not anonymous like Monero.** The range constraint now runs *inside* the proof -- two
  alpha challenges per amount, refused when a bit is not binary, agreed by both
  implementations -- but the amounts a wallet actually spends are still carried in the
  clear, and the ring pool on a fresh chain is mostly deterministic decoys.
- **Not finished.** The relaxed carry bound, wallet integration of the stealth derivation,
  and the audit are outstanding. Consensus, the peer-to-peer network, amount commitments and
  the range proof itself do exist.
- **Verify misses its target.** 106-110 ms measured against a 100 ms bar, and a phone
  multiplier makes it worse. Both ends of that range miss it, so the verdict does not
  depend on which measurement you prefer.

[`vault/Status and Honest Limitations.md`](vault/Status%20and%20Honest%20Limitations.md)
is the honest one-page summary.

## Contributing

Review is more useful than code right now. The open questions are listed in
[`REVIEW-REQUEST.md`](REVIEW-REQUEST.md); the highest-value single task is running a
lattice estimator against the current parameters. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Licence

MIT — see [`LICENSE`](LICENSE). No warranty; not fit for any purpose; do not use it to
store or transfer value.
