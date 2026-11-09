---
title: Reproducing Everything
tags: [lecturers, evidence, howto]
---

# Reproducing everything

Exact commands, expected results, and what each one proves. From a fresh clone with
Python 3.12+ and a Rust toolchain.

## 1. The fast test suite (about 75 s)

```powershell
python -m pytest -q -m "not slow"
```

Expected: **411 passed, 1 xfailed, 40 deselected**. The `xfail` is deliberate — it
asserts that the *withdrawn* tag construction can be forged.

If this fails, nothing else is meaningful. Start here.

## 2. The real-crypto suite (several minutes)

```powershell
python -m pytest -q tests/test_testnet_end_to_end.py
```

Expected: **7 passed**, about 5–6 minutes. This builds a real 1024-member ring
signature and pushes it through the node.

## 3. The Rust suite (seconds)

```powershell
& .\scripts\rust.ps1 test -Directory proof_rust
```

Expected: **69 passing** across the library and two integration tests.
On macOS/Linux: `cd proof_rust && cargo test`.

## 4. The cross-language checks

**Python proof → Rust verifier** (already in the Rust suite, listed here because it is
the important one):

```powershell
cd proof_rust
cargo test --test python_proof
```

Expected: `1 passed`.

**Rust proof → Python verifier:**

```powershell
python experiments\verify_rust_proof.py
```

Expected:

```
rust_proof.bin: 32512 proof bytes, python verifier says True
  with a different message: False
```

Both lines matter. The second says the proof is *bound to the message*, not merely
accepted.

## 5. The measurements

```powershell
cd proof_rust
cargo run --release --bin bench_proof
```

Expected on the machine used for `PERFORMANCE.md`: about **496 ms** prove, **110 ms**
verify, 9.75 attempts.

```powershell
python experiments\mask_calibration.py
python experiments\slot_constancy_probe.py
```

The first reproduces the mask widths and the rejection curve; the second prints the
modulus classification table (marginal / irreducible / split) and shows why
`q = 4,294,966,337` was chosen.

## 6. The app

```powershell
python -m radix_testnet                    # opens the wallet in a browser
python -m radix_testnet --no-browser       # headless
```

Or the packaged binary: `.\dist\RadixTestnet.exe`.

Note the first `Send` takes **1–2 minutes** on the Python backend. For the fast path,
see [[Performance Measurements]] and select the Rust backend.

## 7. Building the Rust prover for the testnet

```powershell
cd proof_rust
cargo build --release --bin prove_request
cd ..
python -m pytest -q tests/test_testnet_rust_backend.py
```

Expected: **3 passed** (about 80 s), including a tagged spend proved in Rust and
verified by Python.

## What each command is evidence *of*

| Command | Evidence of |
|---|---|
| 1 | The codebase is internally consistent and reviewed defects stay fixed |
| 2 | Real cryptography runs end to end through a node |
| 3 | The port's layers match the reference layer by layer |
| 4 | **The two implementations agree on actual proofs** |
| 5 | The performance numbers are reproducible, not quoted |
| 6 | There is a working application, not only a library |
| 7 | The seam is real: the fast backend serves the app |

## Things that will not reproduce identically

- **Proof bytes differ between Python and Rust.** The two use different random number
  generators, so masks differ. Proofs are checked mathematically, not compared.
- **Timings depend on the machine.** The recorded figures are from one specific
  laptop; treat them as an order of magnitude, not a benchmark.
- **The chain state in the app persists** in `%LOCALAPPDATA%\RadixTestnet` (Windows) or
  `~/.local/share/RadixTestnet`. Delete the folder for a fresh chain.
