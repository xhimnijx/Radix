---
title: File and Commit Index
tags: [lecturers, evidence, reference]
---

# File and commit index

Where things are, and the commits that built them. Commit hashes are from this
repository's history; `git log --oneline` shows the full list with messages.

## The cryptographic core

```
radix_core/candidate_b/lattice/
  params.py            manifest
  ring.py              R_q arithmetic, norms, sampling, codec
  ntt.py               the 128-point NTT (split reference modulus only)
  subring.py           slots, quartic multiply, CRT glue
  transcript.py        absorb/squeeze over SHAKE256
  bdlop.py             commitments
  quadratic.py         product form, coefficient extraction
  tensor.py            index vectors
  recursion.py         the Fig. 8 descent
  setmembership.py     prove / verify / keys / statements   <- the protocol
  ring_signature.py    wrapper + the same-witness tag
  spend.py             outputs and spends
  tag.py               WITHDRAWN, do not use
```

## The testnet

```
radix_testnet/
  chain.py             blocks, mempool, outputs, ring pool, tag rejection
  tagged.py            tagged spend builder
  wallet.py            accounts, addresses, sends
  prover.py            the backend seam
  rust_backend.py      subprocess bridge to the Rust prover
  codec.py             proof decoder + spend envelope
  store.py             atomic persistence, config, address book
  log.py               JSONL event log
  node.py              HTTP API + GUI server
  app.py               desktop launcher
  miner.py             mining
  cli.py               command line
  static/index.html    the wallet page
```

## The Rust port

```
proof_rust/
  src/lib.rs           R_q arithmetic, slots, CRT, norms
  src/sha3.rs          Keccak + SHAKE256
  src/transcript.rs    transcript
  src/codec.rs         wire codec (adds a decoder)
  src/sample.rs        the shared cross-language generator
  src/bdlop.rs         commitments
  src/tensor.rs        index vectors
  src/quadratic.rs     coefficient maps
  src/recursion.rs     the descent
  src/statement.rs     keys, statements, challenges
  src/proof.rs         paper_to_slot, set_matrix, final_x, e1
  src/verifier.rs      the verifier (+ verify_traced)
  src/prover.rs        the prover
  src/bin/             bench, bench_proof, emit_proof, prove_request
  tests/python_proof.rs   Python proof accepted by Rust
  tests/round_trip.rs     Rust proves and verifies
  PORTING.md           the layer table and the recorded bugs
```

## Evidence artefacts

```
experiments/
  mask_calibration.py          measures T, s, beta, the rejection curve
  slot_constancy_probe.py      the modulus classification table
  irreducible_modulus_search.py candidate primes with ord_256 = 4
  port_vectors.py              the shared cross-language vectors
  produce_python_proof.py      writes a Python proof fixture
  verify_rust_proof.py         Python verifies a Rust proof
  tag_forgery_repro.py         reproduces the withdrawn tag's forgery
  rust_crosscheck.py           polynomial digest across languages
```

## Documents at the repository root

```
STATUS.md             what is and is not claimed
REVIEW-FINDINGS.md    the review record, with retractions kept visible
REVIEW-REQUEST.md     the brief for a third review
PERFORMANCE.md        measured timings
TESTNET.md            how to run and build the app
ARCHITECTURE-DECISION.md  why this design, and what was rejected
SECURITY-NOTES.md     security-relevant notes
PRIVACY-MODEL.md      what is hidden and what is not
MAINNET-SWITCHOVER.md the gate and what would have to be true to open it
```

## Principal commits

| Hash | What |
|---|---|
| `1946f71` | The Rust prover, and both cross-language directions pass |
| `f55c9da` | The Rust verifier accepts a real Python proof (the arity and sign fixes) |
| `36ffa79` | SHAKE256, transcript and codec |
| `e65e753` | Vector ops, cross-language sampling, BDLOP |
| `7619a72` | Tensor and quadratic |
| `4d80bb5` | The recursion |
| `8df2c73`, `4965d65` | Keys, statements, `paper_to_slot`, `set_matrix` |
| `44a9de6` | Measured performance |
| `38180f4` | The Rust backend seam |
| `f67f141` | Packaging: exe, spec, CI |
| `4cbb834`, `d4a16e8` | Node hardening, config, logging, icon, version |

## How to check the history is real

```powershell
git log --oneline --all | Measure-Object -Line
git log --stat -1 1946f71
```

Each commit message says what was done and, where relevant, what was found by doing it.
