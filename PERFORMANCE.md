# Performance

What a spend costs, measured where it can be measured and modelled where it cannot.
The distinction matters: the proof has **not** been ported to Rust, so the Rust
numbers below are a validated model, not an end-to-end timing. Everything in the
first two tables is measured.

## Instrumentation

`ring.MUL_COUNT` counts ring multiplications. One proof at depth 2 (ring 1024),
`q = 4,294,966,337`, Gaussian masks with rejection:

| phase | ring multiplications | wall time (CPython) | time per multiplication |
|---|---|---|---|
| prove | 14,450 | 57.7 s | 4.0 ms |
| verify | 4,741 | 20.7 s | 4.4 ms |

The measured cost of one quartic-CRT multiplication in CPython is 3.23 ms. So:

* prove: `14,450 x 3.23 ms = 46.7 s` against 57.7 s actual -- **81%** of the time;
* verify: `4,741 x 3.23 ms = 15.3 s` against 20.7 s actual -- **74%** of the time.

The residual is hashing (SHAKE256), mask sampling and the non-multiplication
reductions. A cost model that explains ~80% of the runtime from one measured
constant is good enough to project with, which is what the third table does.

## The Rust arithmetic, measured

`proof_rust`, release build, same `q` and `d`. Six Rust tests, plus a
cross-language checksum (`experiments/rust_crosscheck.py`) that ties the port to
the Python reference bit for bit.

| implementation | per ring multiplication |
|---|---|
| Python, NTT (only exists at the split modulus) | 1,000 us |
| Python, quartic CRT | 3,233 us |
| **Rust, quartic CRT** | **20.1 us** |
| Rust, naive convolution (reference) | 22.2 us |

Getting to 20.1 us took two measurements: the first version was **71.2 us**, three
times *slower* than the naive convolution, because `mul_mod` did a `u128`
division; Barrett reduction took it to 34.2 us, and accumulating each slot residue
in `u128` with one reduction per residue took it to 20.1 us.

## Measured prove and verify times

The Rust port now runs the real prover and the real verifier, so these are
measurements, not projections. Depth 2 (ring 1024), `q = 4,294,966,337`, release
build, eight proofs:

| | measured |
|---|---|
| proof size | **21,760 bytes** (was 32,512 before compressing both responses) |
| **prove** | **496 ms** |
| **verify** | **110 ms** |
| attempts per proof | 9.75 |

The attempt count is not a defect. There are two rejection points: `z'` early,
before the expensive part, and `z` at the very end. Each accepts with probability at
least `1/(2M^2) = 1/3`, so about nine attempts in total is the expected cost, of
which roughly three reach the set matrix. That is why the mean is 496 ms rather than
150 ms.

### Against the B2 bar

| phase | measured (desktop) | phone, at 3-5x | bar | verdict |
|---|---|---|---|---|
| prove | 496 ms | 1.5-2.5 s | <= 60 s | **passes comfortably** |
| verify | 110 ms | 330-550 ms | <= 100 ms | **fails on a phone** |

Verify is the phase without margin, and this is now a measurement rather than a
warning: 110 ms on the machine that produced it. Any phone multiplier makes it
worse. The earlier projection of 130 ms was pessimistic; 110 ms is still over the
line.

The options, none measured:

1. **Batch verification.** A node verifying many transactions amortises the set
   matrix, which dominates. This is the standard answer and is probably sufficient.
2. **A faster multiplication.** 20.1 us is not close to optimal; Montgomery form or
   fewer passes over the slot table would move everything proportionally.
3. **Smaller ring.** A security parameter, so not free.

### What this replaces

`PERFORMANCE.md` previously projected 0.36 s to prove and 0.13 s to verify from the
dominant work scaled by a per-multiplication cost. The measured figures are 0.50 s
and 0.11 s: the same order, both slightly off, and the sign of the verify error was
not predictable. That is the argument for measuring.

## The node's verification path

A node spends its time verifying, not proving, so routing verification through Rust
matters more than the prover numbers above. Measured on one tagged spend through
`prover.verify_tagged`:

| backend | verification |
|---|---|
| python | 40.3 s |
| **rust** (subprocess per input) | **0.44 s** |

**91x**, and the answers agree — which is the part that matters, not the ratio. The
0.44 s is ~110 ms of verification plus process start and serialisation; the gap will
widen on a machine with less Python overhead to lose.

To use it:

```powershell
cd proof_rust
cargo build --release --bin prove_request --bin verify_request
cd ..
python -m radix_testnet --backend rust
```

If either binary is missing, the backend refuses rather than falling back.

## What this means for the original question

"Will users wait these extortionate times between transactions?" No:

* the 57 s and 21 s figures are CPython with deliberately unoptimised loops;
* the signer's cost is ~0.36 s of *offline* computation before broadcast;
* the verifier's cost is the one that matters, ~0.13 s modelled on desktop, which
  is a throughput question for the network rather than a wait for the user;
* block time will dwarf all of it either way.

The honest caveat: verify is the phase that needs attention, and it will need
either batching or a faster multiplication before the 100 ms bar is credible on a
phone.

## Reproducing

```powershell
python experiments/mask_calibration.py
python experiments/rust_crosscheck.py
& .\scripts\rust.ps1 run --release --bin bench -Directory proof_rust
```
