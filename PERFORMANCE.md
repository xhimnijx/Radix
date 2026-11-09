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

## Projected prove and verify times

Scaling the measured counts by the measured Rust per-multiplication cost, and
dividing by the coverage fractions above:

| phase | multiplications | Rust model | the B2 bar |
|---|---|---|---|
| prove | 14,450 | **~0.36 s** | <= 60 s on phone-class |
| verify | 4,741 | **~0.13 s** | <= 100 ms |

**Prove clears its bar by two orders of magnitude. Verify does not.**

That is the finding, and it should be stated plainly rather than smoothed over. A
phone-class device is plausibly 3-5x slower than the machine these numbers come
from, which puts verification at 0.4-0.65 s against a 100 ms target. Either the
target moves, or verification needs work.

The options, none measured:

1. **Batch verification.** A node verifying many transactions amortises the setup
   and the fixed matrices. This is the standard answer and is probably enough.
2. **A faster multiplication.** 20 us is not close to optimal; Montgomery form,
   fewer passes over the slot table, or a proper NTT-style algorithm at the new
   modulus would all move it. Halving it moves verify to ~65 ms on desktop.
3. **Smaller ring.** Ring size is a security parameter, so this is not free.

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
