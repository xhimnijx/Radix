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

The profile of one Python proof is unambiguous, so the port followed it rather
than the whole protocol: `_set_matrix` is **58%** of the time, `ring.dot` **35%**,
and both are built from the ring multiplication already ported. Everything else --
transcript hashing, mask sampling, the recursion glue -- is the remaining 7%.

`proof_rust/src/bin/prove_bench.rs` reproduces those two structures at their real
sizes and times them, on the same machine and the same `q`:

| workload | Rust, measured |
|---|---|
| set matrix x2 (depth 2, 1024 members, K = 4) | **0.055 s** |
| 240 dot calls (6,240 multiplications) | **0.101 s** |
| **one prover attempt** | **0.156 s** |
| **prove, at 2M^2 ~ 3 attempts** | **~0.47 s** |
| **verify (one set matrix + 645 multiplications)** | **0.037 s** |

Compare the Python profile for the same work: `_set_matrix` 38.0 s and `ring.dot`
22.8 s out of 65.2 s for six attempts. The Rust numbers are measurements of those
same operations, not projections from a per-operation cost -- the earlier model
predicted 0.36 s for prove and 0.13 s for verify, and the direct measurement
corrected verify downwards by 3.5x.

One structural difference worth knowing: the Rust set matrix computes the slot
residues of `c` once and multiplies slotwise, whereas the Python version
multiplies in full and then decomposes again. That is the same mathematical work
done once instead of twice, so the Rust figure is an efficient implementation of
the same algorithm rather than a different one.

### Against the B2 bar

| phase | measured (desktop) | phone, at 3-5x | bar | verdict |
|---|---|---|---|---|
| prove | ~0.47 s | 1.4-2.4 s | <= 60 s | **passes comfortably** |
| verify | 37 ms | 110-185 ms | <= 100 ms | **marginal** |

Verify is no longer the failure the projection suggested -- it is 37 ms, not
130 ms -- but it sits right on the line. On desktop it passes; on a phone it
probably does not, and it certainly has no margin. That is still the phase to work
on.

The options, none measured:

1. **Batch verification.** A node verifying many transactions amortises the set
   matrix, which is most of the cost. Probably sufficient, and standard.
2. **A faster multiplication.** 20.1 us is not close to optimal; Montgomery form
   or fewer passes over the slot table would move everything.
3. **Smaller ring.** Security parameter, so not free.

The residual 7% (hashing and sampling) is not in the measurement above; at Python
it is 4.4 s of 65.2 s, and a Keccak permutation in Rust is microseconds, so it
does not change these conclusions.

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
