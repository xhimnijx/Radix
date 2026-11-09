# Porting the proof to Rust

The arithmetic layer was ported first and measured at 20.1 µs per ring
multiplication. This is the rest of it: the prover and verifier, layered bottom-up,
with a known-answer test from the Python reference at every layer before the next
one starts. A layer that has no such test is not done.

## Why bottom-up with reference vectors

If a port is verified only by "it compiles and the proof verifies", a wrong
transcript constant and a wrong recursion coefficient are indistinguishable: both
produce a proof that fails. Checking each layer against the reference localises any
mistake to the layer that introduced it, which is the difference between an
afternoon and a week.

## Layers

| # | Layer | Python source | Verification | State |
|---|---|---|---|---|
| 1 | SHAKE256 | `hashlib.shake_256` | known answers, empty/`abc`/200-byte/500-byte | **done** |
| 2 | Transcript | `transcript.py` | two squeezes and a ternary challenge match byte for byte | **done** |
| 3 | Codec | `ring.encode/decode`, `Proof.encode` | polynomial digest and proof round-trip match | **done** |
| 4 | BDLOP | `bdlop.py` | commitments and openings match | next |
| 5 | Quadratic, tensor | `quadratic.py`, `tensor.py` | coefficients match | pending |
| 6 | Recursion | `recursion.py` | `matrix_vector`, `challenge_block`, `reduce_matrix` match | pending |
| 7 | Prove/verify | `setmembership.py` | cross-language verification | pending |
| 8 | Cross-checks | -- | Rust proof verified by Python, Python proof by Rust | pending |
| 9 | Timing | -- | end-to-end prove and verify, replacing the projection | pending |
| 10 | Seam | `radix_testnet/prover.py` | `--backend rust` produces proofs the Python verifier accepts | pending |

## Deliberate differences from Python

* **RNG.** The Python prover uses `random.Random` (Mersenne Twister) for masks and
  randomness. The Rust port uses its own generator. Proofs therefore do not match
  bit for bit, and they must not be expected to: a proof is checked mathematically,
  not by comparison. The cross-language tests verify each other's proofs instead.
  If reproducible proofs are ever needed, the RNG has to be specified, not just
  implemented.
* **Sampling.** The Python Gaussian is continuous-then-rounded. The port keeps that
  behaviour rather than silently switching to a discrete Gaussian, because the
  caveat is recorded in `setmembership.py` and the port must not quietly change it.
* **Errors.** Python raises exceptions; Rust returns `Result`. The wire behaviour is
  the same: a malformed proof is rejected, never panics. `decode` must reject
  inputs rather than index out of bounds.

## Current state

19 Rust tests pass: the original 6 arithmetic, 4 SHAKE256, 4 transcript, 5 codec.
The foundation is verified; the proof pipeline itself (layers 4-7) is the bulk of
the work and has not been started.

## Rules

1. `radix_core` is not modified. The reference stays the reference.
2. Every layer test must be a value produced by the Python code, quoted in the test
   with the expression that produced it.
3. No security claim. The Python implementation itself makes none.
4. A layer is not "done" because it compiles.

## Running

```powershell
& .\scripts\rust.ps1 test -Directory proof_rust
& .\scripts\rust.ps1 run --release --bin bench -Directory proof_rust
```
