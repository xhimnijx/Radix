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
| 4 | BDLOP | `bdlop.py` | **commitment digest matches Python**; homomorphism and opening tests | **done** |
| 5 | Quadratic, tensor | `quadratic.py`, `tensor.py` | **coefficient and expected-value digests match**; flat index 2083 | **done** |
| 6 | Recursion | `recursion.py` | `matrix_vector`, `challenge_block`, `reduce_matrix` match | next |
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

## Cross-language sampling

`proof_rust/src/sample.rs` and `experiments/port_vectors.py` implement the same
generator: `uniform_from(label, counter)` hashes `domain || len(label) || label ||
counter` with SHAKE256 and reduces to `q`. That means both languages can be handed
identical polynomials in a test without quoting megabytes of coefficients, and the
label length is prefixed so `"ab"`+`"c"` cannot collide with `"a"`+`"bc"`.

## Current state

40 Rust tests pass: 6 arithmetic, 4 SHAKE256, 4 transcript, 5 codec, 5 sampling,
5 BDLOP, 5 tensor, 6 quadratic. The BDLOP commitment digest matches the Python reference byte for byte,
which is the first check of real cryptographic structure rather than of hashing or
encoding -- it exercises the sampling convention, the CRT multiplication and the
commitment layout together.

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
