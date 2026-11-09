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
| 6 | Recursion | `recursion.py` | **pairing digest matches**; shapes, linearity and constant-vector rejection | **done** |
| 7 | Prove/verify | `setmembership.py` | cross-language verification | **both done**; Rust proofs verify in Rust and in Python |
| 8 | Cross-checks | -- | Rust proof verified by Python, Python proof by Rust | **both directions PASS** |
| 9 | Timing | -- | end-to-end prove and verify, replacing the projection | next |
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

57 Rust tests pass. Every layer below the proof itself has at least one value
produced by the Python reference, and the proof's own scaffolding now does too:
`masking_width`, `draw` and `draw_ternary` match. What remains of layer 7 is the
verifier's body (the slot mapping, the descent, `F` and the final equation) and
then the prover. The BDLOP commitment digest matches the Python reference byte for byte,
which is the first check of real cryptographic structure rather than of hashing or
encoding -- it exercises the sampling convention, the CRT multiplication and the
commitment layout together.

## Resolved failure, 2026-11-09

The acceptance test initially rejected a valid Python proof. Instrumenting `verify`
with `verify_traced` -- which records the name of every stage it enters -- reduced
the search to two bugs in one run:

1. **The commitment arity was wrong.** I used `kappa + lambda + depth + 1` (23);
   the real count is `kappa + rows + 2m + 1` (19). The wrong formula equals 23 when
   `rows = 8`, which is the *tagged* shape, so it passed every test that used tagged
   parameters and was wrong everywhere else. The same formula is in
   `radix_testnet/codec.py`, where it has the same latent bug; both are fixed.
   This is the port finding a defect in the Python side, which is the whole point of
   an independent implementation.
2. **The last term of `lhs` was subtracted instead of added.** Python's
   `ring.add(x, f[rows + 2m + 1])` adds it. The trace showed all eighteen stages
   passing, including `c`, which means the entire transcript ordering, the descent,
   `final_x` and the line 10-13 accumulation were already correct -- the bug was one
   sign in the final line.

With both fixed, the Rust verifier accepts a real 32,512-byte Python proof:
`cargo test --test python_proof` passes. The transcript, the slot map, the descent
and the final equation are all confirmed against the reference.

`verify_traced` stays in the crate. It cost twenty lines and turned a blind
debugging session into one run; the next disagreement will need it too.

## The prover, and one more silent bug

The prover is a direct translation of `_prove_once`, including both rejection points
and the rebuild-from-scratch behaviour on rejection. The Rust verifier rejected the
first Rust proofs, and the stage trace named the last line: `h`'s first four
coefficients must be zero.

The cause was a genuine misreading. Python builds `g` with its first `d/l`
**coefficients** zero; the port zeroed the first `d/l` **slots** and lifted the
result. Those are different polynomials, and every other stage of the proof still
passed -- the commitments, both challenges and the whole descent were consistent,
because they do not constrain `g`. Only lines 14-15 catch it, which is exactly the
check that exists for this purpose.

## Cross-language results

| direction | result |
|---|---|
| Python proof -> Rust verifier | passes |
| Rust proof -> Python verifier | passes |
| Rust proof, different message | rejected by both |
| tampered response | rejected |

`experiments/produce_python_proof.py` and `proof_rust/src/bin/emit_proof.rs` write
fixtures; `experiments/verify_rust_proof.py` checks the Rust one against the Python
reference.

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
