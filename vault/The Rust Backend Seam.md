---
title: The Rust Backend Seam
tags: [rust, testnet, integration]
---

# The Rust backend seam

How the fast prover serves the app. `radix_testnet/prover.py` and `rust_backend.py`.

## One seam, two backends

Everything above the seam — node, miner, wallet, GUI — calls exactly two functions:

```python
prover.prove_spend(...)     # build a spend
prover.verify_tagged(...)   # check one
```

Swapping backends is a change in one module and nowhere else.

## Why a subprocess and not FFI

`pyo3` is not available offline, and the boundary is **one call per proof**: ~40 ms of
process start against ~500 ms of proving. If that ever matters, `rust_backend.py` is the
only file that changes.

## The tagged complication

The testnet spends **tagged** proofs (`k′ = 4`), and the Rust port implements the
untagged protocol. The seam handles it without porting anything extra:

1. Python computes `T = A'·s` (it already does);
2. Python builds `A_ext = [A; A']` and the extended ring `{(pk_j, T)}`;
3. Rust proves the statement it is handed — it never learns what a tag is;
4. Python's `verify_tagged` reconstructs the same extended statement and checks.

That is why adding tags required **no prover changes**: a tag is just four more rows of
the matrix and one more polynomial in each ring member.

## The request

Binary, little-endian: a header (`depth, rows, cols, kappa, width, index,
message_len`), the message, then the polynomials: `rows0`, `rows`, `matrix`, `ring`,
`secret`. Layout documented in [[The Wire Format]].

## Choosing a backend

```powershell
cd proof_rust
cargo build --release --bin prove_request
cd ..
python -m radix_testnet.cli --backend rust ...
```

or set `RADIX_PROVE_BIN` to the binary.

If the binary is missing, `set_backend("rust")` **raises**. It does not silently fall
back to Python — a demo that claims the fast path while quietly using the slow one is
worse than no demo.

## Measured through the seam

| step | result |
|---|---|
| Rust proves a tagged spend (incl. process start and serialisation) | **0.93 s** |
| Python `verify_tagged` accepts it | **True** (38 s — that is Python's own verifier cost) |
| Different message | rejected |

## Verification

`tests/test_testnet_rust_backend.py`, 3 tests:

1. the Rust backend produces a proof Python accepts, and it is message-bound;
2. a tagged spend built through the seam verifies;
3. the backend refuses when the binary is missing.

> [!note] One of these failed first because the test was wrong
> The fixture spent 1000 units with **no outputs** — an unbalanced spend — which
> `verify_tagged_spend` correctly rejects. The code was right; the test was wrong.

## What is still missing

The verifier still runs in Python, at 20–38 s. Routing verification through Rust would
drop it to ~110 ms, and the seam is already shaped for it — but the node's
`verify` hook has not been pointed at the Rust verifier yet.
