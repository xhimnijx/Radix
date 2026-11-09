---
title: The Wire Format
tags: [implementation, codec]
---

# The wire format

How a proof and a spend become bytes. `radix_testnet/codec.py` and
`proof_rust/src/codec.rs`.

## The proof, as bytes

`Proof.encode()` is a bare concatenation, in this order:

```
commitment[...]      κ + rows + 2m + 1 polynomials
h                    one polynomial
omega                one polynomial
response_prime[...]  ℓ polynomials
response[...]        W polynomials
challenge            d bytes, one per ternary coefficient (value + 1)
challenge_prime      d bytes
```

Each polynomial is `d × 4 = 512` bytes, little-endian 32-bit coefficients.

For depth 2, rows 4: `(19 + 2 + 13 + 29) · 512 + 2·128 = 32,512` bytes.

> [!warning] There are no length prefixes
> The decoder must be told the statement shape, because none of it is in the bytes.
> That is a real design wart; the Rust port reproduces it rather than inventing a
> versioned format the Python side could not read.

The decoder rejects a wrong-length input with an error rather than panicking, which
matters because the input is attacker-controlled.

## The spend envelope

Rings travel as **indices** into the node's pool:

```json
{
  "v": 1,
  "anchor": "<hex, 32 bytes>",
  "input_values": [1000],
  "ring_indices": [[...1024 ints...]],
  "outputs": [{"key": [[...]], "value": 990}],
  "fee": 10,
  "signatures": ["<hex proof>"],
  "tags": [[[...]]]
}
```

Size: about 70 KB for a spend, dominated by the proof (36 KB tagged) and the 1024
indices.

Why indices rather than keys: a depth-2 ring is 1024 keys × 4 polynomials × 512 bytes
≈ **2 MB**, and no chain puts 2 MB of public keys in a block. The verifier rebuilds the
ring from its own pool, which is also how Monero-style ring references work.

## The trust implication

Because the ring is not transmitted, the verifier's pool must match the prover's. In
this testnet both are the same process, so it always does. A real network would need
the pool to be *committed to* by the anchor, or the proof would not bind to the ring it
was made for. That is a real design question this prototype does not answer, and it is
worth flagging to a reviewer.

## The request format for the Rust prover

`prove_request.rs` takes a binary file:

```
u32 depth | u32 rows | u32 cols | u32 kappa | u32 width | u32 index | u32 message_len
message
rows0   : κ × W polys
rows    : (rows + 2m + 1) × W polys
matrix  : rows × cols polys
ring    : 32^depth × rows polys
secret  : cols polys
```

and writes the raw proof bytes. The matrix and ring are passed **extended** for tagged
proofs, so the Rust prover never needs to know what a tag is
([[The Rust Backend Seam]]).

## Verification of the codec

- polynomial digest matches Python (`1e86594e…`);
- ternary encoding round-trips, and a non-ternary byte is rejected;
- a truncated proof is a decoded error, not a panic;
- a proof round-trips through the wire and still verifies.
