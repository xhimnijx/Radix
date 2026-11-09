# Radix testnet

A local harness for exercising the Candidate-B proof end to end: a wallet that
signs a real 1024-member ring signature, a node that verifies it with the real
verifier, and a miner that settles it in a block.

> **This is not a cryptocurrency.** No value, no consensus, no peer-to-peer
> network, no economic layer, no security claim. One process on localhost, one
> chain, one miner. See `STATUS.md` for where the cryptography actually stands.

## Quickstart

```powershell
python -m radix_testnet.cli node                 # http://127.0.0.1:8642
python -m radix_testnet.cli status               # in another terminal
python -m radix_testnet.cli address              # the faucet's address
python -m radix_testnet.cli send --to rtx1... --amount 100 --fee 10
python -m radix_testnet.cli mine
python -m radix_testnet.cli gui                  # opens the browser UI
```

Or open <http://127.0.0.1:8642> once the node is running. The page polls the node
every three seconds, shows the chain, the mempool and the faucet balance, and has
a send form and a mine button.

## What a send actually costs

It signs a real tagged ring signature over **1024 ring members** at
`q = 4,294,966,337`. In CPython that takes **1-2 minutes**, and the UI says so
while it waits. The Rust arithmetic layer is measured at 20 µs per multiplication
(≈0.47 s to prove, 37 ms to verify), but **the proof is not ported yet**, so the
harness runs the Python reference rather than pretending to be fast.

`--backend rust` exists and **refuses** rather than silently falling back to the
slow path. `radix_testnet/prover.py` is the single seam: node, miner, wallet and
GUI call `prove_spend` and `verify_spend` and nothing else, so the Rust port will
attach there.

## Double spends

A ring signature deliberately hides which key it opens, so a plain UTXO set cannot
tell a first spend from a second. The **linkable tag** is what restores
double-spend detection, and this harness uses the same-witness extension
(`sign_tagged` / `verify_tagged`, `k′ = 4`) — the sound version, not the withdrawn
one. A reused tag is refused both in the mempool and on the chain.

## Layout

| File | Role |
|---|---|
| `chain.py` | blocks, trivial proof of work, mempool, UTXO, 1024-key decoy pool, tag rejection |
| `tagged.py` | tagged spend builder and verifier |
| `wallet.py` | seed → keypair, address, note tracking, send with change |
| `prover.py` | the python/rust seam |
| `codec.py` | `Proof` decoder and the spend envelope |
| `node.py` | HTTP API and the GUI server |
| `miner.py` | mine the mempool |
| `cli.py` | one entry point |
| `static/index.html` | the browser page, no external dependencies |

Rings travel as **pool indices**, not keys: a depth-2 ring is 1024 lattice keys
(≈2 MB) and no chain would put that in a block, so an envelope is ~70 KB.

## Limitations, stated rather than hidden

* **No persistence.** The chain lives in memory; restarting the node resets it.
* **No consensus.** One node, no peers, no fork choice, longest-chain-by-fiat.
* **No economic layer.** The faucet is funded at genesis from nothing.
* **One keypair per wallet.** Outputs are addressed to a public key directly;
  one-time addressing needs a key exchange the scheme does not provide yet (B2).
* **Trivial proof of work.** `POW_BITS = 10`, for block shape, not for security.
* **Deterministic parameters.** A fixed seed so the node, wallet and tests agree;
  a real deployment takes parameters from a reviewed manifest and keys from entropy.

## Tests

```powershell
python -m pytest -q tests/test_testnet_chain.py        # 9 tests, ~4 s, stub verifier
python -m pytest -q tests/test_testnet_end_to_end.py   # real proof, several minutes
```

The fast suite tests the plumbing with a stub verifier. The slow one runs an
actual proof through the node and checks the recipient's note, the sender's
change, and that the second spend is refused by its tag.
