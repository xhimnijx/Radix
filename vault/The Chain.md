---
title: The Chain
tags: [chain, testnet]
---

# The chain

`radix_testnet/chain.py`. A deliberately small chain: blocks, a mempool, an output
set, a ring pool, and tag-based double-spend rejection. **No consensus**, one node.

## A block

```python
@dataclass(frozen=True)
class Block:
    height: int
    previous: bytes      # hash of the parent
    anchor: bytes        # the state root spends reference
    transactions: tuple[dict, ...]
    nonce: int
    timestamp: int
```

`block_hash()` is SHA-256 of the header; `meets_power()` requires 10 leading zero bits.
The proof of work exists so a block has to be *found*, not assembled — it is not a
security mechanism.

## The anchor

A spend references the block hash it was built against. This is the anti-replay rule:
a transaction built for block `h` cannot be replayed at `h+1`. An **anchor mismatch**
is a distinct error from a **double spend**, and the checks are ordered so the more
specific complaint wins (the tag check runs first).

## The output set — and why it never shrinks

Every output ever created is kept. The chain **cannot** remove a spent one:

> A ring signature hides which output it spends, so a node cannot know which output to
> delete.

Double spends are prevented by **tags**, not by removal. This is the same trade Monero
makes with key images. The field is called `outputs` rather than `utxo` precisely so
nobody assumes it means "unspent".

## The ring pool

A spend proves membership in a set of 1024 keys. Those keys come from a pool:

- the pool starts with **1024 deterministic decoys** so a fresh chain can already
  produce a valid ring;
- every new output's key is appended;
- a spend selects 1024 distinct indices including its own key.

Rings travel as **indices**, not keys: 1024 lattice keys is ~2 MB, and no chain puts
that in a block. The verifier rebuilds the ring from its own pool.

> [!warning] Decoys are not privacy
> Deterministic decoys make the harness work on day one. Real anonymity requires real
> decoys drawn from real outputs, and that is a wallet/chain design problem this
> prototype does not solve.

## Validation order

`Chain._check_spend`:

1. **tags** — reused tag ⇒ "double spend" (checked first because it is the more
   specific error, and a stale anchor would otherwise mask it);
2. **anchor** — must equal the current tip's hash;
3. **balance** — `Σ in = Σ out + fee`;
4. **ring** — 1024 distinct indices;
5. **proof** — the real verifier.

## Mining

`Chain.mine()` takes the mempool, finds a nonce meeting the target, applies the block
(outputs appended, tags recorded), clears the mempool.

## Persistence

`store.py` writes the chain atomically (temp file + `os.replace`) to
`chain.json`: blocks, outputs, spent tags, appended pool keys, mempool. On load the
chain is **not re-verified** — a local file this process wrote is trusted, and
re-verifying every block would cost ~20 s each.

A **corrupt** chain file refuses to start with a message naming the file, rather than
silently starting fresh: silent reset would look like the data had never existed.

## What is missing, and known to be missing

- no consensus, no peers, no fork choice;
- no difficulty adjustment;
- no fee market;
- no pruning (because pruning is impossible without revealing spends).

## Next

[[The Node and Miner]] for the process around it, and [[The Wallet and Its Accounts]]
for who owns the outputs.
