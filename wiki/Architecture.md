# Architecture

```text
 wallet (browser UI)          CLI
        |                      |
        +--------- HTTP -------+
                 |
              node:  mempool -> blocks, outputs, tags
                 |                       |
            verifier                 chain state (JSON, atomic)
                 |
        proof (Python 1-2 min  |  Rust 0.5 s)
                 |
        ring signature over 1024 keys  +  linkable tag
```

## Components

| Component | Module | Role |
|---|---|---|
| Proof | `radix_core/candidate_b/lattice/` | The SMILE ring signature and its helpers |
| Chain | `radix_testnet/chain.py` | Blocks, mempool, outputs, tags, ring pool |
| Node | `radix_testnet/node.py` | HTTP API + GUI server |
| Wallet | `radix_testnet/wallet.py` | Accounts, addresses, sends |
| Seam | `radix_testnet/prover.py` | Chooses the Python or Rust prover |
| Rust | `proof_rust/` | The fast implementation |

## Three design points worth knowing

**Outputs are never removed.** A ring signature hides which output it spends, so the
chain cannot prune. Double spends are prevented by **tags**, not by deletion.

**The tag belongs to the key, not the note.** `T = A'·s` is a function of the secret, so
a keypair is spendable once. The wallet therefore has accounts, and change moves to the
next one.

**Rings travel as indices.** 1024 lattice keys is ~2 MB; the envelope carries indices and
the verifier rebuilds the ring from its own pool.

## Deeper

`vault/` has a note for each of these, from the maths upwards.
