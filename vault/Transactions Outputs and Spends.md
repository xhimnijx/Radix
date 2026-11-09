---
title: Transactions Outputs and Spends
tags: [money, protocol]
---

# Transactions, outputs and spends

How a proof becomes money. The data structures are in
`radix_core/candidate_b/lattice/spend.py` and `radix_testnet/tagged.py`.

## An output

```python
@dataclass(frozen=True)
class Output:
    key: tuple[Poly, ...]   # a lattice public key: k = 4 polynomials
    value: int              # plain integer
```

An output is "money addressed to a public key". There is no script, no address type and
**no hiding of the value** — see the warning below.

## A spend

```python
@dataclass(frozen=True)
class TaggedSpend:
    anchor: bytes                    # which block this was built against
    input_values: tuple[int, ...]    # what the inputs are claimed to hold
    rings: tuple[tuple[key, ...], ...]   # one 1024-key ring per input
    outputs: tuple[Output, ...]
    fee: int
    signatures: tuple[Proof, ...]    # one ring signature per input
    tags: tuple[tuple[Poly, ...], ...]   # one tag per input
```

Invariants enforced in `__post_init__`: one ring, signature, tag and value per input;
at least one input; the anchor is 32 bytes.

## The message each signature commits to

```python
_frame([anchor,
        u16(len(input_values)), values...,
        u16(len(outputs)),     each output encoded...,
        u64(fee)])
```

Every signature signs **the same message**, so inputs cannot be mixed and matched from
different transactions. This is the domain separation between transactions.

## Balance

`total_in = Σ input_values` and `total_out = Σ output values + fee`, and
`balanced` requires equality. It is checked by the verifier.

> [!danger] The values are not hidden and not proven
> Radix has **no amount commitments, no range proofs and no conservation proof**. The
> `input_values` field is the spender's own claim, and an attacker willing to lie about
> it can mint money. This is the largest functional gap in the testnet and it is listed
> in [[Status and Honest Limitations]]. The privacy properties are about *who*, not
> *how much*.

## Why the ring is a list of keys and also a list of indices

- The `Spend` object holds the actual 1024 keys so the verifier can compute with them.
- On the wire, the envelope carries **indices into the node's pool** and the verifier
  rebuilds the keys ([[The Wire Format]]).

## One input, one proof

Each input has its own ring signature over the shared message. A 2-input spend is two
proofs, and costs twice as much. The current wallet only ever builds one input.

## Tags and double spending

`tags` is the per-input array of `A'·s`. The chain records them and refuses a repeat
([[Linkable Tags]]). Note the consequence: **the tag identifies the key, not the note**,
which is why one account can be spent once ([[The Wallet and Its Accounts]]).

## What would change for a real system

- amounts committed (Pedersen-style over the lattice) and proven in range;
- a conservation proof that `Σ in − Σ out − fee = 0` across commitments;
- one-time addressing so each output has its own key and tag;
- a fee market and a mempool policy.

All four are B2 work and none is built.
