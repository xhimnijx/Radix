"""Deterministic harness parameters, so a restart reproduces the same keys.

A real deployment takes its parameters from a reviewed manifest and its keys from
entropy. A harness wants neither: the node, the wallet and the tests must agree on
the same ring parameters every time they start, or nothing is reproducible.
"""

from __future__ import annotations

import random

from radix_core.candidate_b.lattice import ring_signature as RS

PARAMETER_SEED = b"radix-testnet-params-v1"
FAUCET_SEED = b"radix-testnet-faucet-v1"
DEPTH = 2
#: k' = 1. C2's third review priced both options: the tag's own collision instance is
#: 2^213 at k' = 1, 85 bits over target, while k' = 4 puts the target below
#: det^(1/n) and pays for a margin that is already there. Fewer rows also means fewer
#: module equations in s on top of pk = A s, which helps hiding. C1's original
#: recommendation of 4 was on collision grounds; C2's estimate shows 1 already clears
#: them.
TAG_ROWS = 1
GENESIS_NOTES = 4
GENESIS_VALUE = 1000


def parameters(seed: bytes = PARAMETER_SEED, depth: int = DEPTH, tag_rows: int = TAG_ROWS) -> RS.Parameters:
    """The ring parameters every testnet process uses."""
    return RS.setup(random.Random(int.from_bytes(seed, "big")), depth, None, tag_rows)


def faucet_seed(seed: bytes = FAUCET_SEED) -> bytes:
    """The seed every node derives its genesis allocation from.

    PUBLIC ON PURPOSE, and this is the honest statement of what that means: anyone who
    reads this file can derive the keys and spend the genesis coins. That is a faucet,
    not a launch. A mainnet needs an allocation specified and audited before genesis --
    a published seed is a testnet convenience, not a shortcut to be carried forward.
    """
    return seed


#: The famous BIP-39 test vector, and that is the point: it is unmistakably public.
#: Anyone reading this file can derive the keys and spend the genesis coins. That is a
#: faucet, not a launch. A mainnet needs an allocation specified and audited before
#: genesis; a published phrase is a testnet convenience and must not be carried forward.
GENESIS_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about"
)


def genesis_wallet(parameters=None):
    """The wallet whose first account receives the genesis allocation."""
    from .wallet import Wallet

    return Wallet.from_mnemonic(GENESIS_MNEMONIC, parameters or globals()["parameters"]())


def genesis_allocations(parameters=None):
    """The genesis allocation, derived rather than transmitted.

    Every node computes this identically from the constant seed, so two nodes that have
    never spoken still agree on block zero. The sync no longer carries an allocation
    list, which was the testnet shortcut recorded in `p2p.py`.
    """
    wallet = genesis_wallet(parameters)
    return [(wallet.accounts[0].public, GENESIS_VALUE * GENESIS_NOTES)]
