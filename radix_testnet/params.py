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
TAG_ROWS = 4  # k' = 4 for the distinct-note property, per REVIEW-FINDINGS.md
GENESIS_NOTES = 4
GENESIS_VALUE = 1000


def parameters(seed: bytes = PARAMETER_SEED, depth: int = DEPTH, tag_rows: int = TAG_ROWS) -> RS.Parameters:
    """The ring parameters every testnet process uses."""
    return RS.setup(random.Random(int.from_bytes(seed, "big")), depth, None, tag_rows)


def faucet_seed(seed: bytes = FAUCET_SEED) -> bytes:
    return seed
