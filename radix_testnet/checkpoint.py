"""Checkpoints: start replay from a known state instead of from genesis.

Why this exists
---------------
`Chain.rebuild` replays every block from genesis. Measured on this machine: an empty
block costs about 1 ms, and a block carrying one transaction costs about 2.7 ms more
because its proof has to be decoded out of the wire format. At ten transactions per
120-second block that is **27 ms per block, or 3.9 hours to replay one year of chain** —
and replay does not even verify the proofs, which cost 105 ms each. Checkpoints turn that
linear cost into a constant.

What a checkpoint is, and is not
--------------------------------
A checkpoint is a **trust anchor**, not a consensus rule. A node that restores from one
accepts the state it describes without re-deriving it. That is exactly why checkpoints
work and exactly why they are dangerous: a node that trusts a bad checkpoint is on a
chain that no other node will accept, and no amount of subsequent validation will notice.

So the honest framing is: a checkpoint lets a node skip work, and in exchange it trusts
whoever produced the checkpoint. That trade belongs in the documentation, not in a
comment here.

The checkpoint file holds the state, not the history: the blocks are not included, only
the digest of the state they produced.
"""

from __future__ import annotations

import hashlib
import json

from radix_core.candidate_b.lattice import ring
from radix_core.candidate_b.lattice.params import SMILE
from radix_core.candidate_b.lattice.spend import Output

from .chain import Block, Chain

VERSION = 1
#: The decoy pool is derived from a fixed seed, so it is not stored: only the coins
#: added after it need to be. Storing 1024 decoys per checkpoint would be 2 MB of
#: bytes that every node can regenerate.
DECOYS = 1024


class CheckpointError(ValueError):
    """A checkpoint is malformed, or does not match the chain it is applied to."""


def _encode_key(key) -> str:
    return b"".join(ring.encode(poly, SMILE) for poly in key).hex()


def _decode_key(text: str):
    chunk = SMILE.ring_degree * 4
    blob = bytes.fromhex(text)
    if len(blob) % chunk:
        raise CheckpointError("a key in the checkpoint has the wrong length")
    return tuple(
        ring.decode(blob[offset : offset + chunk], SMILE)
        for offset in range(0, len(blob), chunk)
    )


def snapshot(chain: Chain) -> dict:
    """The chain's state at its tip, as JSON-able data."""
    return {
        "version": VERSION,
        "height": chain.height,
        "block_hash": chain.tip.block_hash().hex(),
        # The tip block itself: `height` is derived from the chain's length, and the
        # anchor is its hash, so a restored chain needs this one block to stand at the
        # right height and to accept the next block.
        "tip": chain.tip.to_wire(),
        "allocations": chain.allocations_wire(),
        "outputs": [
            [identifier.hex(), _encode_key(note.key), note.value]
            for identifier, note in chain.outputs.items()
        ],
        # Only the coins added after the deterministic decoys.
        "pool_tail": [_encode_key(key) for key in chain.pool[DECOYS:]],
        "spent_tags": [tag.hex() for tag in sorted(chain.spent_tags)],
        "treasury": [[height, atoms] for height, atoms in sorted(chain.treasury.items())],
        "immature": [[identifier.hex(), height] for identifier, height in chain.immature.items()],
    }


def digest(state: dict) -> str:
    """A digest of the state, so a checkpoint can be compared without shipping it."""
    canonical = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def restore(state: dict, parameters=None, depth: int = 2, verify=None) -> Chain:
    """Build a chain whose state is exactly this snapshot, with no blocks replayed."""
    if state.get("version") != VERSION:
        raise CheckpointError(f"unsupported checkpoint version {state.get('version')}")

    chain = Chain(parameters=parameters, depth=depth, verify=verify)
    chain.genesis(Chain.allocations_from_wire(state["allocations"]))
    tip = Block.from_wire(state["tip"])
    if tip.block_hash().hex() != state["block_hash"]:
        raise CheckpointError("the stored tip does not match the recorded block hash")
    # The blocks below the checkpoint are gone; the tip keeps the height and the anchor
    # correct so the next block links to it. `height` is `len(blocks) - 1`, so the list
    # is padded with None up to the tip -- the ledger holds no fake transactions, only
    # absent history.
    chain.blocks = [None] * tip.height + [tip]

    chain.outputs = {}
    for identifier, key_text, value in state["outputs"]:
        note = Output(key=_decode_key(key_text), value=int(value))
        chain.outputs[bytes.fromhex(identifier)] = note

    tail = [_decode_key(text) for text in state["pool_tail"]]
    chain.pool = [*chain.pool[:DECOYS], *tail]
    chain.spent_tags = {bytes.fromhex(tag) for tag in state["spent_tags"]}
    chain.treasury = {int(height): int(atoms) for height, atoms in state["treasury"]}
    chain.immature = {
        bytes.fromhex(identifier): int(height) for identifier, height in state["immature"]
    }
    return chain


def replay_from(state: dict, blocks: list, parameters=None, depth: int = 2, verify=None) -> Chain:
    """Restore a checkpoint, then apply only the blocks after it.

    `blocks` must start at the checkpoint's height: the caller has already discarded
    everything below it.
    """
    chain = restore(state, parameters=parameters, depth=depth, verify=verify)
    for block in blocks:
        if block.height != chain.height + 1:
            raise CheckpointError(
                f"block height {block.height} does not follow the checkpoint at {chain.height}"
            )
        chain._apply(block)
    return chain
