"""Checkpointed sync: replay from a snapshot when the chain agrees with it.

`Chain.rebuild` replays from genesis. Measured earlier: an empty block costs about 1 ms and
a transaction adds 2.7 ms, so a year of chain at ten transactions per block is 3.9 hours of
replay -- and replay does not verify proofs, which cost 105 ms each.

A checkpoint lets a node replay only the tail. The safety condition is the whole point: a
snapshot is a statement about a *particular* chain, so it is only used when the peer's chain
hashes to the same block at that height. Applying it to a different chain would adopt a
state that never existed.

The measured win is modest -- 1.1x at 200 empty blocks, break-even around 73 skipped
transactions -- because restoring costs a fixed 197 ms, mostly regenerating the decoy pool.
These tests check the correctness and the fallback, not the speed.
"""

import tempfile

from radix_testnet import params as P
from radix_testnet.node import CHECKPOINT_INTERVAL, Node


def fresh_node():
    return Node(data_dir=tempfile.mkdtemp(), persist=True, peers=[])


def test_a_fresh_node_has_no_checkpoint():
    node = fresh_node()
    assert node._checkpoint is None


def test_a_short_chain_does_not_produce_a_checkpoint():
    node = fresh_node()
    assert node.chain.height < CHECKPOINT_INTERVAL
    assert node.refresh_checkpoint() is False


def test_a_checkpoint_records_its_height_and_hash():
    node = fresh_node()
    node.refresh_checkpoint()
    node._checkpoint = {"height": 0, "block_hash": node.chain.tip.block_hash().hex(),
                        "version": 1}
    assert node._checkpoint["block_hash"] == node.chain.blocks[0].block_hash().hex()


def test_a_checkpoint_that_disagrees_with_the_chain_is_not_used():
    """A snapshot is a statement about one chain; using it for another would be a lie."""
    node = fresh_node()
    node._checkpoint = {
        "version": 1,
        "height": 0,
        "block_hash": "00" * 32,          # deliberately not our genesis
        "tip": node.chain.tip.to_wire(),
        "allocations": node.chain.allocations_wire(),
        "outputs": [],
        "pool_tail": [],
        "spent_tags": [],
        "treasury": [],
        "immature": [],
    }
    assert node._replay_from_checkpoint(list(node.chain.blocks)) is None


def test_no_checkpoint_means_a_full_replay():
    node = fresh_node()
    assert node._replay_from_checkpoint(list(node.chain.blocks)) is None
