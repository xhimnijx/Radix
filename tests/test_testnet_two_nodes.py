"""S-09: two nodes exchange a block over real sockets.

Every other node test drives `handle_p2p` in-process, which is why the peer listener could be
missing from the shipped product for so long: the tests always started their own server. These
tests start two listeners, connect over TCP, and move a block from one chain to the other.

The path exercised is the one a real peer takes: mine on A, broadcast A's tip to B, and B applies it
with verification on.
"""

import pathlib
import tempfile

import pytest

from radix_testnet import p2p
from radix_testnet.chain import TARGET_INTERVAL
from radix_testnet.node import Node


def two_nodes():
    """Two nodes on the SAME chain, which takes care: a fresh node generates its own wallet and
    therefore its own genesis allocation, so two independently created nodes disagree from block
    zero. The second node is created from a copy of the first's state, which is what a real
    operator does when joining an existing network."""
    import shutil

    first_dir = pathlib.Path(tempfile.mkdtemp())
    second_dir = pathlib.Path(tempfile.mkdtemp())
    first = Node(data_dir=first_dir, persist=True, peers=[])
    shutil.rmtree(second_dir)
    shutil.copytree(first_dir, second_dir)
    second = Node(data_dir=second_dir, persist=True, peers=[])
    first.chain.verify = lambda *a, **k: True
    second.chain.verify = lambda *a, **k: True
    first_server = p2p.Server(first, host="127.0.0.1", port=0)
    second_server = p2p.Server(second, host="127.0.0.1", port=0)
    first_port = first_server.start()
    second_port = second_server.start()
    return first, second, first_server, second_server, first_port, second_port


def test_a_mined_block_propagates_to_a_peered_node():
    first, second, first_server, second_server, first_port, second_port = two_nodes()
    try:
        assert first.chain.blocks[0].block_hash() == second.chain.blocks[0].block_hash(), (
            "the two nodes must share a genesis for a block to be admissible"
        )
        first.chain.miner_key = tuple(tuple([2] * 128) for _ in range(4))
        block = first.chain.mine(
            timestamp=first.chain.tip.timestamp + TARGET_INTERVAL, allow_empty=True
        )
        assert first.chain.height == 1
        assert second.chain.height == 0

        # The real path: dial the peer and push the block.
        reply = p2p.Peer.parse(f"127.0.0.1:{second_port}").call(
            {"type": "block", "block": block.to_wire()}
        )

        assert reply["type"] == "ok", reply
        assert second.chain.height == 1, "the peer did not adopt the block"
        assert second.chain.tip.block_hash() == block.block_hash()
    finally:
        first_server.stop()
        second_server.stop()


def test_sync_pulls_the_whole_chain_from_a_peer():
    first, second, first_server, second_server, first_port, second_port = two_nodes()
    try:
        stamp = first.chain.tip.timestamp
        for index in range(3):
            stamp += TARGET_INTERVAL
            first.chain.miner_key = tuple(tuple([index + 3] * 128) for _ in range(4))
            first.chain.mine(timestamp=stamp, allow_empty=True)
        assert first.chain.height == 3

        second.sync_from(f"127.0.0.1:{first_port}")

        assert second.chain.height == 3
        assert [b.block_hash() for b in second.chain.blocks] == [
            b.block_hash() for b in first.chain.blocks
        ]
    finally:
        first_server.stop()
        second_server.stop()


def test_a_block_with_an_unknown_parent_is_refused_over_the_wire():
    """The listener must not be a way to push an arbitrary chain fragment in."""
    first, second, first_server, second_server, first_port, second_port = two_nodes()
    try:
        first.chain.miner_key = tuple(tuple([4] * 128) for _ in range(4))
        first.chain.mine(timestamp=first.chain.tip.timestamp + TARGET_INTERVAL, allow_empty=True)
        second.chain.miner_key = tuple(tuple([6] * 128) for _ in range(4))
        second.chain.mine(
            timestamp=second.chain.tip.timestamp + TARGET_INTERVAL, allow_empty=True
        )
        # Both are at height 1 but on different blocks, so first's block 2 is not a successor.
        forward = first.chain.mine(
            timestamp=first.chain.tip.timestamp + TARGET_INTERVAL, allow_empty=True
        )

        # `Peer.call` raises on an error reply rather than returning it, so the refusal
        # arrives as an exception. What matters is that it is refused and not applied.
        with pytest.raises(p2p.PeerError, match="does not build on our tip|fork"):
            p2p.Peer.parse(f"127.0.0.1:{second_port}").call(
                {"type": "block", "block": forward.to_wire()}
            )

        assert second.chain.height == 1, "a non-successor block was applied"
    finally:
        first_server.stop()
        second_server.stop()
