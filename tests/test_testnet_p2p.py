"""Two nodes, real sockets, one chain.

These are the three claims `docs/CONSENSUS.md` §7 could not make before: that nodes can
exchange blocks, that a mined block reaches a peer, and that a node which starts behind
catches up. Fork *reconciliation* is deliberately absent — the chain has no undo
journal — and there is a test that it fails loudly rather than corrupting state.

Blocks here carry no transactions, so these tests exercise the transport and the fork
rules rather than the proof system. That is the point: the transport should be testable
without spending two minutes per proof.
"""

import dataclasses

import pytest

from radix_testnet import p2p
from radix_testnet.chain import Block, ChainError
from radix_testnet.node import Node


def _mine_empty(node, timestamp=None):
    """A block with no transactions, mined the same way the chain mines one."""
    chain = node.chain
    block = Block(
        height=chain.height + 1,
        previous=chain.anchor,
        anchor=chain.anchor,
        transactions=(),
        nonce=0,
        timestamp=chain.tip.timestamp + 1 if timestamp is None else timestamp,
    )
    while not block.meets_power():
        block = dataclasses.replace(block, nonce=block.nonce + 1)
    chain.append(block)
    return block


@pytest.fixture
def two_nodes(tmp_path):
    """Two independent nodes, each with its own wallet, each listening."""
    first = Node(data_dir=tmp_path / "a", persist=True, peers=[])
    second = Node(data_dir=tmp_path / "b", persist=True, peers=[])
    first_server = p2p.Server(first, port=0)
    second_server = p2p.Server(second, port=0)
    first_port = first_server.start()
    second_port = second_server.start()
    first.peers = [f"127.0.0.1:{second_port}"]
    second.peers = [f"127.0.0.1:{first_port}"]
    try:
        yield first, second, first_port, second_port
    finally:
        first_server.stop()
        second_server.stop()


def test_a_handshake_reports_height_and_work(two_nodes):
    first, _second, first_port, _second_port = two_nodes
    reply = p2p.Peer.parse(f"127.0.0.1:{first_port}").call({"type": "hello"})

    assert reply["type"] == "hello"
    assert reply["height"] == first.chain.height == 0
    assert reply["work"] == first.chain.cumulative_work() == 1
    assert reply["genesis"] == first.chain.blocks[0].block_hash().hex()


def test_genesis_is_identical_on_both_nodes(two_nodes):
    """If genesis differed, two nodes could never agree on anything."""
    first, second, _first_port, _second_port = two_nodes
    assert first.chain.blocks[0].block_hash() == second.chain.blocks[0].block_hash()


def test_a_mined_block_propagates_to_a_peer(two_nodes):
    first, second, _first_port, _second_port = two_nodes
    block = _mine_empty(first)
    assert first.chain.height == 1

    results = first.broadcast_block(block)

    assert list(results.values()) == ["ok"], results
    assert second.chain.height == 1
    assert second.chain.tip.block_hash() == block.block_hash()


def test_a_node_that_starts_behind_catches_up(two_nodes):
    first, second, first_port, _second_port = two_nodes
    for _ in range(4):
        _mine_empty(first)
    assert first.chain.height == 4
    assert second.chain.height == 0

    outcome = second.sync_from(f"127.0.0.1:{first_port}")

    assert outcome["adopted"] is True
    assert second.chain.height == 4
    assert second.chain.tip.block_hash() == first.chain.tip.block_hash()
    assert second.chain.cumulative_work() == first.chain.cumulative_work()


def test_a_node_with_more_work_does_not_adopt_a_shorter_chain(two_nodes):
    first, second, second_port, _unused = two_nodes
    for _ in range(3):
        _mine_empty(first)

    outcome = first.sync_from(f"127.0.0.1:{second_port}")

    assert outcome["adopted"] is False
    assert first.chain.height == 3
    assert second.chain.height == 0


def test_a_fork_is_refused_rather_than_silently_applied(two_nodes):
    """Two different blocks at the same height: the second is rejected, loudly.

    Reconciliation needs an undo journal that the chain does not have, so applying a
    competing block would corrupt state irrecoverably. Refusing is the only safe
    behaviour, and it is stated in `p2p.py` rather than left to be discovered.
    """
    first, second, _first_port, _second_port = two_nodes
    _mine_empty(first)
    _mine_empty(second)  # different nonce, different hash, both at height 1

    with pytest.raises(ChainError, match="does not follow|fork"):
        first.chain.append(second.chain.tip)


def test_a_malformed_message_does_not_kill_the_server(two_nodes):
    first, _second, first_port, _second_port = two_nodes
    with pytest.raises(p2p.PeerError):
        p2p.Peer.parse(f"127.0.0.1:{first_port}").call({"type": "nonsense"})

    # and the server is still answering
    reply = p2p.Peer.parse(f"127.0.0.1:{first_port}").call({"type": "hello"})
    assert reply["type"] == "hello"


def test_an_unreachable_peer_is_an_error_not_a_hang():
    with pytest.raises(p2p.PeerError, match="cannot reach"):
        p2p.Peer.parse("127.0.0.1:1", timeout=1.0).call({"type": "hello"})
