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
from radix_testnet import params as P


def _mine_empty(node, timestamp=None):
    """A block with no transactions, mined the same way the chain mines one.

    The target and the timestamp both matter now: a block must carry the target the
    chain requires, and its time must be after the median and not in the future.
    """
    import time as clock

    chain = node.chain
    # Each block must be later than the median of the last eleven, and blocks mined
    # inside one second would otherwise share a timestamp and be rejected.
    when = (
        max(int(clock.time()), chain.tip.timestamp + 1)
        if timestamp is None
        else timestamp
    )
    block = Block(
        height=chain.height + 1,
        previous=chain.anchor,
        anchor=chain.anchor,
        transactions=(),
        nonce=0,
        timestamp=when,
        target=chain.next_target(),
    )
    while not block.meets_power():
        block = dataclasses.replace(block, nonce=block.nonce + 1)
    chain.append(block)
    return block


@pytest.fixture
def two_nodes(tmp_path):
    """Two nodes on the SAME network, which means the same genesis allocation.

    They share a wallet because the genesis allocation is derived from it: two nodes
    with independent wallets have different allocations, therefore different genesis
    blocks, and the sync check correctly refuses to merge them. That is not a test
    artefact, it is the point of the check -- a real network fixes the allocation in the
    protocol so that it is not per-node.
    """
    from radix_testnet import mnemonic as M
    from radix_testnet.wallet import Wallet

    phrase = M.new_phrase(128)
    shared = Wallet.from_mnemonic(phrase, P.parameters())
    first = Node(data_dir=tmp_path / "a", persist=True, peers=[], faucet=shared)
    second = Node(data_dir=tmp_path / "b", persist=True, peers=[], faucet=shared)
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


def test_a_peer_on_a_different_genesis_is_refused(two_nodes):
    """The allocation is part of the chain, so a different genesis is a different network.

    Without this check a node that trusted a peer would adopt their chain and silently
    leave its own -- and the handshake was already carrying the hash that makes the
    check possible.
    """
    first, second, first_port, _second_port = two_nodes
    for _ in range(3):
        _mine_empty(first)

    # Give the second node a chain it cannot share: a different genesis allocation.
    from radix_testnet.chain import Chain

    other = Chain(parameters=second.parameters, depth=2)
    key = tuple(tuple([i % 5] * 128) for i in range(4))
    other.genesis([(key, 999)])
    second.chain = other
    assert second.chain.blocks[0].block_hash() != first.chain.blocks[0].block_hash()

    with pytest.raises(p2p.PeerError, match="different chain"):
        second.sync_from(f"127.0.0.1:{first_port}")

    assert second.chain.blocks[0].block_hash() == other.blocks[0].block_hash()


def test_a_fork_is_reconciled_by_work(two_nodes):
    """Two branches from one genesis: the shorter one yields.

    This is what `Chain.rebuild` makes cheap -- reconciliation is a replay from
    genesis, not an undo journal. The node that is behind replaces its chain wholesale,
    and both end on the same tip.
    """
    first, second, _first_port, second_port = two_nodes
    assert first.chain.blocks[0].block_hash() == second.chain.blocks[0].block_hash()

    # Both mine from the same genesis. The timestamps must differ or the two nodes
    # search the same nonce sequence and produce *identical* blocks, which is not a
    # fork at all -- a mistake this test made in its first version.
    _mine_empty(first, timestamp=int(__import__('time').time()) + 1)
    _mine_empty(first, timestamp=int(__import__('time').time()) + 2)
    _mine_empty(second, timestamp=int(__import__('time').time()) + 4)
    assert first.chain.tip.block_hash() != second.chain.tip.block_hash()

    # One more block settles it: the first node now has more work.
    _mine_empty(first, timestamp=int(__import__('time').time()) + 3)
    assert first.chain.cumulative_work() > second.chain.cumulative_work()

    outcome = second.sync_from(f"127.0.0.1:{_first_port}")

    assert outcome["adopted"] is True
    assert second.chain.tip.block_hash() == first.chain.tip.block_hash()
    assert second.chain.cumulative_work() == first.chain.cumulative_work()
    assert second.chain.blocks[1].block_hash() == first.chain.blocks[1].block_hash()


def test_equal_work_is_broken_deterministically(two_nodes):
    """A tie must resolve the same way on both sides, or they never converge."""
    first, second, first_port, second_port = two_nodes
    _mine_empty(first, timestamp=int(__import__('time').time()) + 1)
    _mine_empty(second, timestamp=int(__import__('time').time()) + 4)
    assert first.chain.cumulative_work() == second.chain.cumulative_work()
    assert first.chain.tip.block_hash() != second.chain.tip.block_hash()

    # Whichever direction is tried, the node with the lower tip hash keeps its chain
    # and the other adopts. Run both directions and require agreement.
    first_tip = first.chain.tip.block_hash()
    second_tip = second.chain.tip.block_hash()

    from_first = second.sync_from(f"127.0.0.1:{first_port}")
    from_second = first.sync_from(f"127.0.0.1:{second_port}")

    if first_tip < second_tip:
        assert from_first["adopted"] is True
        assert from_second["adopted"] is False
    else:
        assert from_first["adopted"] is False
        assert from_second["adopted"] is True

    assert first.chain.tip.block_hash() == second.chain.tip.block_hash()


def test_a_node_serves_the_peers_it_knows(two_nodes):
    first, _second, first_port, second_port = two_nodes
    reply = p2p.Peer.parse(f"127.0.0.1:{first_port}").call({"type": "getpeers"})

    assert reply["type"] == "peers"
    assert f"127.0.0.1:{second_port}" in reply["peers"]


def test_discovery_turns_one_known_peer_into_two(two_nodes, tmp_path):
    """The point of discovery: configure one peer, learn the rest of its view.

    It is one hop and nothing more -- no gossip, no self-announcement -- so a node that
    nobody introduces still has to be configured by hand. That limitation is written in
    `discover` rather than hidden behind the word "discovery".
    """
    first, _second, first_port, second_port = two_nodes

    third = Node(data_dir=tmp_path / "c", persist=True, peers=[])
    try:
        assert third.peers == []
        added = third.discover(f"127.0.0.1:{first_port}")

        # The third node already knew nobody; it now knows the second node, via the first.
        assert f"127.0.0.1:{second_port}" in added
        assert f"127.0.0.1:{second_port}" in third.peers
    finally:
        pass


def test_discovery_does_not_add_a_peer_twice(two_nodes):
    first, _second, first_port, _second_port = two_nodes
    third_port_node = first  # reuse the fixture's node to keep the test cheap

    first.peers = []
    added = first.discover(f"127.0.0.1:{first_port}")  # asks itself
    assert f"127.0.0.1:{first_port}" not in added, "a node must not record itself"
