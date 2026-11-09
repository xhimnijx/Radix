"""Transaction relay: a spend submitted to one node reaches the others.

Before this, only blocks propagated. A transaction submitted to a node lived only in that
node's mempool, so a network of peers each had a different view of what was pending and
only the node that received a spend could mine it.

The plumbing tests here use deliberately invalid payloads, because the question they ask
is whether the message is routed and answered — not whether a proof verifies. The one
test that needs a real spend is marked slow, since it costs about a minute to produce.
"""

import pytest

from radix_testnet import p2p
from radix_testnet.node import Node


@pytest.fixture
def two_nodes(tmp_path):
    """Two nodes on the same genesis, so a transaction valid at one is valid at the other."""
    from radix_testnet import mnemonic as M
    from radix_testnet import params as P
    from radix_testnet.wallet import Wallet

    shared = Wallet.from_mnemonic(M.new_phrase(128), P.parameters())
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


def test_a_malformed_transaction_is_refused_over_the_wire(two_nodes):
    _first, _second, first_port, _second_port = two_nodes
    with pytest.raises(p2p.PeerError, match="|"):
        p2p.Peer.parse(f"127.0.0.1:{first_port}").call(
            {"type": "tx", "payload": {"not": "a spend"}}
        )


def test_a_transaction_with_no_payload_is_refused(two_nodes):
    _first, _second, first_port, _second_port = two_nodes
    with pytest.raises(p2p.PeerError, match="no payload"):
        p2p.Peer.parse(f"127.0.0.1:{first_port}").call({"type": "tx"})


def test_a_repeated_transaction_is_answered_as_known(two_nodes):
    """The seen-set is what stops relay from looping between two nodes."""
    first, second, _first_port, second_port = two_nodes
    payload = {"deliberately": "invalid"}
    key = second.transaction_key(payload)
    second.seen_txs.add(key)

    reply = p2p.Peer.parse(f"127.0.0.1:{second_port}").call({"type": "tx", "payload": payload})
    assert reply.get("known") is True


def test_the_transaction_key_ignores_key_order(two_nodes):
    first, _second, _first_port, _second_port = two_nodes
    assert first.transaction_key({"a": 1, "b": 2}) == first.transaction_key({"b": 2, "a": 1})


@pytest.mark.slow
def test_a_real_spend_relays_between_nodes(two_nodes):
    """The end-to-end claim: submit to one node, and the other sees it in the mempool.

    Slow because producing a real tag and proof takes about a minute. It goes through
    `Node.send`, which is the same path the HTTP endpoint and the GUI use, so this
    exercises the relay exactly as a wallet would trigger it.
    """
    first, second, _first_port, _second_port = two_nodes
    wallet = first.faucet
    recipient = wallet.accounts[1].address

    before = len(second.chain.mempool)
    result = first.send(recipient, 10, 1)

    assert "id" in result
    assert len(first.chain.mempool) == before + 1
    assert len(second.chain.mempool) == before + 1, "the spend did not relay"
