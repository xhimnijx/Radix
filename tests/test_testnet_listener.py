"""The peer listener ships.

The independent review's sharpest engineering point: `p2p.py` could relay, sync, discover and
authenticate, and **nothing in the shipped product ever opened the port**. `serve()` started the
HTTP server and stopped there, so a node could not be dialled by the peers it already knew about,
and the whole peer layer existed only inside tests.

`serve()` now starts a `p2p.Server` alongside HTTP, records the bound address on the node, and
stops the listener on shutdown. `--p2p-port` exposes it; `0` binds an ephemeral port and `-1`
disables it.
"""

import inspect
import pathlib
import tempfile

from radix_testnet import node as N
from radix_testnet import p2p


def fresh_node():
    return N.Node(data_dir=pathlib.Path(tempfile.mkdtemp()), persist=True, peers=[])


def test_serve_starts_a_peer_listener():
    """Wiring assertion: the listener must be started, not merely referenced."""
    source = inspect.getsource(N.serve)
    assert "p2p.Server" in source, "serve() does not construct a peer listener"
    assert ".start()" in source, "the peer listener is constructed but never started"
    assert "node.address" in source, (
        "the bound peer address is not recorded, so discovery cannot advertise this node"
    )


def test_serve_stops_the_listener_on_shutdown():
    source = inspect.getsource(N.serve)
    assert ".stop()" in source, "the listener leaks on shutdown"


def test_the_cli_exposes_a_peer_port():
    source = pathlib.Path("radix_testnet/cli.py").read_text(encoding="utf-8")
    assert "--p2p-port" in source
    assert "p2p_port=" in source


def test_a_listener_answers_a_hello_over_a_real_socket():
    """The behaviour the wiring exists for, exercised rather than asserted."""
    node = fresh_node()
    server = p2p.Server(node, host="127.0.0.1", port=0)
    port = server.start()
    try:
        assert port > 0, "an ephemeral bind must report the port it actually got"
        reply = p2p.Peer.parse(f"127.0.0.1:{port}").call({"type": "hello"})
        assert reply["type"] == "hello"
        assert reply["height"] == node.chain.height
        assert reply["work"] == node.chain.cumulative_work()
    finally:
        server.stop()


def test_the_listener_reports_its_own_genesis():
    """A peer dialling us must be able to check we are on the same chain."""
    node = fresh_node()
    server = p2p.Server(node, host="127.0.0.1", port=0)
    port = server.start()
    try:
        reply = p2p.Peer.parse(f"127.0.0.1:{port}").call({"type": "hello"})
        assert reply["genesis"] == node.chain.blocks[0].block_hash().hex()
    finally:
        server.stop()


def test_relayed_transactions_pass_authentication():
    """S-05 / N-4: relay must work when the shared secret is set.

    A bogus payload is relayed deliberately. What is being tested is not that the transaction
    is accepted -- it should not be -- but that the *reply* is about the transaction rather
    than about authentication. Before the fix, the relay omitted the secret, so every relayed
    transaction was refused with an auth error and the sender saw only "unreachable".
    """
    import tempfile

    secret = b"a shared secret for the relay test"
    sender = N.Node(data_dir=pathlib.Path(tempfile.mkdtemp()), persist=True, peers=[])
    receiver = N.Node(data_dir=pathlib.Path(tempfile.mkdtemp()), persist=True, peers=[])
    sender.secret = secret
    receiver.secret = secret

    server = p2p.Server(receiver, host="127.0.0.1", port=0)
    port = server.start()
    try:
        sender.peers = [f"127.0.0.1:{port}"]
        results = sender.relay_tx({"v": 1, "anchor": "00", "signatures": []})
        reply = results[sender.peers[0]]
        # The payload is deliberately invalid, so a payload-level complaint is the success
        # case here. What must NOT appear is an authentication failure -- that is what the
        # missing secret produced, and it is the reason the defect was invisible.
        assert "authentication" not in str(reply).lower(), (
            f"the relayed message failed authentication, so the secret is still not passed: {reply}"
        )
        assert "ring_indices" in str(reply) or "error" in str(reply).lower(), (
            f"the peer produced neither a payload error nor an auth error: {reply}"
        )
    finally:
        server.stop()
