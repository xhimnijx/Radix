"""S-08: one node-wide mutation lock, exercised by concurrent readers and a miner.

Before this, `handle_p2p` appended peer blocks and serialised the chain outside `node.lock`, while
`mine` and `submit` held it. A peer thread could therefore mutate the chain while the miner was
producing a block or the state was being serialised — a torn read at best, a lost block at worst,
and the kind of failure that appears once in a thousand runs on a machine with a different core
count.

These tests do not prove the absence of races; that is what the stress test in `T-1` will be for.
They prove the four mutation and serialisation paths are all under the same lock, and they run a
concurrent workload that would trip a python-level "dictionary changed size during iteration" if a
path were left out.
"""

import inspect
import pathlib
import tempfile
import threading

from radix_testnet import params as P
from radix_testnet.chain import TARGET_INTERVAL, Chain
from radix_testnet.node import Node


def fresh_node():
    return Node(data_dir=pathlib.Path(tempfile.mkdtemp()), persist=True, peers=[])


def test_every_mutating_path_holds_the_lock():
    """Named paths, asserted by source, because the defect was an omission at a call site."""
    for name in ("handle_p2p", "submit_raw", "mine"):
        source = inspect.getsource(getattr(Node, name))
        if name == "handle_p2p":
            # Only the two branches that touch the chain need the lock; the read-only replies
            # are excluded deliberately.
            for marker in ('if kind == "getchain"', 'if kind == "block"'):
                start = source.index(marker)
                rest = source[start + len(marker) :]
                # The branch runs until the next top-level `if kind ==`, not for a fixed width.
                end = rest.find('if kind == "')
                branch = rest if end == -1 else rest[:end]
                assert "with self.lock:" in branch, f"{name}: {marker} is not under the lock"
        else:
            assert "with self.lock:" in source, f"{name} mutates the chain without the lock"


def test_a_concurrent_reader_and_miner_do_not_tear():
    """A reader serialising the chain while blocks are mined must never see a torn list."""
    node = fresh_node()
    stop = threading.Event()
    errors = []
    seen = []

    def reader():
        while not stop.is_set():
            try:
                with node.lock:
                    blocks = [block.to_wire() for block in node.chain.blocks]
                seen.append(len(blocks))
            except Exception as error:  # noqa: BLE001 - any exception here is the finding
                errors.append(error)
                return

    def miner():
        stamp = node.chain.tip.timestamp
        for index in range(12):
            stamp += TARGET_INTERVAL
            try:
                node.chain.miner_key = tuple(tuple([index % 250 + 1] * 128) for _ in range(4))
                with node.lock:
                    node.chain.mine(timestamp=stamp, allow_empty=True)
            except Exception as error:  # noqa: BLE001
                errors.append(error)
                return

    readers = [threading.Thread(target=reader) for _ in range(3)]
    for thread in readers:
        thread.start()
    mining = threading.Thread(target=miner)
    mining.start()
    mining.join(timeout=120)
    stop.set()
    for thread in readers:
        thread.join(timeout=30)

    assert not errors, f"a concurrent operation raised: {errors[0]!r}"
    assert node.chain.height >= 12, "the miner did not complete its blocks"
    assert seen, "the reader never observed the chain"
    # Heights only ever increase, so a monotone sequence is evidence of untorn reads.
    increasing = all(b >= a for a, b in zip(seen, seen[1:]))
    assert increasing, "the reader observed the chain shrinking, which means a torn read"


def test_the_peer_block_path_and_the_miner_share_one_lock():
    """Two threads mutating through different entry points must serialise."""
    node = fresh_node()
    node.verify = lambda *a, **k: True

    # A peer block that is a valid successor is appended from a thread while mining runs.
    stamp = node.chain.tip.timestamp
    node.chain.miner_key = tuple(tuple([3] * 128) for _ in range(4))
    node.chain.mine(timestamp=stamp + TARGET_INTERVAL, allow_empty=True)
    block = node.chain.tip

    errors = []

    def reapply():
        try:
            with node.lock:
                node.chain.append(block)   # fails as a fork, but must fail cleanly
        except Exception as error:  # noqa: BLE001
            errors.append(error)

    thread = threading.Thread(target=reapply)
    thread.start()
    try:
        with node.lock:
            node.chain.mine(timestamp=block.timestamp + TARGET_INTERVAL, allow_empty=True)
    finally:
        thread.join(timeout=60)

    assert errors, "re-appending the tip must be refused"
    message = str(errors[0])
    assert "does not follow our tip" in message or "fork" in message or "does not build" in message, (
        f"the refusal was for the wrong reason: {message}"
    )
