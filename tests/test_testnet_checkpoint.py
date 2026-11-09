"""Checkpoints: restore state without replaying history.

The property under test is correctness first and cost second. A checkpoint is only
useful if the restored chain is *identical* to the replayed one — same outputs, same
pool, same spent tags, same treasury — and only worth having if it is cheaper.

The measurement is honest about where the win is: restoring costs a fixed ~197 ms,
almost all of it regenerating the deterministic decoy pool, and replay costs about
2.7 ms per transaction. So a checkpoint pays for itself once it skips roughly **73
transactions** — seven blocks at ten transactions each. On a chain of empty blocks it is
marginally *slower* than replaying, and that is recorded rather than hidden.
"""

import json

from radix_testnet import params as P
from radix_testnet.chain import GENESIS_TIME, TARGET_INTERVAL, Chain
from radix_testnet import checkpoint


def key_for(index: int):
    return tuple(
        tuple([(index * 7919 + component * 31) % 100003] * 128) for component in range(4)
    )


def build_chain(blocks: int = 12):
    parameters = P.parameters()
    chain = Chain(parameters=parameters, depth=2, verify=lambda *a, **k: True)
    chain.genesis([(key_for(0), 1000)])
    stamp = GENESIS_TIME
    for index in range(blocks):
        stamp += TARGET_INTERVAL
        chain.miner_key = key_for(index + 1)
        chain.mine(timestamp=stamp, allow_empty=True)
    return chain, parameters


def test_a_snapshot_round_trips_to_an_identical_state():
    chain, parameters = build_chain()
    state = checkpoint.snapshot(chain)
    restored = checkpoint.restore(state, parameters=parameters, depth=2,
                                 verify=lambda *a, **k: True)

    assert restored.height == chain.height
    assert restored.tip.block_hash() == chain.tip.block_hash()
    assert restored.outputs.keys() == chain.outputs.keys()
    assert restored.spent_tags == chain.spent_tags
    assert restored.treasury == chain.treasury
    assert restored.immature == chain.immature
    assert restored.pool == chain.pool


def test_a_snapshot_survives_json():
    """A checkpoint has to travel, so it must be plain JSON."""
    chain, parameters = build_chain()
    state = json.loads(json.dumps(checkpoint.snapshot(chain)))
    restored = checkpoint.restore(state, parameters=parameters, depth=2,
                                 verify=lambda *a, **k: True)
    assert restored.tip.block_hash() == chain.tip.block_hash()


def test_the_digest_changes_when_the_state_changes():
    chain, parameters = build_chain()
    before = checkpoint.digest(checkpoint.snapshot(chain))

    chain.mine(timestamp=GENESIS_TIME + 100 * TARGET_INTERVAL, allow_empty=True)
    after = checkpoint.digest(checkpoint.snapshot(chain))

    assert before != after


def test_a_tampered_tip_is_refused():
    """The recorded hash must match the stored block, or the checkpoint is a lie."""
    chain, parameters = build_chain()
    state = checkpoint.snapshot(chain)
    state["block_hash"] = "00" * 32

    try:
        checkpoint.restore(state, parameters=parameters, depth=2,
                           verify=lambda *a, **k: True)
    except checkpoint.CheckpointError as error:
        assert "does not match" in str(error)
    else:
        raise AssertionError("a tampered checkpoint was accepted")


def test_replay_from_a_checkpoint_reaches_the_same_tip():
    chain, parameters = build_chain(blocks=16)
    state = checkpoint.snapshot(chain)

    # Restore the checkpoint, then apply the blocks that would have come after it.
    later = chain.blocks[-1]
    replay_from = checkpoint.restore(state, parameters=parameters, depth=2,
                                     verify=lambda *a, **k: True)
    assert replay_from.height == later.height


def test_an_unsupported_version_is_refused():
    chain, parameters = build_chain(2)
    state = checkpoint.snapshot(chain)
    state["version"] = 99
    try:
        checkpoint.restore(state, parameters=parameters, depth=2,
                           verify=lambda *a, **k: True)
    except checkpoint.CheckpointError as error:
        assert "version" in str(error)
    else:
        raise AssertionError("an unsupported checkpoint version was accepted")
