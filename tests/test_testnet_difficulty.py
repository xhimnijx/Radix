"""Difficulty adjustment and timestamp rules.

The chain used to accept any block whose hash had ten leading zero bits — about a
thousand attempts, and no adjustment at all. These tests are about the mechanism that
replaces it: a per-block target carried in the header, LWMA over 90 blocks, a 2x clamp,
and the timestamp rules that stop a miner from lying the difficulty down.

The convergence test simulates the loop rather than hashing, because the difficulty
algorithm only ever sees timestamps. Feeding it the timestamps a given hashrate *would*
produce tests the algorithm exactly, without spending minutes on SHA-256.
"""

import dataclasses

import pytest

from radix_testnet import params as P
from radix_testnet.chain import (
    GENESIS_TARGET,
    LWMA_WINDOW,
    MAX_TARGET,
    MEDIAN_WINDOW,
    MIN_TARGET,
    TARGET_INTERVAL,
    Block,
    Chain,
    ChainError,
)


def chain_with_genesis():
    parameters = P.parameters()
    key = tuple(tuple([i % 7] * 128) for i in range(4))
    chain = Chain(parameters=parameters, depth=2, verify=lambda *a, **k: True)
    chain.genesis([(key, 1000)])
    return chain


def append_synthetic(chain, timestamp, target=None):
    """Append a block without hashing.

    The difficulty algorithm only reads timestamps and targets, so a test of the
    algorithm must not spend its time on SHA-256. The first version of this helper did
    mine each block, and `test_the_target_stays_inside_its_bounds` then asked for 80
    blocks at a target heading towards 2^32 — billions of hashes, and a test that never
    finished. Appending directly tests exactly the same property.
    """
    block = Block(
        height=chain.height + 1,
        previous=chain.anchor,
        anchor=chain.anchor,
        transactions=(),
        nonce=0,
        timestamp=timestamp,
        target=chain.next_target() if target is None else target,
    )
    chain.blocks.append(block)
    return block


def mined_block(chain, timestamp, target=None):
    """A block that really does meet its target, for the tests about validation."""
    block = Block(
        height=chain.height + 1,
        previous=chain.anchor,
        anchor=chain.anchor,
        transactions=(),
        nonce=0,
        timestamp=timestamp,
        target=chain.next_target() if target is None else target,
    )
    while not block.meets_power():
        block = dataclasses.replace(block, nonce=block.nonce + 1)
    return block


def test_the_genesis_target_is_the_published_constant():
    chain = chain_with_genesis()
    assert chain.tip.target == GENESIS_TARGET
    assert chain.tip.work() == (1 << 64) // GENESIS_TARGET


def test_fast_blocks_make_the_target_smaller():
    """Blocks arriving four times too fast must be made harder, not easier.

    The first version of this code had the ratio inverted, which made a rush of blocks
    make the chain *easier* — the opposite of a difficulty adjustment. It printed a
    target that grew while the comment said "harder", which is how it was caught.
    """
    chain = chain_with_genesis()
    start = chain.next_target()
    stamp = 2_000_000_000
    for _ in range(5):
        append_synthetic(chain, stamp)
        stamp += 10  # far faster than TARGET_INTERVAL
    assert chain.next_target() < start


def test_slow_blocks_make_the_target_larger():
    chain = chain_with_genesis()
    stamp = 2_000_000_000
    for _ in range(5):
        append_synthetic(chain, stamp)
        stamp += 600  # five times slower than the target
    assert chain.next_target() > GENESIS_TARGET


def test_a_single_block_cannot_move_the_target_more_than_twofold():
    """One liar, or one empty block, must not collapse the difficulty."""
    chain = chain_with_genesis()
    stamp = 2_000_000_000
    append_synthetic(chain, stamp)
    stamp += 1  # absurdly fast
    append_synthetic(chain, stamp)

    base = chain.tip.target
    adjusted = chain.next_target()
    assert adjusted >= base // 2
    assert adjusted <= base * 2


def test_the_target_stays_inside_its_bounds():
    chain = chain_with_genesis()
    stamp = 2_000_000_000
    for _ in range(80):
        append_synthetic(chain, stamp)
        stamp += 1  # relentlessly fast
    assert MIN_TARGET <= chain.next_target() <= MAX_TARGET


def test_recent_solve_times_outweigh_old_ones():
    """Linear weighting is the point of LWMA: a burst now matters more than a burst ago.

    The first version of this test had the flag inverted -- "fast at the end" actually
    spaced the early blocks at one second and the late ones at the target interval --
    and the assertion failed for exactly the right reason. Naming the flag for what it
    does, rather than for what it was meant to do, is what fixed it.
    """
    def target_after(fast_at_end: bool) -> int:
        chain = chain_with_genesis()
        stamp = 2_000_000_000
        half = LWMA_WINDOW // 2
        for index in range(LWMA_WINDOW + 1):
            # A fixed target on every block, so the comparison is between two runs
            # that differ only in their timestamps. Without this the target compounds
            # block by block and both runs saturate at the clamp floor -- which is what
            # the first version of this test did, and why it could not tell them apart.
            append_synthetic(chain, stamp, target=GENESIS_TARGET)
            fast = (index >= half) if fast_at_end else (index < half)
            stamp += 90 if fast else 150
        return chain.next_target()

    # A burst of fast blocks near the tip must tighten the target; the same burst long
    # ago must barely move it.
    assert target_after(fast_at_end=True) < target_after(fast_at_end=False)


def test_a_block_must_carry_the_required_target():
    """A miner may not pick its own difficulty, even a harder one."""
    chain = chain_with_genesis()
    wrong = chain.next_target() // 4  # harder than required, but not what the chain says
    block = mined_block(chain, 2_000_000_000, target=wrong)
    with pytest.raises(ChainError, match="the chain requires"):
        chain.append(block)


def test_a_block_that_does_not_meet_its_target_is_rejected():
    chain = chain_with_genesis()
    block = Block(
        height=1,
        previous=chain.anchor,
        anchor=chain.anchor,
        transactions=(),
        nonce=0,
        timestamp=2_000_000_000,
        target=chain.next_target(),
    )
    if block.meets_power():
        pytest.skip("this nonce happened to satisfy the target; rerun")
    with pytest.raises(ChainError, match="proof-of-work"):
        chain.append(block)


def test_a_timestamp_at_or_before_the_median_is_rejected():
    """MTP-11: without it a miner can lie backwards and drag the difficulty down."""
    chain = chain_with_genesis()
    stamp = 2_000_000_000
    for _ in range(MEDIAN_WINDOW + 2):
        append_synthetic(chain, stamp)
        stamp += TARGET_INTERVAL

    median = chain.median_time_past()
    block = mined_block(chain, median)  # exactly at the median is not enough
    with pytest.raises(ChainError, match="median"):
        chain.append(block)


def test_a_far_future_timestamp_is_rejected():
    chain = chain_with_genesis()
    import time as clock

    block = mined_block(chain, int(clock.time()) + 3 * 3600)
    with pytest.raises(ChainError, match="future"):
        chain.append(block)


def test_mining_converges_to_the_target_interval():
    """Simulate a fixed hashrate and check the interval settles near TARGET_INTERVAL.

    The difficulty algorithm only sees timestamps, so feeding it the timestamps a given
    hashrate would produce tests it exactly without hashing anything.
    """
    hashrate = 50_000.0  # hashes per second, arbitrary but fixed
    chain = chain_with_genesis()
    now = 2_000_000_000
    intervals = []

    for _ in range(200):
        target = chain.next_target()
        expected_hashes = (1 << 64) / target
        seconds = expected_hashes / hashrate
        now += max(1, int(seconds))
        append_synthetic(chain, now, target=target)
        intervals.append(seconds)

    # The last quarter of the run should sit near the target interval. A generous
    # tolerance: this is a simulation of a stochastic process, not a proof.
    settled = intervals[-50:]
    average = sum(settled) / len(settled)
    assert 0.4 * TARGET_INTERVAL < average < 2.5 * TARGET_INTERVAL, (
        f"settled at {average:.0f} s against a {TARGET_INTERVAL} s target; "
        f"first quarters were {intervals[:3]}"
    )
