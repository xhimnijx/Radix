"""Block rewards, the treasury slice, and coinbase maturity.

Before this, mining paid nothing: a block settled the mempool and the miner received no
output, so the chain had no security budget and no reason for anyone to mine.

The maturity rule is enforced *structurally*: an immature key is not in the ring pool,
and a ring can only reference the pool. That matters because a ring signature hides
which member is real, so checking one specific output's age is impossible.

Every test mines with a **distinct key per block**, which is not a stylistic choice:
output identity is the hash of (key, value), so two rewards to one key with the same
value are one output, and the tag makes that key spendable once regardless. There is a
test at the bottom that asserts exactly that limitation.
"""

import pytest

from radix_core.candidate_b.lattice.spend import Output
from radix_testnet import params as P
from radix_testnet.chain import (
    SUPPLY_CAP_ATOMS,
    TAIL_END_BLOCKS,
    COINBASE_MATURITY,
    DECAY_BLOCKS,
    GENESIS_TIME,
    INITIAL_REWARD_ATOMS,
    TAIL_REWARD_ATOMS,
    TARGET_INTERVAL,
    TREASURY_BPS,
    Chain,
    ChainError,
    emission,
    output_id,
    split_reward,
)


def key_for(index: int):
    """A deterministic key that is genuinely distinct per index.

    The first version used `(index + i) % 13`, which repeats every thirteen blocks --
    so the reward key for height 1 reappeared at height 92, collided with it, and the
    maturity test could never see the first reward mature.
    """
    return tuple(
        tuple([(index * 7919 + component * 31) % 100003] * 128) for component in range(4)
    )


def build_chain():
    parameters = P.parameters()
    chain = Chain(parameters=parameters, depth=2, verify=lambda *a, **k: True)
    chain.genesis([(key_for(0), 1000)])
    return chain


def mine(chain, count, start=GENESIS_TIME):
    """Mine `count` blocks one target interval apart, each to a distinct key.

    The start must be near the genesis time. Genesis is stamped in 2023, so a first
    block stamped years later reports a huge solve time; that legitimately relaxes the
    difficulty and dominates the window for ninety blocks, which is correct behaviour
    and makes the chain unmineable in a test.
    """
    stamp = start
    keys = []
    for index in range(count):
        stamp += TARGET_INTERVAL
        key = key_for(100 + index)
        keys.append(key)
        chain.miner_key = key
        chain.mine(timestamp=stamp, allow_empty=True)
    return keys


# ---------------------------------------------------------------- emission
def test_emission_starts_at_the_initial_reward_and_floors_at_the_tail():
    assert emission(0) == INITIAL_REWARD_ATOMS
    assert emission(DECAY_BLOCKS) == TAIL_REWARD_ATOMS
    # The tail is flat from the end of the decay until the supply cap, and then stops. The old
    # version of this test asserted it at DECAY_BLOCKS * 10, which is past the cap -- that
    # assertion is what made the cap look compatible with a perpetual tail.
    assert emission((DECAY_BLOCKS + TAIL_END_BLOCKS) // 2) == TAIL_REWARD_ATOMS
    assert emission(TAIL_END_BLOCKS - 1) == TAIL_REWARD_ATOMS
    assert emission(TAIL_END_BLOCKS) == 0


def test_emission_never_increases():
    previous = emission(0)
    for height in range(1, DECAY_BLOCKS + 10, 997):
        current = emission(height)
        assert current <= previous, f"emission rose at height {height}"
        previous = current


def test_the_tail_stops_at_the_supply_cap():
    """It used to be called `test_the_tail_never_stops`, and that was the bug.

    A perpetual tail makes total supply unbounded. The supply cap is not a preference -- the
    balance argument is a congruence modulo q, so integer balance only follows below q/2. With a
    perpetual tail the cap was reached at height 1,000,104 and `check_supply` would have halted the
    chain there. The tail now ends exactly at the cap, so supply is bounded and the chain is not.
    """
    assert emission(DECAY_BLOCKS) == TAIL_REWARD_ATOMS > 0
    assert emission(TAIL_END_BLOCKS - 1) > 0
    assert emission(TAIL_END_BLOCKS) == 0
    assert emission(TAIL_END_BLOCKS * 100) == 0
    total = sum(emission(height) for height in range(1, TAIL_END_BLOCKS))
    assert total == SUPPLY_CAP_ATOMS, "the schedule must land exactly on the cap, not near it"


def test_the_treasury_takes_its_slice_and_the_miner_gets_the_rest():
    for height in (0, 1000, DECAY_BLOCKS):
        miner, treasury = split_reward(height)
        assert miner + treasury == emission(height)
        assert treasury == emission(height) * TREASURY_BPS // 10000


def test_a_negative_height_is_refused():
    with pytest.raises(ChainError):
        emission(-1)


# ----------------------------------------------------------------- reward
def test_a_block_pays_its_coinbase_recipient():
    chain = build_chain()
    assert chain.treasury == {}

    keys = mine(chain, 1)

    assert chain.height == 1
    miner_atoms, treasury_atoms = split_reward(1)
    identifier = output_id(Output(key=keys[0], value=miner_atoms))
    assert identifier in chain.outputs, "the miner was not paid"
    assert chain.treasury == {1: treasury_atoms}


def test_the_treasury_accumulates_over_blocks():
    chain = build_chain()
    mine(chain, 5)
    expected = sum(split_reward(h)[1] for h in range(1, 6))
    assert sum(chain.treasury.values()) == expected
    assert sorted(chain.treasury) == [1, 2, 3, 4, 5]


def test_genesis_pays_nobody():
    chain = build_chain()
    assert chain.treasury == {}
    assert chain.immature == {}
    assert len(chain.outputs) == 1  # only the genesis allocation


# ---------------------------------------------------------------- maturity
def test_a_reward_is_not_in_the_ring_pool_before_maturity():
    chain = build_chain()
    keys = mine(chain, 1)

    miner_atoms, _treasury = split_reward(1)
    identifier = output_id(Output(key=keys[0], value=miner_atoms))
    assert identifier in chain.immature
    assert keys[0] not in chain.pool


def test_a_reward_enters_the_pool_after_maturity():
    chain = build_chain()
    keys = mine(chain, COINBASE_MATURITY + 2)

    miner_atoms, _treasury = split_reward(1)
    identifier = output_id(Output(key=keys[0], value=miner_atoms))
    assert identifier not in chain.immature
    assert keys[0] in chain.pool


def test_maturity_is_counted_in_blocks_not_wall_time():
    """Timestamps are attacker-controlled; block depth is not."""
    chain = build_chain()
    keys = mine(chain, 5)
    miner_atoms, _treasury = split_reward(1)
    identifier = output_id(Output(key=keys[0], value=miner_atoms))

    assert identifier in chain.immature
    mine(chain, 3, start=GENESIS_TIME + 10 * TARGET_INTERVAL)
    assert identifier in chain.immature


def test_every_block_reward_is_fully_accounted():
    chain = build_chain()
    mine(chain, 6)

    mined = sum(split_reward(h)[0] for h in range(1, 7))
    treasury = sum(split_reward(h)[1] for h in range(1, 7))
    assert mined + treasury == sum(emission(h) for h in range(1, 7))
    assert sum(chain.treasury.values()) == treasury


def test_the_same_key_cannot_accumulate_two_rewards():
    """A documented limitation, asserted rather than papered over.

    Output identity is the hash of (key, value); a reward to the same key with the same
    value hashes identically, so two blocks paid to one key become one output. And
    because the tag is a function of the secret, that key is spendable once regardless.

    Fixing it needs one-time addressing. Until then a miner reusing one key accumulates
    one reward, not n -- which is why every other test here rotates keys.
    """
    chain = build_chain()
    shared = key_for(7)
    chain.miner_key = shared
    stamp = GENESIS_TIME
    for _ in range(3):
        stamp += TARGET_INTERVAL
        chain.mine(timestamp=stamp, allow_empty=True)

    rewards = [note for note in chain.outputs.values() if note.key == shared]
    assert len(rewards) == 1, "identical rewards to one key must collapse to one output"
