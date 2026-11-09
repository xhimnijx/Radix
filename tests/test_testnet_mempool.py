"""Mempool policy and fees.

Before this, a fee was a number the sender typed: nothing rejected a zero fee, nothing
bounded the mempool, and the miner received none of it. That is a chain where a free
transaction is indistinguishable from a paid one and a block producer is paid only by the
emission.

The policy is written as pure functions in `chain.py` so it can be tested without
producing a proof — a real tagged spend costs about a minute, which would make a rule
about fee ordering untestable in practice.
"""

import pytest

from radix_testnet.chain import (
    MEMPOOL_MAX,
    MIN_FEE_ATOMS,
    TREASURY_BPS,
    ChainError,
    admit,
    block_reward,
    emission,
    fee_rate,
    split_reward,
)


def full_mempool(fee: int = 1):
    """A mempool at capacity, every entry identical and cheap."""
    return {bytes([index]): {"fee": fee, "blob": "x" * 100} for index in range(MEMPOOL_MAX)}


# ------------------------------------------------------------------ fees
def test_a_zero_fee_is_refused():
    """A free transaction is a denial of service with extra steps."""
    with pytest.raises(ChainError, match="below the minimum"):
        admit({}, b"tx", {"fee": 0}, 0, 100)


def test_a_fee_below_the_minimum_is_refused():
    admit({}, b"tx", {"fee": MIN_FEE_ATOMS}, MIN_FEE_ATOMS, 100)
    with pytest.raises(ChainError, match="below the minimum"):
        admit({}, b"tx2", {"fee": MIN_FEE_ATOMS - 1}, MIN_FEE_ATOMS - 1, 100)


def test_a_duplicate_is_refused():
    mempool = {}
    admit(mempool, b"tx", {"fee": 5}, 5, 100)
    with pytest.raises(ChainError, match="already in the mempool"):
        admit(mempool, b"tx", {"fee": 5}, 5, 100)


def test_fee_rate_is_atoms_per_byte():
    assert fee_rate(100, 50) == 2.0
    assert fee_rate(100, 200) == 0.5
    assert fee_rate(100, 0) == 100.0  # a zero size cannot divide by zero


# -------------------------------------------------------------- eviction
def test_a_full_mempool_evicts_the_cheapest():
    mempool = full_mempool(fee=1)
    evicted = admit(mempool, b"better", {"fee": 500, "blob": "x" * 100}, 500, 100)

    assert evicted is not None
    assert len(mempool) == MEMPOOL_MAX, "the pool must stay at its cap"
    assert b"better" in mempool
    assert evicted not in mempool


def test_a_worse_fee_rate_is_refused_when_the_pool_is_full():
    """Otherwise a flood of cheap transactions could displace expensive ones."""
    mempool = full_mempool(fee=10)
    with pytest.raises(ChainError, match="not better than the cheapest"):
        admit(mempool, b"worse", {"fee": 1, "blob": "x" * 100}, 1, 100)

    assert len(mempool) == MEMPOOL_MAX
    assert b"worse" not in mempool


def test_eviction_is_by_rate_not_by_absolute_fee():
    """A large cheap transaction must not outrank a small expensive one."""
    mempool = {
        b"big": {"fee": 100, "blob": "x" * 1000},    # 0.1 atoms/byte
        b"small": {"fee": 50, "blob": "x" * 100},    # 0.5 atoms/byte
    }
    # Fill to one below the cap so the next admission has to choose.
    for index in range(MEMPOOL_MAX - 2):
        mempool[bytes([index])] = {"fee": 100, "blob": "x" * 1000}

    evicted = admit(mempool, b"winner", {"fee": 200, "blob": "x" * 100}, 200, 100)

    assert evicted == b"big", "the worst rate must go, not the smallest fee"


# ----------------------------------------------------------------- reward
def test_fees_go_to_the_miner_and_not_to_the_treasury():
    miner, treasury = block_reward(1, 500)
    miner_only, treasury_only = split_reward(1)

    assert miner == miner_only + 500
    assert treasury == treasury_only, "the treasury takes its slice of the emission only"
    assert treasury == emission(1) * TREASURY_BPS // 10000


def test_a_block_with_no_fees_pays_exactly_the_emission():
    miner, treasury = block_reward(1000, 0)
    assert miner + treasury == emission(1000)


def test_a_negative_fee_cannot_reduce_the_reward():
    """Defensive: the fee comes off the wire, so it must not be able to go negative."""
    miner, _treasury = block_reward(1, -1000)
    miner_only, _ = split_reward(1)
    assert miner == miner_only
