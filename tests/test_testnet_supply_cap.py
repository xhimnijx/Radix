"""The supply cap, as a consensus rule rather than a sentence in a document.

C1's ninth-pass verdict made the cap load-bearing: the trace pairing
`Tr(w4*m_in) = Tr(w4*m_out) + fee` holds modulo `q`, so the integer difference is a multiple of
`q` and is zero only if both totals stay below `q/2`. A documented cap is not a proof; the chain
has to enforce one, and it has to be below `q/2 = 2^31`.

Measured: the emission schedule totals **570,093,820 atoms** = 2^29.1, a factor of 7.5 below the
bound. So the cap is comfortable rather than marginal, and it is a property the schedule already
had rather than one it had to be given.
"""

import tempfile

import pytest

from radix_testnet import chain as C
from radix_testnet import params as P
from radix_core.candidate_b.lattice.params import SMILE


def test_the_cap_is_below_half_the_modulus():
    """The condition the balance argument needs, asserted rather than assumed."""
    assert C.SUPPLY_CAP_ATOMS < SMILE.modulus // 2, (
        "a cap at or above q/2 makes the trace-paired balance unsound, because the integer "
        "difference could be a non-zero multiple of q"
    )


def test_the_whole_schedule_fits_under_the_cap():
    """Every atom the schedule can ever emit, summed, must fit."""
    total = 0
    for height in range(1, C.DECAY_BLOCKS + 1000):
        total += C.emission(height)
    assert total <= C.SUPPLY_CAP_ATOMS, (
        f"the schedule emits {total} atoms, above the cap of {C.SUPPLY_CAP_ATOMS}"
    )


def test_the_cap_is_refused_above_the_bound():
    with pytest.raises(C.ChainError, match="supply cap exceeded"):
        C.check_supply(C.SUPPLY_CAP_ATOMS + 1)


def test_the_cap_accepts_exactly_the_bound():
    C.check_supply(C.SUPPLY_CAP_ATOMS)          # must not raise


def test_a_negative_mint_is_refused():
    with pytest.raises(C.ChainError, match="not be negative"):
        C.check_supply(-1)


def test_applying_blocks_accumulates_the_minted_total():
    """The count is incremented on the application path, not derived on demand."""
    parameters = P.parameters()
    chain = C.Chain(parameters=parameters, depth=2, verify=lambda *a, **k: True)
    chain.genesis(P.genesis_allocations(parameters))

    assert chain.minted == 0, "genesis mints nothing"

    stamp = C.GENESIS_TIME
    for index in range(3):
        stamp += C.TARGET_INTERVAL
        chain.miner_key = tuple(tuple([index + 1] * 128) for _ in range(4))
        chain.mine(timestamp=stamp, allow_empty=True)

    expected = sum(C.emission(height) for height in range(1, chain.height + 1))
    assert chain.minted == expected
