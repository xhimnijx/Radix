import pytest

from radix_core.encoding import U64_MAX
from radix_core.monetary import (
    PROPOSED_BASE_UNITS_PER_RAD,
    PROPOSED_BLOCKS_PER_EPOCH,
    PROPOSED_INITIAL_SUBSIDY,
    PROPOSED_SUBSIDY_BY_EPOCH,
    PROPOSED_TAIL_EPOCH,
    PROPOSED_TAIL_SUBSIDY,
    proposed_cumulative_subsidy_before_height_v1,
    proposed_subsidy_at_height_v1,
)


def test_proposed_subsidy_uses_exact_integer_epoch_boundaries():
    assert PROPOSED_INITIAL_SUBSIDY == 10_000_000_000_000
    assert proposed_subsidy_at_height_v1(0) == PROPOSED_INITIAL_SUBSIDY
    assert proposed_subsidy_at_height_v1(719) == PROPOSED_INITIAL_SUBSIDY
    assert proposed_subsidy_at_height_v1(720) == 9_995_250_000_000
    assert proposed_subsidy_at_height_v1(1440) == 9_990_502_256_250


def test_proposed_schedule_reaches_tail_at_exact_first_epoch():
    assert PROPOSED_TAIL_EPOCH == 9693
    assert PROPOSED_TAIL_EPOCH * PROPOSED_BLOCKS_PER_EPOCH == 6_978_960
    assert PROPOSED_SUBSIDY_BY_EPOCH[-2] == 100_037_652_128
    assert PROPOSED_SUBSIDY_BY_EPOCH[-1] == PROPOSED_TAIL_SUBSIDY == 100_000_000_000
    assert proposed_subsidy_at_height_v1(6_978_959) == 100_037_652_128
    assert proposed_subsidy_at_height_v1(6_978_960) == PROPOSED_TAIL_SUBSIDY
    assert proposed_subsidy_at_height_v1(U64_MAX) == PROPOSED_TAIL_SUBSIDY


def test_proposed_cumulative_supply_counts_partial_and_tail_epochs_exactly():
    assert proposed_cumulative_subsidy_before_height_v1(0) == 0
    assert proposed_cumulative_subsidy_before_height_v1(1) == PROPOSED_INITIAL_SUBSIDY
    assert proposed_cumulative_subsidy_before_height_v1(720) == 720 * PROPOSED_INITIAL_SUBSIDY
    assert proposed_cumulative_subsidy_before_height_v1(721) == (
        720 * PROPOSED_INITIAL_SUBSIDY + 9_995_250_000_000
    )
    assert proposed_cumulative_subsidy_before_height_v1(6_978_960) == (
        15_006_330_736_512_179_040
    )
    assert proposed_cumulative_subsidy_before_height_v1(1 << 64) == (
        1_844_674_407_385_263_596_336_512_179_040
    )
    # At a constant 120-second target, a 0.1 RAD tail emits 26,280 RAD/year.
    blocks_per_year = 365 * 24 * 60 * 60 // 120
    assert blocks_per_year * PROPOSED_TAIL_SUBSIDY == 26_280 * PROPOSED_BASE_UNITS_PER_RAD
    assert (
        proposed_cumulative_subsidy_before_height_v1(U64_MAX)
        + proposed_subsidy_at_height_v1(U64_MAX)
        == proposed_cumulative_subsidy_before_height_v1(1 << 64)
    )


@pytest.mark.parametrize("height", [True, -1, U64_MAX + 1, 1.0])
def test_proposed_subsidy_rejects_non_u64_height(height):
    with pytest.raises(ValueError, match="U64"):
        proposed_subsidy_at_height_v1(height)


@pytest.mark.parametrize("height", [True, -1, (1 << 64) + 1, 1.0])
def test_proposed_cumulative_subsidy_rejects_invalid_exclusive_height(height):
    with pytest.raises(ValueError, match="exclusive height"):
        proposed_cumulative_subsidy_before_height_v1(height)
