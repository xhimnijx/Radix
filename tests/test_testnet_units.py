"""D4: one source of truth for what an atom is.

The plan asks for a frozen constant table in one code location, and for the cap to be a soundness
bound rather than a preference. These tests pin both: the numbers, the relationship between them,
and the fact that the cap is derived from the modulus rather than picked.
"""

import pytest

from radix_testnet import chain as C
from radix_testnet import units


def test_the_decimals_and_the_unit_agree():
    assert units.ATOMS_PER_UNIT == 10 ** units.DECIMALS


def test_the_supply_cap_is_the_chain_cap():
    """One location: the chain must not carry a second copy that can drift."""
    assert units.SUPPLY_CAP_ATOMS == C.SUPPLY_CAP_ATOMS


def test_the_cap_is_below_the_modulus_bound_with_room():
    assert units.MAX_SOUND_ATOMS == C.SMILE.modulus // 2
    assert units.SUPPLY_CAP_ATOMS < units.MAX_SOUND_ATOMS
    headroom = units.MAX_SOUND_ATOMS / units.SUPPLY_CAP_ATOMS
    assert headroom > 3.5, f"only {headroom:.2f}x headroom under q/2"


def test_the_whole_emission_schedule_lands_exactly_on_the_cap():
    """Not merely below it: exactly on it, because the tail is cut where the cap is reached.

    A perpetual tail and a hard cap are incompatible -- the original schedule hit the cap at height
    1,000,104 (about 3.8 years) and `check_supply` would have halted the chain there. Ending the
    tail at the cap makes supply bounded and the cap exact.
    """
    total = sum(C.emission(height) for height in range(1, C.TAIL_END_BLOCKS + 10_000))
    assert total == units.SUPPLY_CAP_ATOMS
    assert C.emission(C.TAIL_END_BLOCKS) == 0, "the tail must stop at the cap"
    assert C.emission(C.TAIL_END_BLOCKS - 1) == C.TAIL_REWARD_ATOMS


def test_formatting_never_goes_through_a_float():
    assert units.format_atoms(0) == "0.00"
    assert units.format_atoms(1) == "0.01"
    assert units.format_atoms(100) == "1.00"
    assert units.format_atoms(12_345) == "123.45"
    assert units.format_atoms(-12_345) == "-123.45"


def test_conversions_round_trip():
    for atoms in (0, 1, 99, 100, 101, 570_100_000):
        assert units.atoms_of(units.units_of(atoms)) == atoms


def test_a_fractional_atom_is_refused():
    with pytest.raises(ValueError, match="whole number of atoms"):
        units.atoms_of(1.001)
