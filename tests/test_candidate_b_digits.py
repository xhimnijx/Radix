"""Base-4 digits and the packed binaryness constraint.

The claim under test is C2's correction to the cost of a range proof: because
`b(b-1) = 0` holds slotwise, one polynomial carries 32 bits and 64 bit-constraints per
amount cost two polynomials and two α challenges -- not sixty-four. If that were wrong,
hidden amounts would be roughly thirty times more expensive than the plan assumes, so it
is worth testing rather than believing.
"""

import pytest

from radix_core.candidate_b.lattice import digits
from radix_core.candidate_b.lattice.params import SMILE


# ------------------------------------------------------------- encoding
def test_an_amount_round_trips_through_base_4():
    for amount in (0, 1, 3, 4, 255, 4096, 2**32 - 1, 2**63, 4**32 - 1):
        assert digits.decode_amount(digits.encode_amount(amount)) == amount


def test_digits_are_in_range_for_the_largest_amount():
    encoded = digits.encode_amount(4**32 - 1)
    assert len(encoded) == 32
    assert set(encoded) == {3}


def test_an_amount_too_large_is_refused():
    with pytest.raises(digits.DigitError, match="does not fit"):
        digits.encode_amount(4**32)


def test_a_negative_amount_is_refused():
    with pytest.raises(digits.DigitError, match="non-negative"):
        digits.encode_amount(-1)


def test_an_out_of_range_digit_is_refused():
    bad = list(digits.encode_amount(1000))
    bad[5] = 4
    with pytest.raises(digits.DigitError, match="not in"):
        digits.decode_amount(tuple(bad))


# ----------------------------------------------------------------- bits
def test_bits_round_trip_through_the_digit_encoding():
    for amount in (0, 7, 1000, 2**40 + 12345):
        assert digits.amount_of(digits.bits_of(amount)) == amount


def test_a_bit_that_is_not_a_bit_is_refused():
    bits = list(digits.bits_of(9))
    bits[3] = 2
    with pytest.raises(digits.DigitError, match="must be 0 or 1"):
        digits.amount_of(tuple(bits))


# -------------------------------------------------------------- packing
def test_sixty_four_bits_fit_two_polynomials():
    """The whole point: 32 bits per polynomial, so 64 bits cost two."""
    bits = digits.bits_of(123456789)
    packed = digits.pack_bits(bits)

    assert len(packed) == 2, f"64 bits took {len(packed)} polynomials, expected 2"
    assert digits.slots(SMILE) == 32
    assert all(len(poly) == SMILE.ring_degree for poly in packed)


def test_packing_round_trips():
    for amount in (0, 5, 2**31 + 7, 4**32 - 1):
        bits = digits.bits_of(amount)
        assert digits.unpack_bits(digits.pack_bits(bits)) == bits


def test_every_packed_slot_is_constant_and_binary():
    packed = digits.pack_bits(digits.bits_of(0xDEADBEEF))
    assert digits.is_slot_binary(packed)

    for poly in packed:
        for slot in range(digits.slots(SMILE)):
            chunk = poly[slot * digits.SLOT_WIDTH : (slot + 1) * digits.SLOT_WIDTH]
            assert len(set(chunk)) == 1, f"slot {slot} is not constant"
            assert chunk[0] in (0, 1)


def test_a_non_constant_slot_is_rejected():
    """A slot with disagreeing coefficients is not a slot-constant, so `b(b-1)=0` says
    nothing about it and the packing is invalid."""
    packed = list(digits.pack_bits(digits.bits_of(42)))
    broken = list(packed[0])
    broken[1] = 1 - broken[1]  # make one slot disagree with itself
    packed[0] = tuple(broken)

    assert not digits.is_slot_binary(tuple(packed))
    with pytest.raises(digits.DigitError, match="not constant"):
        digits.unpack_bits(tuple(packed))


def test_a_slot_holding_two_is_rejected():
    """`b` must be a bit. A slot holding 2 satisfies nothing and would break the
    digit range, which is exactly what the constraint exists to prevent."""
    packed = list(digits.pack_bits(digits.bits_of(1)))
    broken = list(packed[0])
    for index in range(digits.SLOT_WIDTH):
        broken[index] = 2
    packed[0] = tuple(broken)

    assert not digits.is_slot_binary(tuple(packed))


# ---------------------------------------------------------------- budget
def test_the_alpha_budget_is_per_vector():
    """C2's correction, asserted: three α for one amount, not sixty-four."""
    assert digits.constraint_count(1) == 3
    assert digits.constraint_count(2) == 5
    assert digits.constraint_count(4) == 9


def test_the_alpha_budget_is_far_below_the_naive_count():
    """If this ever regresses to one constraint per bit, hidden amounts get ~30x worse."""
    naive = digits.BITS * 4  # 64 bits per amount, four amounts
    assert digits.constraint_count(4) < naive / 20
