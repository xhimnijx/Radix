"""Base-4 digits and the packed binaryness constraint.

The claim under test is C2's correction to the cost of a range proof: because
`b(b-1) = 0` holds slotwise, one polynomial carries 32 bits and 64 bit-constraints per
amount cost two polynomials and two α challenges -- not sixty-four. If that were wrong,
hidden amounts would be roughly thirty times more expensive than the plan assumes, so it
is worth testing rather than believing.
"""

import pytest

from radix_core.candidate_b.lattice import digits, ring, subring
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


def test_every_packed_slot_is_a_binary_constant_in_the_crt():
    """The property the proof consumes, not a proxy for it.

    `b*b = b` in the ring is what makes `f^2 + c*f = 0` certify binaryness, and it holds
    only when every CRT slot value is 0 or 1. The earlier version of this test checked
    coefficient blocks instead, which the ring does not multiply in: it passed while
    `b*b != b`, so the verifier would have certified nothing.
    """
    packed = digits.pack_bits(digits.bits_of(0xDEADBEEF))
    assert digits.is_slot_binary(packed)

    for poly in packed:
        assert ring.mul(poly, poly, SMILE) == poly, "b*b != b, so the check proves nothing"
        for slot, element in enumerate(subring.slots(poly, SMILE)):
            assert element[1:] == (0, 0, 0), f"slot {slot} is not a constant: {element}"
            assert element[0] in (0, 1), f"slot {slot} holds {element[0]}"


def test_a_non_constant_slot_is_rejected():
    """A slot whose value is not a scalar is not binary, so `b(b-1)=0` says nothing.

    Built by adding `X`, whose CRT slots are not constant, rather than by editing a
    coefficient block -- the block representation is not where multiplication lives.
    """
    packed = list(digits.pack_bits(digits.bits_of(42)))
    x_poly = tuple(1 if index == 1 else 0 for index in range(SMILE.ring_degree))
    packed[0] = ring.add(packed[0], x_poly, SMILE)

    assert not digits.is_slot_binary(tuple(packed))
    with pytest.raises(digits.DigitError, match="not a constant"):
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
    """Both reviewers' eighth-pass correction: TWO α per amount, not sixty-four.

    The two bit-polynomials need independent α challenges -- folding one into an existing
    α gives α(v² − v + b² − b) = 0, which a prover satisfies with v² − v = −(b² − b) and
    so breaks the selector. The digit and carry relations are linear and need none.
    """
    assert digits.constraint_count(1) == 2
    assert digits.constraint_count(2) == 4
    assert digits.constraint_count(4) == 8


def test_the_alpha_budget_is_far_below_the_naive_count():
    """If this ever regresses to one constraint per bit, hidden amounts get ~30x worse."""
    naive = digits.BITS * 4  # 64 bits per amount, four amounts
    assert digits.constraint_count(4) < naive / 20
