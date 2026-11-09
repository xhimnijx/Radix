"""The range proof's alpha-slot terms: construction, shape, and challenge drawing.

Deliberately not tested here: the cancellation condition. That is the verifier's equation,
and encoding it a second time in a helper would create exactly the two-places-disagree bug
this project has already paid for four times.
"""

import pytest

from radix_core.candidate_b.lattice import range_slots, ring
from radix_core.candidate_b.lattice.params import SMILE


def centred(poly):
    value = poly[0]
    return value - SMILE.modulus if value > SMILE.modulus // 2 else value


def bits(*values):
    return tuple(tuple([value] * 128) for value in values)


def test_psi_uses_one_minus_two_b():
    """psi = sum eta * a * (1 - 2b): at b = 0 it is a, at b = 1 it is -a.

    Constant polynomials, because the ring multiplies polynomials: `ring.mul` on a vector of
    fours is a convolution, not a scaling, and the first version of this test assumed the
    latter.
    """
    a = (ring.constant(4, SMILE),)
    eta = (ring.constant(1, SMILE),)
    at_zero = range_slots.psi_terms(a, bits(0), eta)
    at_one = range_slots.psi_terms(a, bits(1), eta)
    assert centred(at_zero) == 4
    assert centred(at_one) == -4


def test_omega_uses_a_squared():
    a = (ring.constant(3, SMILE),)
    eta = (ring.constant(1, SMILE),)
    assert range_slots.omega_terms(a, eta) == ring.constant(9, SMILE)


def test_the_number_of_terms_must_agree():
    a = (tuple([1] * 128), tuple([2] * 128))
    eta = (tuple([1] * 128),)
    with pytest.raises(range_slots.RangeSlotError, match="shape mismatch"):
        range_slots.psi_terms(a, bits(0, 1), eta)
    with pytest.raises(range_slots.RangeSlotError, match="shape mismatch"):
        range_slots.omega_terms(a, eta)


def test_challenges_are_drawn_in_order_and_are_independent():
    first = range_slots.challenge_from(b"seed", 3)
    second = range_slots.challenge_from(b"seed", 3)
    assert first == second, "the same seed must give the same challenges"
    assert len(first) == 3
    assert range_slots.challenge_from(b"other", 3) != first


def test_a_different_number_of_challenges_is_a_prefix():
    """Drawing three then two must not change the first two: the transcript is a stream."""
    three = range_slots.challenge_from(b"seed", 3)
    two = range_slots.challenge_from(b"seed", 2)
    assert two == three[:2]


def test_no_challenges_is_refused():
    with pytest.raises(range_slots.RangeSlotError, match="at least one"):
        range_slots.challenge_from(b"seed", 0)
