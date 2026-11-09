"""Base-4 addition with an explicit carry.

This is the relation `[25]` gives on p. 4 and SMILE specialises to base 4:

    a + b + f·(X - 4) = c

The tests check the two things that make it meaningful: the identity holds coefficient by
coefficient (not merely by evaluation), and a tampered total is refused. They also check
the bound on the carry, because whether the carry is binary decides between a bit
decomposition and the relaxed range proof — and for two terms it is binary.
"""

import pytest

from radix_core.candidate_b.lattice import carry, digits


def polys(left_amount, right_amount, total_amount=None, digits_count=32):
    total_amount = left_amount + right_amount if total_amount is None else total_amount
    return (
        carry.digit_poly(digits.encode_amount(left_amount, digits_count)),
        carry.digit_poly(digits.encode_amount(right_amount, digits_count)),
        carry.digit_poly(digits.encode_amount(total_amount, digits_count)),
    )


def test_a_digit_polynomial_evaluates_back_to_its_integer():
    for amount in (0, 7, 255, 4096, 2**32 + 3):
        poly = carry.digit_poly(digits.encode_amount(amount))
        assert carry.evaluate(poly) == amount


def test_addition_with_carry_holds_coefficient_by_coefficient():
    left, right, total = polys(1000, 2000)
    f = carry.addition_carry(left, right, total)
    assert carry.holds(left, right, total, f)


def test_the_relation_is_checked_as_polynomials_not_by_evaluation():
    """Evaluation at one point cannot tell two polynomials apart; the check can.

    The perturbation below adds `(X - 4)` to the carry, which vanishes at `X = 4` and
    therefore leaves the *evaluated* identity intact. A check that only evaluated would
    accept it; the coefficient-wise check rejects it, which is why the relation is stated
    over polynomials.
    """
    left, right, total = polys(123, 456)
    f = carry.addition_carry(left, right, total)
    assert carry.holds(left, right, total, f)

    perturbed = list(f)
    perturbed[0] -= carry.BASE   # -4
    perturbed[1] += 1            # +X
    assert carry.evaluate(tuple(perturbed)) == carry.evaluate(f), "the perturbation must vanish at X=4"
    assert carry.holds(left, right, total, tuple(perturbed)) is False


def test_a_tampered_total_is_refused():
    left, right, _total = polys(500, 500)
    wrong_total = carry.digit_poly(digits.encode_amount(1001))
    f = carry.addition_carry(left, right, carry.digit_poly(digits.encode_amount(1000)))
    assert carry.holds(left, right, wrong_total, f) is False


def test_the_carry_for_two_terms_is_binary():
    """Which is why adding two amounts needs no relaxed proof -- only summing many does."""
    for left_amount, right_amount in ((999, 1), (1234, 8766), (65535, 1)):
        left, right, total = polys(left_amount, right_amount)
        f = carry.addition_carry(left, right, total)
        assert carry.bound(f) <= 1, (
            f"carry for {left_amount}+{right_amount} reached {carry.bound(f)}, "
            "which would need the relaxed proof rather than a binary constraint"
        )


def test_an_inconsistent_addition_cannot_produce_a_carry():
    left, right, _ = polys(10, 20)
    wrong_total = carry.digit_poly(digits.encode_amount(31))
    with pytest.raises(carry.CarryError, match="!="):
        carry.addition_carry(left, right, wrong_total)


def test_a_digit_out_of_range_is_refused():
    with pytest.raises(carry.CarryError, match="not in"):
        carry.digit_poly((4,) + (0,) * 31)
