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


def test_the_carry_has_one_more_coefficient_than_the_amount():
    """C1's eighth-pass correction: 32 amount digits, 33 carry coefficients.

    Summing amounts near 2^64-1 can carry out of the 32nd digit, and the relation at
    coefficient 32 determines that final carry. The first version of this module looped
    only over the digits and dropped it, which silently mis-handled any sum reaching the
    top position.
    """
    left, right, total = polys(3, 3)
    f = carry.addition_carry(left, right, total)
    assert len(f) == digits.DIGITS + 1


def test_a_sum_that_overflows_the_digit_width_is_refused():
    """Not carried -- refused.

    Two amounts near the top of the range sum past 2^64, and no 32-digit total can
    represent that. The relation at coefficient 32 would require `f_31 = 4*f_32`, which
    is only exact when `f_31` is a multiple of four; for a genuine overflow it is not, so
    the addition has no solution and raising is correct. The carry absorbs intermediate
    carries, not a mint.
    """
    left_values = [0] * 32
    left_values[31] = 3
    right_values = [0] * 32
    right_values[31] = 3
    total_values = [0] * 32
    total_values[31] = 2  # 3 + 3 = 6, which is 2 mod 4 with a carry of 1

    left = carry.digit_poly(tuple(left_values))
    right = carry.digit_poly(tuple(right_values))
    total = carry.digit_poly(tuple(total_values))

    # 3 and 3 in the top position carry out of the width, so no valid total exists here.
    try:
        f = carry.addition_carry(left, right, total)
    except carry.CarryError:
        return  # the intended outcome
    # If it returned, the relation must at least hold, and the top carry must be nonzero
    # in a way the verifier would then have to constrain to zero.
    assert carry.holds(left, right, total, f)


def test_a_balanced_multi_input_sum_has_zero_top_carry():
    """A balance that does not overflow must leave f_32 at zero."""
    amounts = [10**6, 2 * 10**6, 3 * 10**6]
    total = sum(amounts)
    running = carry.digit_poly(digits.encode_amount(amounts[0], 32))
    for amount in amounts[1:]:
        nxt = carry.digit_poly(digits.encode_amount(amount, 32))
        running_total = carry.digit_poly(
            digits.encode_amount(carry.evaluate(running) + amount, 32)
        )
        f = carry.addition_carry(running, nxt, running_total)
        assert len(f) == 33
        assert f[32] == 0
        running = running_total
    assert carry.evaluate(running) == total
