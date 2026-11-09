"""The range statement, as one verifier.

This is the specification the α-slot proof will have to reproduce: every amount in range,
and the totals balancing with an explicit carry. It sees the witness in the clear, so it
proves nothing on its own — it exists so the proof's obligations are written down and
tested before the layout is attempted.
"""

import pytest

from radix_core.candidate_b.lattice import carry as C
from radix_core.candidate_b.lattice import digits as D
from radix_core.candidate_b.lattice import range as R


def honest_carry(inputs, outputs, fee):
    """The carry a prover would send: computed by long addition in base 4."""
    total_in = sum(inputs)
    total_out = sum(outputs) + fee
    if total_in != total_out:
        raise ValueError("the test asked for an unbalanced statement")
    into = C.digit_poly(D.encode_amount(total_in))
    outof = C.digit_poly(D.encode_amount(total_out))
    return into, outof


def test_a_balanced_statement_verifies():
    inputs = [600, 500]
    outputs = [1000]
    fee = 100
    into, outof = honest_carry(inputs, outputs, fee)
    # The difference of the two totals is zero, so the carry of the whole statement is
    # the zero polynomial: the digits already add without carrying.
    zero = tuple([0] * 128)
    assert R.verify(inputs, outputs, fee, zero)


def test_an_unbalanced_statement_is_refused():
    """Amounts individually in range, and the transaction still mints."""
    zero = tuple([0] * 128)
    assert R.verify([600, 500], [1000], 200, zero) is False


def test_an_amount_out_of_range_is_refused():
    """4^32 does not fit 32 base-4 digits, so it cannot be encoded and cannot verify."""
    zero = tuple([0] * 128)
    assert R.verify([4**32], [], 0, zero) is False


def test_digits_are_checked_against_their_bits():
    statement = R.build([1234])
    # Corrupt a digit without touching the bits: the tie between the two must fail.
    broken = dict(statement)
    broken["digits"] = [tuple([0] * 32)]
    assert R.verify_digits(broken) is False


def test_a_non_binary_bit_is_refused():
    statement = R.build([1234])
    broken = dict(statement)
    bits = list(broken["bits"][0])
    bits[0] = 2
    broken["bits"] = [tuple(bits)]
    assert R.verify_digits(broken) is False


def test_the_statement_carries_the_alpha_budget():
    statement = R.build([1, 2, 3])
    assert statement["alpha_count"] == D.constraint_count(3)
    assert R.alpha_budget(3) == 7


def test_the_carry_bounds_the_number_of_inputs():
    """A carry is at most the number of terms added, which is why many inputs need the
    relaxed bound rather than a bit constraint."""
    for count in (2, 3, 5):
        inputs = [1] * count
        total = sum(inputs)
        left = C.digit_poly(D.encode_amount(inputs[0]))
        right = C.digit_poly(D.encode_amount(total - inputs[0]))
        f = C.addition_carry(left, right, C.digit_poly(D.encode_amount(total)))
        assert C.bound(f) <= 1, "two-term addition must stay binary"


def test_an_empty_input_list_is_refused():
    assert R.verify([], [100], 0, tuple([0] * 128)) is False


def test_a_negative_fee_is_refused():
    assert R.verify([100], [], -1, tuple([0] * 128)) is False
