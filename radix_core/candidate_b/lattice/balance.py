"""The balance statement: a spend proves its amounts add up without revealing them.

The relation a transaction actually needs, in one line:

    sum(inputs) - sum(outputs) - fee = carry * (X - 4)

Why that is the right identity: evaluating a digit polynomial at `X = 4` recovers its integer,
so if the integers balance then the difference of the polynomials vanishes at `X = 4`, and
therefore `(X - 4)` divides it exactly. The quotient is the carry. This is [25] p. 4
generalised from two terms to `m`, and it is what `carry.py` implements for the two-term case.

Two things make it cheap:

- **Digits are linear in the bits.** `d_i = 2*hi_i + lo_i` and `from_constants` is linear, so
  a digit polynomial is `2*hi + lo` for free -- the balance can be written directly over the
  bit planes, with no committed digit row.
- **The carry is a ring multiplication.** Carrying in base 4 is multiplication by `(X - 4)`,
  which is just a polynomial weight in a `LinearRelation`.

Row layout, and `prove` must receive rows in this order:

    range rows   2 per amount (low half, high half of the 64 bits), then the carry's planes
    carry rows   1: the carry polynomial

Negative positions in a relation index range rows first, then carry rows.
"""

from __future__ import annotations

from radix_core.candidate_b.lattice import carry as C
from radix_core.candidate_b.lattice import digits as D
from radix_core.candidate_b.lattice import ring, setmembership as S, subring
from radix_core.candidate_b.lattice.params import SMILE, SmileParameters


class BalanceError(ValueError):
    """A balance statement is malformed, or the amounts do not add up."""


def bit_width(bound: int) -> int:
    """Bits needed to represent a value in `[0, bound]`."""
    if bound < 0:
        raise BalanceError("a bound must not be negative")
    width = 1
    while (1 << width) <= bound:
        width += 1
    return width


def x_minus_base(parameters: SmileParameters = SMILE) -> tuple:
    """The polynomial `X - 4`, which carries in base 4 multiply by."""
    values = list(ring.zero(parameters))
    values[0] = (-4) % parameters.modulus
    values[1] = 1
    return tuple(values)


def divide_by_x_minus_base(poly: tuple, parameters: SmileParameters = SMILE) -> tuple:
    """The quotient of `poly` by `(X - 4)`, or a refusal if it does not divide exactly.

    Synthetic division from the top coefficient down, using `f_k*(X-4)` having coefficient
    `f_{k-1} - 4 f_k` at `X^k`.
    """
    degree = len(poly)
    signed = []
    half = parameters.modulus // 2
    for value in poly:
        signed.append(value - parameters.modulus if value > half else value)

    quotient = [0] * degree
    running = 0
    for index in range(degree - 1, 0, -1):
        # coefficient of X^index in poly is (f_{index-1} - 4 f_index)
        running = signed[index] + 4 * running
        quotient[index - 1] = running
    if signed[0] != -4 * quotient[0]:
        raise BalanceError("the difference does not divide by (X - 4), so the amounts do not balance")
    if any(value for value in quotient[degree - 1 :]):
        raise BalanceError("the quotient has non-zero coefficients above the ring degree")
    return tuple(value % parameters.modulus for value in quotient)


def _pack(flat: list[int], parameters: SmileParameters) -> tuple:
    padded = list(flat) + [0] * (-len(flat) % 32)
    return tuple(
        subring.from_constants(tuple(padded[start : start + 32]), parameters)
        for start in range(0, len(padded), 32)
    )


def _half_planes(amount: int, parameters: SmileParameters) -> tuple:
    """The two packed bit polynomials for one amount: bits 0..31 and 32..63."""
    bits = D.bits_of(amount, D.DIGITS)
    return (
        _pack([bits[position] for position in range(32)], parameters),
        _pack([bits[position] for position in range(32, 64)], parameters),
    )


def _digit_difference(inputs: list[int], outputs: list[int], fee: int,
                      parameters: SmileParameters) -> tuple:
    total = [0] * parameters.ring_degree
    for amount in inputs:
        for index, value in enumerate(C.digit_poly(D.encode_amount(amount, D.DIGITS))):
            total[index] += value
    for amount in list(outputs) + [fee]:
        for index, value in enumerate(C.digit_poly(D.encode_amount(amount, D.DIGITS))):
            total[index] -= value
    half = parameters.modulus // 2
    return tuple(
        (value % parameters.modulus) if value >= 0 else (value + parameters.modulus) % parameters.modulus
        for value in total
    )


def build(inputs: list[int], outputs: list[int], fee: int,
          parameters: SmileParameters = SMILE) -> dict:
    """The witness for a spend, or a refusal if the amounts do not balance."""
    if not inputs:
        raise BalanceError("a spend needs at least one input")
    if any(amount < 0 for amount in inputs + outputs) or fee < 0:
        raise BalanceError("amounts and the fee must not be negative")

    amounts = list(inputs) + list(outputs)
    carry_poly = divide_by_x_minus_base(
        _digit_difference(inputs, outputs, fee, parameters), parameters
    )
    carry_values = [
        value - parameters.modulus if value > parameters.modulus // 2 else value
        for value in carry_poly
    ]
    bound = max((abs(value) for value in carry_values), default=0)
    if bound > len(inputs):
        raise BalanceError(
            f"the carry reaches {bound}, above the input count {len(inputs)}; the "
            "decomposition below assumes it does not"
        )

    bits_needed = bit_width(bound)
    if bits_needed > 2:
        raise BalanceError(
            f"a carry of {bound} needs {bits_needed} bits and this packing carries two"
        )

    range_bits: list = []
    for amount in amounts:
        low_half, high_half = _half_planes(amount, parameters)
        range_bits.extend((low_half[0], high_half[0]))

    # The carry's own bit planes, so it is shown to be bounded rather than assumed.
    carry_low = _pack([(value & 1) for value in carry_values], parameters)
    carry_high = _pack([((value >> 1) & 1) for value in carry_values], parameters)
    range_bits.extend(carry_low)
    range_bits.extend(carry_high)

    return {
        "range_bits": tuple(range_bits),
        "carry_bits": (subring.from_constants(tuple(carry_values), parameters),),
        "carry_bound": bound,
        "amounts": amounts,
        "range_count": len(range_bits),
    }


# `relations` was removed rather than shipped, and the reason is worth recording because it is
# a real gap between the paper and this implementation rather than a bug.
#
# The binaryness check requires messages that are **constant in each CRT slot**: that is what
# makes `b*b = b` hold, and `digits.pack_bits` builds them that way.
#
# The carrying identity requires multiplication by `(X - 4)` in the **coefficient** domain:
# evaluating a coefficient-domain digit polynomial at `X = 4` recovers its integer, and that is
# the whole reason `(X - 4)` divides the difference.
#
# Those are not the same subspace. Multiplying a slot-constant polynomial by `(X - 4)` leaves
# the slot-constant subspace -- verified: a slot-constant 1 in slot 0 becomes `(-4, 1, 0, 0)`
# in that slot -- so a balance relation written over the bit planes is not the identity it
# looks like, and would verify while meaning nothing.
#
# Resolving it needs a decision this implementation cannot make for itself: either the amounts
# are committed in the coefficient domain and their range is proven some other way (the
# paper's `d in {0,1,2,3}` per coefficient is a quartic membership test, which the quadratic
# alpha machinery does not express), or the digits are encoded one per slot and the carry is
# handled slot-wise. The two packings in this codebase are each sound alone and do not compose.
#
# `build` below is unaffected: computing the carry and refusing an unbalanced spend are sound
# in the coefficient domain, and both are tested.
