"""Base-4 addition with an explicit carry: the relation balance rests on.

`docs/CONFIDENTIAL-TRANSACTIONS.md` §5 stops at the carry. Reference [25] p. 4 gives the
relation, and this module implements it at `r = 4`:

    a + b + f·(X - 4) = c        as polynomials over Z, not just over Z_q

where `a`, `b`, `c` are the base-4 digit polynomials of the integers and `f` is the carry.
The reason the identity is written with `(X - 4)` and not `(X - 2)` is the base: at base
`r`, `X = r` is the evaluation that turns a digit polynomial back into its integer, so
`(a + b - c)(4) = 0` and the difference is divisible by `(X - 4)`.

Two things follow, and both are the point:

1. **The carry for a two-term addition is small but not always binary.** Adding two base-4
   digits gives at most 6, so a carry is at most 1 — it *is* binary for two terms. Summing
   `m` amounts is what makes it non-binary, and that is what the relaxed range proof from
   `relaxed.py` bounds instead of a bit decomposition.
2. **If the relation holds over `Z` rather than `Z_q`, it constrains the integers.** That
   is why the digits must be range-proven first: `a + b + f(X-4) = c` modulo `q` is
   vacuous for large coefficients, and only means something once every coefficient is
   known to be in `{0,1,2,3}`.
"""

from __future__ import annotations

from radix_core.candidate_b.lattice import digits as D
from radix_core.candidate_b.lattice.params import SMILE, SmileParameters

#: The base. Two bits per digit, so the evaluation point is 4.
BASE = 4


class CarryError(ValueError):
    """An addition relation does not hold, or a digit is out of range."""


def digit_poly(values: tuple[int, ...]) -> tuple[int, ...]:
    """A digit vector as a polynomial: coefficient `i` is digit `i`.

    Unlike `digits.pack_bits` this is not slot-constant packing; it is the plain
    polynomial whose evaluation at `BASE` is the integer, which is what the relation
    needs.
    """
    if len(values) > SMILE.ring_degree:
        raise CarryError(f"{len(values)} digits do not fit one polynomial")
    for value in values:
        if value not in (0, 1, 2, 3):
            raise CarryError(f"digit {value} is not in {{0,1,2,3}}")
    return tuple(values) + tuple([0] * (SMILE.ring_degree - len(values)))


def evaluate(poly: tuple[int, ...], parameters: SmileParameters = SMILE) -> int:
    """The integer a digit polynomial represents, by Horner at `BASE`."""
    total = 0
    for coefficient in reversed(poly):
        total = total * BASE + coefficient
    return total


def addition_carry(left: tuple[int, ...], right: tuple[int, ...],
                   total: tuple[int, ...], digits_count: int = D.DIGITS) -> tuple[int, ...]:
    """The carry `f` with `left + right + f(X - BASE) = total`, as digit polynomials.

    The carry has **`digits_count + 1` coefficients**, not `digits_count`. C1's eighth-pass
    correction: summing `m` amounts can carry out of the 32nd digit, and the relation at
    coefficient 32 is

        left_32 + right_32 + f_31 - BASE * f_32 = total_32

    with `total_32 = 0` because the amount polynomials have only 32 digits. That
    determines `f_32`, so the carry is 33 coefficients even though the amount is 32.
    The first version of this function looped only over the digits and dropped the final
    carry, which silently mis-handled any sum that reached the top position.

    Computed by long addition in base 4, so a caller cannot manufacture a relation that
    does not exist.
    """
    a = evaluate(left)
    b = evaluate(right)
    c = evaluate(total)
    if a + b != c:
        raise CarryError(f"{a} + {b} != {c}")

    carry = []
    carry_in = 0
    for index in range(digits_count):
        column = left[index] + right[index] + carry_in
        carry_in = column // BASE
        carry.append(carry_in)
    # The carry out of the top digit. For a balanced transaction this is the coefficient
    # that must vanish, and dropping it is what made the earlier version wrong.
    carry.append(carry_in)
    return tuple(carry)


def holds(left: tuple[int, ...], right: tuple[int, ...], total: tuple[int, ...],
          carry: tuple[int, ...]) -> bool:
    """Does `left + right + f(X - BASE) = total` hold as polynomials over Z?

    Checked coefficient by coefficient rather than by evaluation, because evaluation at
    one point cannot distinguish two different polynomials.
    """
    for index in range(SMILE.ring_degree):
        left_c = left[index] if index < len(left) else 0
        right_c = right[index] if index < len(right) else 0
        total_c = total[index] if index < len(total) else 0
        carry_c = carry[index] if index < len(carry) else 0
        previous = carry[index - 1] if index > 0 and index - 1 < len(carry) else 0
        # (f(X - 4))_i = f_{i-1} - 4 f_i
        if (left_c + right_c + previous - BASE * carry_c) != total_c:
            return False
    return True


def bound(carry: tuple[int, ...]) -> int:
    """The largest carry coefficient: what a relaxed range proof would bound."""
    return max((abs(value) for value in carry), default=0)
