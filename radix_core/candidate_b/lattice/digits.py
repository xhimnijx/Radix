"""Base-4 digits and the bit-packed binaryness constraint.

Hidden amounts need each digit of an amount proven to lie in `{0,1,2,3}`. C1's correction
to the plan was that this is **not** the ring set-membership: a four-element one-hot is a
different statement from a one-out-of-1024 selector, and the tensor decomposition that
makes the selector work is for `32^2 = 1024`, not for 4.

C2's correction was the one that makes it affordable. The equation a bit must satisfy is

    b * (b - 1) = 0

and that is a *ring* equation, so it holds **slotwise**. At the irreducible modulus this
codebase uses, a polynomial is 32 slots of 4 coefficients each, and a slot-constant
polynomial holds one value across its four coefficients. So one polynomial carries **32
bits**, not one: 64 bit-constraints for an amount cost **two** polynomials and therefore
**two α challenges**, not sixty-four.

That is the difference between a range proof that costs 64 constraints per amount and one
that costs two. It is why this module packs bits into slots rather than committing a bit
per coefficient.

What this module is not: it does not run the proof. It implements the encoding, the
packing and the checks the proof will assert, so the statement has something concrete to
refer to and the arithmetic can be tested before the proof is wired up.
"""

from __future__ import annotations

from radix_core.candidate_b.lattice.params import SMILE, SmileParameters

#: Digits per amount. 4^32 > 2^64, so 32 base-4 digits represent every 64-bit amount.
DIGITS = 32
BITS = DIGITS * 2
#: Coefficients per slot: the degree of each irreducible quartic factor.
SLOT_WIDTH = 4


class DigitError(ValueError):
    """An amount, a digit, or a packed polynomial is out of range."""


def slots(parameters: SmileParameters = SMILE) -> int:
    """How many slot-constants a polynomial holds at this modulus."""
    return parameters.ring_degree // SLOT_WIDTH


def encode_amount(amount: int, digits: int = DIGITS) -> tuple[int, ...]:
    """Least-significant-first base-4 digits."""
    if type(amount) is not int or amount < 0:
        raise DigitError("an amount must be a non-negative integer")
    if amount >= 4**digits:
        raise DigitError(f"amount {amount} does not fit {digits} base-4 digits")
    out = []
    value = amount
    for _ in range(digits):
        out.append(value & 3)
        value >>= 2
    return tuple(out)


def decode_amount(digits: tuple[int, ...]) -> int:
    total = 0
    for index, digit in enumerate(digits):
        if digit not in (0, 1, 2, 3):
            raise DigitError(f"digit {digit} is not in {{0,1,2,3}}")
        total += digit << (2 * index)
    return total


def bits_of(amount: int, digits: int = DIGITS) -> tuple[int, ...]:
    """The 2*digits bits of the amount, least significant first."""
    out = []
    for digit in encode_amount(amount, digits):
        out.append(digit & 1)
        out.append((digit >> 1) & 1)
    return tuple(out)


def amount_of(bits: tuple[int, ...]) -> int:
    """Inverse of `bits_of`. Each pair is `d = 2*b1 + b0`."""
    if len(bits) % 2:
        raise DigitError("bits must come in pairs")
    amount = 0
    for index in range(0, len(bits), 2):
        low, high = bits[index], bits[index + 1]
        if low not in (0, 1) or high not in (0, 1):
            raise DigitError("bits must be 0 or 1")
        digit = (high << 1) | low
        amount += digit << index
    return amount


def pack_bits(bits: tuple[int, ...], parameters: SmileParameters = SMILE) -> tuple:
    """Pack bits into slot-constant polynomials, one bit per slot.

    Each slot's four coefficients are set to the same bit value. That is what makes
    `b(b-1) = 0` a per-slot constraint, which is what makes one α cover 32 bits.
    """
    per_poly = slots(parameters)
    if len(bits) % per_poly:
        raise DigitError(
            f"{len(bits)} bits do not fill {per_poly}-bit polynomials exactly"
        )
    for bit in bits:
        if bit not in (0, 1):
            raise DigitError(f"{bit} is not a bit")

    polynomials = []
    for start in range(0, len(bits), per_poly):
        coefficients = []
        for bit in bits[start : start + per_poly]:
            coefficients.extend([bit] * SLOT_WIDTH)
        polynomials.append(tuple(coefficients))
    return tuple(polynomials)


def unpack_bits(polynomials: tuple, parameters: SmileParameters = SMILE) -> tuple[int, ...]:
    """Inverse of `pack_bits`, refusing a polynomial that is not slot-constant binary."""
    out = []
    for poly in polynomials:
        if len(poly) != parameters.ring_degree:
            raise DigitError("a packed polynomial has the wrong degree")
        for slot in range(slots(parameters)):
            chunk = poly[slot * SLOT_WIDTH : (slot + 1) * SLOT_WIDTH]
            if len(set(chunk)) != 1:
                raise DigitError(f"slot {slot} is not constant: {chunk}")
            value = chunk[0]
            if value not in (0, 1):
                raise DigitError(f"slot {slot} holds {value}, which is not a bit")
            out.append(value)
    return tuple(out)


def is_slot_binary(polynomials: tuple, parameters: SmileParameters = SMILE) -> bool:
    """The verifier's `b(b-1) = 0` check, slotwise.

    `b * (b - 1) = 0` in a field forces `b` to be 0 or 1. At the field modulus each slot
    is such a field, so the check is per slot and one α covers all of them.
    """
    for poly in polynomials:
        for slot in range(slots(parameters)):
            chunk = poly[slot * SLOT_WIDTH : (slot + 1) * SLOT_WIDTH]
            if len(set(chunk)) != 1:
                return False
            if chunk[0] not in (0, 1):
                return False
    return True


def constraint_count(amounts: int, parameters: SmileParameters = SMILE) -> int:
    """α challenges needed for `amounts` amounts: two per amount, plus one for the carry."""
    return amounts * 2 + 1
