"""The range statement: what a proof of "these amounts are in range" must establish.

Every primitive now exists separately — base-4 digits, bit packing, the slotwise
binaryness check, the carry relation, the relaxed bound. This module assembles them into
one object and one verifier, so the statement is defined exactly rather than described in
prose, and so the proof that will eventually replace `verify` has a specification.

What is checked, and why each part is necessary:

1. **Every bit is a bit.** `b(b-1) = 0` slotwise. Without it a "digit" could be any field
   element and the reconstruction in step 2 would be meaningless.
2. **Every digit is `2*b1 + b0`.** This is what ties the committed bits to the committed
   digits; without it a prover could commit honest bits and dishonest digits.
3. **Every digit is in `{0,1,2,3}`.** Follows from 1 and 2, and is checked anyway because
   a verifier should not rely on an implication it does not test.
4. **The digits add up.** `sum(inputs) + f(X-4) = total + fee` as polynomials. Without
   this the amounts are in range individually and the transaction still mints.
5. **The carry is small.** Bounded by the relaxed argument rather than decomposed; for two
   terms it is binary, and for `m` terms it is at most `m`.

`verify` is the specification, not the proof. It takes the witness in the clear, so it
proves nothing on its own -- it exists so the proof's obligations are written down and
tested before the α-slot layout is attempted.
"""

from __future__ import annotations

from radix_core.candidate_b.lattice import carry as C
from radix_core.candidate_b.lattice import digits as D
from radix_core.candidate_b.lattice.params import SMILE, SmileParameters


class RangeError(ValueError):
    """A range statement is malformed, or does not hold."""


def build(amounts: list[int], parameters: SmileParameters = SMILE) -> dict:
    """The witness data for `amounts`: digits, packed bits and digit polynomials."""
    if not amounts:
        raise RangeError("a range statement needs at least one amount")
    digit_vectors = [D.encode_amount(amount, D.DIGITS) for amount in amounts]
    return {
        "amounts": list(amounts),
        "digits": digit_vectors,
        "bits": [D.bits_of(amount, D.DIGITS) for amount in amounts],
        "polys": [C.digit_poly(vector) for vector in digit_vectors],
        "alpha_count": D.constraint_count(len(amounts), parameters),
    }


def verify_digits(statement: dict, parameters: SmileParameters = SMILE) -> bool:
    """Checks 1 to 3: bits are bits, digits follow from bits, digits are in range.

    A verifier rejects malformed input rather than raising on it: an exception tells a
    caller something went wrong, and a return value tells them the statement is false.
    Only the second is a verdict.
    """
    try:
        return _verify_digits(statement, parameters)
    except (D.DigitError, KeyError, TypeError, IndexError):
        return False


def _verify_digits(statement: dict, parameters: SmileParameters = SMILE) -> bool:
    for bits, digit_vector in zip(statement["bits"], statement["digits"]):
        packed = D.pack_bits(bits, parameters)
        if not D.is_slot_binary(packed, parameters):
            return False
        if D.unpack_bits(packed, parameters) != tuple(bits):
            return False
        reconstructed = []
        for index in range(0, len(bits), 2):
            reconstructed.append((bits[index + 1] << 1) | bits[index])
        if tuple(reconstructed) != tuple(digit_vector):
            return False
        if any(digit not in (0, 1, 2, 3) for digit in digit_vector):
            return False
    return True


def verify_balance(input_polys: list, output_polys: list, fee_poly: tuple,
                   carry_poly: tuple) -> bool:
    """Check 4: the digit polynomials add up, with an explicit carry."""
    total_in = [0] * SMILE.ring_degree
    for poly in input_polys:
        total_in = [a + b for a, b in zip(total_in, poly)]
    total_out = [0] * SMILE.ring_degree
    for poly in output_polys:
        total_out = [a + b for a, b in zip(total_out, poly)]
    total_out = [a + b for a, b in zip(total_out, fee_poly)]

    # sum(in) - sum(out) - fee must be exactly f*(X - 4).
    difference = [a - b for a, b in zip(total_in, total_out)]
    return C.holds(tuple(difference), (0,) * SMILE.ring_degree,
                   (0,) * SMILE.ring_degree, carry_poly)


def verify(inputs: list[int], outputs: list[int], fee: int,
           carry_poly: tuple, parameters: SmileParameters = SMILE) -> bool:
    """The whole statement: every amount in range, and the totals balance.

    `carry_poly` is the witness that absorbs the base-4 carries, so this is a
    specification rather than a proof -- it sees every amount in the clear. It is what the
    alpha-slot version must reproduce without revealing any of them.
    """
    if not inputs:
        return False
    if fee < 0 or fee >= parameters.modulus:
        return False
    try:
        statement = build(list(inputs) + list(outputs), parameters)
        fee_poly = C.digit_poly(D.encode_amount(fee, D.DIGITS))
    except (D.DigitError, C.CarryError, RangeError):
        return False

    if not verify_digits(statement, parameters):
        return False

    in_polys = statement["polys"][: len(inputs)]
    out_polys = statement["polys"][len(inputs) :]
    return verify_balance(in_polys, out_polys, fee_poly, carry_poly)


def alpha_budget(amounts: int, parameters: SmileParameters = SMILE) -> int:
    """alpha challenges for a statement over `amounts` amounts: C2's three-per-amount."""
    return D.constraint_count(amounts, parameters)
