"""The slot decomposition R_q = prod_i Z_q[X]/(X^4 - r_i), i.e. SMILE's M_q.

This pins the convention that p. 6 of the full version states and that p. 7 uses:

    <w, w'> := g( NTT^-1(w) * NTT^-1(w') ) = sum_i w_i w'_i  mod (X^4 - r_i)

with ``r_i`` the 32 roots of ``Y^32 = -1``, and

    g(y) = sum_i (y mod (X^4 - r_i)) = 32 * (y_0 + y_1 X + y_2 X^2 + y_3 X^3).

So ``R_q`` splits into 32 *quartic* slots (not 128 scalar ones): the CRT factors
of ``X^128 + 1`` over ``Z_q`` are ``X^4 - r_i``, and the paper's "NTT" is the map
``y |-> (y mod (X^4 - r_i))_i``. That is the object the set-membership recursion
of Section 3.1 manipulates, and the reason a vanishing coefficient condition is a
dot product: the slot residues multiply slotwise and ``g`` sums them.

Consequences that are tested rather than asserted:
* ``g`` really is ``32`` times the first four coefficients (power sums of the 32
  roots of ``Y^32 + 1`` vanish for degrees 1..31),
* the slot map is a ring homomorphism onto the product of the quartic rings,
* ``glue`` inverts it, so ``NTT^-1`` here is exact integer CRT, not a transform
  with a normalisation to be guessed.
"""

from __future__ import annotations

from functools import lru_cache

from . import ntt
from .params import SMILE, SmileParameters

SLOT_DEGREE = 4


class SubringError(ValueError):
    """A polynomial, slot, or parameter set does not fit the decomposition."""


@lru_cache(maxsize=8)
def roots(modulus: int, degree: int) -> tuple[int, ...]:
    """The 32 values r_i with r_i^32 = -1: the quartic factors' constant terms."""
    table = ntt.transform()
    if degree != table.degree:
        raise SubringError("ring degree does not match the cached transform")
    if degree % SLOT_DEGREE:
        raise SubringError("ring degree must be a multiple of four")
    zeta = table.root
    count = degree // SLOT_DEGREE
    candidates = tuple(
        pow(zeta, 2 * SLOT_DEGREE * index + SLOT_DEGREE, modulus) for index in range(count)
    )
    if len(set(candidates)) != count:
        raise SubringError("quartic factors are not distinct")
    for value in candidates:
        if pow(value, count, modulus) != modulus - 1:
            raise SubringError("quartic constant term is not a 32nd root of -1")
    return candidates


def slot(poly: tuple[int, ...], index: int, parameters: SmileParameters | None = None) -> tuple[int, int, int, int]:
    """y mod (X^4 - r_index): the index-th quartic residue of y."""
    p = SMILE if parameters is None else parameters
    table = roots(p.modulus, p.ring_degree)
    if not 0 <= index < len(table):
        raise SubringError("slot index is outside the decomposition")
    if len(poly) != p.ring_degree:
        raise SubringError("polynomial has the wrong length")
    r = table[index]
    residue = [0, 0, 0, 0]
    for block in range(len(table)):
        power = 1
        for step in range(block):
            power = power * r % p.modulus
        for offset in range(SLOT_DEGREE):
            residue[offset] = (residue[offset] + power * poly[block * SLOT_DEGREE + offset]) % p.modulus
    return tuple(residue)


def slots(poly: tuple[int, ...], parameters: SmileParameters | None = None) -> tuple[tuple[int, ...], ...]:
    """All 32 quartic residues: the paper's NTT of y."""
    p = SMILE if parameters is None else parameters
    return tuple(slot(poly, index, p) for index in range(len(roots(p.modulus, p.ring_degree))))


def evaluate_slot(residue: tuple[int, ...], point: int, parameters: SmileParameters | None = None) -> int:
    """Horner evaluation of a quartic residue at `point`."""
    p = SMILE if parameters is None else parameters
    value = 0
    for coefficient in reversed(residue):
        value = (value * point + coefficient) % p.modulus
    return value


def glue(
    residues: tuple[tuple[int, ...], ...], parameters: SmileParameters | None = None
) -> tuple[int, ...]:
    """NTT^-1 of a slot vector: the unique y with those quartic residues."""
    p = SMILE if parameters is None else parameters
    table = roots(p.modulus, p.ring_degree)
    if len(residues) != len(table):
        raise SubringError("slot vector has the wrong length")
    if any(len(residue) != SLOT_DEGREE for residue in residues):
        raise SubringError("every slot must be a quartic residue")
    zeta = ntt.transform(p).root
    evaluations = []
    for index in range(p.ring_degree):
        point = pow(zeta, 2 * index + 1, p.modulus)
        evaluations.append(evaluate_slot(residues[index % len(table)], point, p))
    return ntt.inverse(tuple(evaluations), p)


def from_constants(
    vector: tuple[int, ...], parameters: SmileParameters | None = None
) -> tuple[int, ...]:
    """NTT^-1 of a vector of constants: the lift SMILE commits to for v_1..v_m.

    The paper's v_i "only have constant terms" (p. 6, footnote 6), which is what
    makes the inner product with a challenge side reduction-free.
    """
    p = SMILE if parameters is None else parameters
    table = roots(p.modulus, p.ring_degree)
    if len(vector) != len(table):
        raise SubringError("constant vector must have one entry per slot")
    return glue(
        tuple((value % p.modulus, 0, 0, 0) for value in vector), p
    )


def g(poly: tuple[int, ...], parameters: SmileParameters | None = None) -> tuple[int, ...]:
    """The sum of the slot residues, which p. 7 states is 32*(y_0..y_3)."""
    p = SMILE if parameters is None else parameters
    total = [0, 0, 0, 0]
    for residue in slots(poly, p):
        for offset in range(SLOT_DEGREE):
            total[offset] = (total[offset] + residue[offset]) % p.modulus
    return tuple(total)


def quartic_multiply(
    left: tuple[int, ...], right: tuple[int, ...], modulus_root: int, q: int
) -> tuple[int, ...]:
    """Product in Z_q[X]/(X^4 - modulus_root)."""
    product = [0] * (2 * SLOT_DEGREE - 1)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            product[i + j] = (product[i + j] + a * b) % q
    folded = [product[i] % q for i in range(SLOT_DEGREE)]
    for i in range(SLOT_DEGREE, len(product)):
        folded[i - SLOT_DEGREE] = (folded[i - SLOT_DEGREE] + modulus_root * product[i]) % q
    return tuple(folded)


def slot_multiply(
    left: tuple[tuple[int, ...], ...],
    right: tuple[tuple[int, ...], ...],
    parameters: SmileParameters | None = None,
) -> tuple[tuple[int, ...], ...]:
    """Slotwise product: the image of ring multiplication under the decomposition."""
    p = SMILE if parameters is None else parameters
    table = roots(p.modulus, p.ring_degree)
    if len(left) != len(table) or len(right) != len(table):
        raise SubringError("slot vector has the wrong length")
    return tuple(
        quartic_multiply(a, b, table[index], p.modulus)
        for index, (a, b) in enumerate(zip(left, right))
    )
