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


def _primitive_64th_root(modulus: int) -> int:
    """An element of multiplicative order exactly 64, or SubringError."""
    if (modulus - 1) % 64:
        raise SubringError("q-1 is not divisible by 64: no quartic decomposition exists")
    for base in range(2, 4096):
        candidate = pow(base, (modulus - 1) // 64, modulus)
        if pow(candidate, 32, modulus) == modulus - 1:
            return candidate
    raise SubringError("no element of order 64 found")


@lru_cache(maxsize=8)
def roots(modulus: int, degree: int) -> tuple[int, ...]:
    """The 32 values r_i with r_i^32 = -1: the quartic factors' constant terms.

    They are `eta^(2i+1)` for `eta` a primitive 64th root. When a full NTT exists
    `eta = zeta^4`, which reproduces the historical ordering exactly; when it does
    not -- an irreducible-quartic modulus -- `eta` is found directly. The condition
    is `64 | q - 1`, not `256 | q - 1`.
    """
    if degree % SLOT_DEGREE:
        raise SubringError("ring degree must be a multiple of four")
    transform = ntt.try_transform(modulus, degree)
    if transform is not None:
        eta = pow(transform.root, 4, modulus)
    else:
        eta = _primitive_64th_root(modulus)
    if pow(eta, 32, modulus) != modulus - 1:
        raise SubringError("the 64th root is not primitive")
    count = degree // SLOT_DEGREE
    candidates = tuple(pow(eta, 2 * index + 1, modulus) for index in range(count))
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
    modulus = p.modulus
    residue = [0, 0, 0, 0]
    power = 1
    for block in range(len(table)):
        base = block * SLOT_DEGREE
        residue[0] = (residue[0] + power * poly[base]) % modulus
        residue[1] = (residue[1] + power * poly[base + 1]) % modulus
        residue[2] = (residue[2] + power * poly[base + 2]) % modulus
        residue[3] = (residue[3] + power * poly[base + 3]) % modulus
        power = power * r % modulus
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


def _glue_ntt(
    residues: tuple[tuple[int, ...], ...], parameters: SmileParameters | None = None
) -> tuple[int, ...]:
    """The NTT-based inverse, valid only when a 256th root of unity exists."""
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


def multiply(
    left: tuple[int, ...], right: tuple[int, ...], parameters: SmileParameters | None = None
) -> tuple[int, ...]:
    """Product in R_q through the quartic CRT, for moduli with no 256th root.

    Slotwise quartic products, then reconstruct. The products do not wrap because
    `glue_crt` sums idempotent multiples of quartics.
    """
    p = SMILE if parameters is None else parameters
    if len(left) != p.ring_degree or len(right) != p.ring_degree:
        raise SubringError("polynomial has the wrong length")
    return glue_crt(slot_multiply(slots(left, p), slots(right, p), p), p)


def g(poly: tuple[int, ...], parameters: SmileParameters | None = None) -> tuple[int, ...]:
    """The sum of the slot residues, which p. 7 states is 32*(y_0..y_3)."""
    p = SMILE if parameters is None else parameters
    total = [0, 0, 0, 0]
    for residue in slots(poly, p):
        for offset in range(SLOT_DEGREE):
            total[offset] = (total[offset] + residue[offset]) % p.modulus
    return tuple(total)



@lru_cache(maxsize=8)
def _idempotents(modulus: int, degree: int) -> tuple[tuple[int, ...], ...]:
    """All 32 CRT idempotents, built once per (modulus, degree)."""
    table = roots(modulus, degree)
    inverse = pow(len(table), -1, modulus)
    out = []
    for r in table:
        r_inverse = pow(r, -1, modulus)
        coefficients = [0] * degree
        power = 1
        for t in range(len(table)):
            coefficients[SLOT_DEGREE * t] = power * inverse % modulus
            power = power * r_inverse % modulus
        out.append(tuple(coefficients))
    return tuple(out)


def glue(
    residues: tuple[tuple[int, ...], ...], parameters: SmileParameters | None = None
) -> tuple[int, ...]:
    """Inverse of `slots`: the unique y with those quartic residues.

    Dispatches on the modulus. When a 256th root of unity exists the NTT path runs;
    otherwise the 32-way CRT. Both are tested against each other at the prototype
    modulus, where both exist.
    """
    p = SMILE if parameters is None else parameters
    if ntt.try_transform(p.modulus, p.ring_degree) is not None:
        return _glue_ntt(residues, p)
    if (p.modulus - 1) % 64 == 0:
        return glue_crt(residues, p)
    raise SubringError("no quartic decomposition for this modulus")


def crt_idempotent(index: int, parameters: SmileParameters | None = None) -> tuple[int, ...]:
    """The CRT idempotent e_index: 1 mod (X^4 - r_index), 0 modulo the others.

    Closed form. `X^128 + 1` divided by `X^4 - r_i` is
    `Q_i = sum_j r_i^j X^(4(31-j))`, and `Q_i` reduces to `32 r_i^31` in the i-th
    slot, so the idempotent is `Q_i / (32 r_i^31)`, i.e. the coefficient of `X^(4t)`
    is `r_i^(-t) / 32`. (The first version of this function dropped the `r_i^31`
    and produced an operator that was not idempotent; the round-trip test caught it.)
    """
    p = SMILE if parameters is None else parameters
    table = roots(p.modulus, p.ring_degree)
    if not 0 <= index < len(table):
        raise SubringError("slot index is outside the decomposition")
    return _idempotents(p.modulus, p.ring_degree)[index]


def glue_crt(
    residues: tuple[tuple[int, ...], ...], parameters: SmileParameters | None = None
) -> tuple[int, ...]:
    """Reconstruct y from its quartic residues by 32-way CRT.

    `y = sum_i e_i * c_i`. This is the replacement for `glue` when the modulus has
    no 256th root of unity: it needs only that `X^128 + 1` factors into the 32
    quartics, which every valid SMILE modulus guarantees. The quartic products do
    not wrap, since `e_i` has degree <= 124 and `c_i` has degree <= 3.
    """
    p = SMILE if parameters is None else parameters
    table = roots(p.modulus, p.ring_degree)
    if len(residues) != len(table):
        raise SubringError("slot vector has the wrong length")
    if any(len(residue) != SLOT_DEGREE for residue in residues):
        raise SubringError("every slot must be a quartic residue")
    out = [0] * p.ring_degree
    for index, residue in enumerate(residues):
        idempotent = crt_idempotent(index, p)
        for base in range(0, p.ring_degree, SLOT_DEGREE):
            for offset in range(SLOT_DEGREE):
                coefficient = residue[offset]
                if coefficient:
                    out[base + offset] = (
                        out[base + offset]
                        + coefficient * idempotent[base]
                    ) % p.modulus
    return tuple(out)

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
