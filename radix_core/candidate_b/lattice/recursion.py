"""SMILE set-membership recursion: the m-level reduction of Section 3.1.

Objects, exactly as p. 5 defines them:

    M_q = Z_q + Z_q X + Z_q X^2 + Z_q X^3            (so an element is 4 residues)
    NTT(w) = (w mod (X^4 - r_1), ..., w mod (X^4 - r_32)) : R_q -> M_q^32
    g(w)   = sum of the 32 NTT coordinates
    <w, w'> = g(NTT^-1(w) NTT^-1(w')) = sum_j w_j w'_j mod (X^4 - r_j)

A vector in ``M_q^32k`` is ``k`` blocks of 32 slots; index ``j`` carries slot
``j % 32``. Multiplying two of them is only defined inside the pairing, where
slot ``j`` reduces modulo its own quartic. That is why the paper can only move
``v_1`` across the matrix: ``v_1`` has *constant* entries, so multiplying by it
needs no reduction (p. 6, footnote 6).

The identity implemented and tested here is (7) on p. 6:

    <P(v_1 (x) ... (x) v_m) - w, gamma> = <v_1, P'(v_2 (x) ... (x) v_m)> - <w, gamma>

with ``P' = [gamma^T P_1 ; ... ; gamma^T P_32]``. That is the recursion: the
right-hand side is a *smaller* instance of the same problem (one tensor factor
fewer), which is what makes the proof size linear in ``m``.
"""

from __future__ import annotations

from . import subring
from .params import SMILE, SmileParameters

Quartic = tuple[int, int, int, int]


class RecursionError(ValueError):
    """A vector, matrix, or challenge does not fit the module structure."""


def _p(parameters: SmileParameters | None = None) -> SmileParameters:
    return SMILE if parameters is None else parameters


def slots_per_block(parameters: SmileParameters | None = None) -> int:
    return _p(parameters).ring_degree // subring.SLOT_DEGREE


def roots(parameters: SmileParameters | None = None) -> tuple[int, ...]:
    p = _p(parameters)
    return subring.roots(p.modulus, p.ring_degree)


def constant(value: int, parameters: SmileParameters | None = None) -> Quartic:
    p = _p(parameters)
    return (value % p.modulus, 0, 0, 0)


def add(left: Quartic, right: Quartic, parameters: SmileParameters | None = None) -> Quartic:
    p = _p(parameters)
    return tuple((a + b) % p.modulus for a, b in zip(left, right))


def negate(value: Quartic, parameters: SmileParameters | None = None) -> Quartic:
    p = _p(parameters)
    return tuple((-a) % p.modulus for a in value)


def scalar(value: int, element: Quartic, parameters: SmileParameters | None = None) -> Quartic:
    p = _p(parameters)
    return tuple(value * a % p.modulus for a in element)


def product(
    left: Quartic, right: Quartic, slot: int, parameters: SmileParameters | None = None
) -> Quartic:
    """Quartic product reduced modulo (X^4 - r_slot)."""
    p = _p(parameters)
    table = roots(p)
    if not 0 <= slot < len(table):
        raise RecursionError("slot index is outside the decomposition")
    return subring.quartic_multiply(left, right, table[slot], p.modulus)


def pairing(
    left: tuple[Quartic, ...],
    right: tuple[Quartic, ...],
    parameters: SmileParameters | None = None,
) -> Quartic:
    """<left, right> over M_q^{32k}: sum_j left_j right_j mod (X^4 - r_{j % 32})."""
    p = _p(parameters)
    if len(left) != len(right):
        raise RecursionError("pairing needs equal lengths")
    if len(left) % slots_per_block(p):
        raise RecursionError("vector length must be a multiple of 32")
    total = constant(0, p)
    for index, (a, b) in enumerate(zip(left, right)):
        total = add(total, product(a, b, index % slots_per_block(p), p), p)
    return total


def is_constant_vector(vector: tuple[Quartic, ...], parameters: SmileParameters | None = None) -> bool:
    p = _p(parameters)
    return all(element[1:] == (0, 0, 0) for element in vector)


def tensor(
    vectors: tuple[tuple[Quartic, ...], ...], parameters: SmileParameters | None = None
) -> tuple[Quartic, ...]:
    """Kronecker product over M_q, right index fastest; entries must be constants."""
    p = _p(parameters)
    if not vectors:
        raise RecursionError("tensor product needs at least one vector")
    for vector in vectors:
        if len(vector) != slots_per_block(p):
            raise RecursionError("each tensor factor must have 32 entries")
        if not is_constant_vector(vector, p):
            raise RecursionError("tensor factors must have constant entries")
    result = tuple(constant(element[0], p) for element in vectors[0])
    for vector in vectors[1:]:
        result = tuple(
            constant(a[0] * b[0] % p.modulus, p) for a in result for b in vector
        )
    return result


def one_hot_tensor(
    indices: tuple[int, ...], parameters: SmileParameters | None = None
) -> tuple[Quartic, ...]:
    """The flat vector e_{i_1} (x) ... (x) e_{i_m}."""
    p = _p(parameters)
    block = slots_per_block(p)
    factors = []
    for index in indices:
        if not 0 <= index < block:
            raise RecursionError("tensor index is outside the subring")
        factors.append(tuple(constant(1 if position == index else 0, p) for position in range(block)))
    return tensor(tuple(factors), p)


def matrix_vector(
    matrix: tuple[tuple[Quartic, ...], ...],
    vector: tuple[Quartic, ...],
    parameters: SmileParameters | None = None,
) -> tuple[Quartic, ...]:
    """P.v over the Z_q-module M_q: the vector entries are scalars."""
    p = _p(parameters)
    if not is_constant_vector(vector, p):
        raise RecursionError("matrix-vector product needs a constant vector")
    if any(len(row) != len(vector) for row in matrix):
        raise RecursionError("matrix row length does not match the vector")
    out = []
    for row in matrix:
        total = constant(0, p)
        for element, weight in zip(row, vector):
            if weight[0]:
                total = add(total, scalar(weight[0], element, p), p)
        out.append(total)
    return tuple(out)


def split(matrix: tuple[tuple[Quartic, ...], ...], m: int) -> tuple[tuple[tuple[Quartic, ...], ...], ...]:
    """P = [P_1 | ... | P_32]: 32 column blocks keyed by the first tensor index."""
    if m < 1:
        raise RecursionError("tensor depth must be positive")
    block = _p().ring_degree // subring.SLOT_DEGREE
    width = block ** (m - 1)
    if any(len(row) != block * width for row in matrix):
        raise RecursionError("matrix width does not match the tensor depth")
    return tuple(
        tuple(tuple(row[index * width : (index + 1) * width]) for row in matrix)
        for index in range(block)
    )


def challenge_block(
    challenge: tuple[Quartic, ...],
    block: tuple[tuple[Quartic, ...], ...],
    parameters: SmileParameters | None = None,
) -> tuple[Quartic, ...]:
    """gamma^T P_j: row `rest` is sum_row gamma[row] P_j[row][rest], slot row % 32."""
    p = _p(parameters)
    size = slots_per_block(p)
    if len(challenge) != len(block):
        raise RecursionError("challenge height does not match the block")
    width = len(block[0]) if block else 0
    out = []
    for column in range(width):
        total = constant(0, p)
        for row_index, (weight, row) in enumerate(zip(challenge, block)):
            total = add(total, product(weight, row[column], row_index % size, p), p)
        out.append(total)
    return tuple(out)


def reduce_matrix(
    challenge: tuple[Quartic, ...],
    matrix: tuple[tuple[Quartic, ...], ...],
    m: int,
    parameters: SmileParameters | None = None,
) -> tuple[tuple[Quartic, ...], ...]:
    """P' = [gamma^T P_1 ; ... ; gamma^T P_32], the next level's matrix."""
    p = _p(parameters)
    blocks = split(matrix, m)
    return tuple(challenge_block(challenge, block, p) for block in blocks)
