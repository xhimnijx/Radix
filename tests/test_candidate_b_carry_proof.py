"""`m`-input carry boundedness, proven with the relation primitive.

For `m` inputs the base-4 carry reaches `m`, so it is no longer binary and the alpha-slot
binaryness check says nothing about it. C1's route was `[25]`'s relaxed proof; this takes a
different sound route with the machinery that exists: **bit-decompose the carry**.

`m` inputs give a carry in `[0, m]`, so `ceil(log2(m+1))` bits per position suffice. The bits
are ordinary range rows, proven binary by the existing check. The link between the carry and
its bits is one `LinearRelation`:

    carry - (2^0 b_0 + 2^1 b_1 + ...) = 0

So the carry is bounded because it *is* a sum of proven bits, not because a norm bound was
hoped for.

Bit planes are packed one polynomial per plane: plane `i` holds bit `i` of every position.
That ordering matters -- packing position-major would scatter each position's bits across
different polynomials and the relation could not be written as a fixed weight per row.
"""

import random

from radix_core.candidate_b.lattice import ring, setmembership as S, subring
from radix_core.candidate_b.lattice.params import SMILE

DEPTH = 2
ROWS = 4
POSITIONS = 32


def build(range_count: int, carry_count: int, seed: int = 71):
    rng = random.Random(seed)
    keys = S.setup(
        rng, DEPTH, None, ROWS, range_count=range_count, carry_count=carry_count
    )
    matrix = tuple(
        tuple(ring.sample_uniform(rng) for _ in range(SMILE.matrix_cols)) for _ in range(ROWS)
    )
    secret = ring.sample_vector(rng, SMILE.matrix_cols, small=True, parameters=SMILE)
    public = tuple(ring.dot(row, secret, SMILE) for row in matrix)
    ring_keys = [
        tuple(ring.sample_uniform(rng) for _ in range(ROWS)) for _ in range(1024)
    ]
    ring_keys[2] = public
    statement = S.Statement(matrix=matrix, keys=tuple(ring_keys), depth=DEPTH)
    return keys, statement, secret


def planes_of(values: list[int], bit_count: int) -> list[int]:
    """Plane-major bit ordering: plane 0 is the low bit of every position, then plane 1."""
    out = []
    for bit in range(bit_count):
        for value in values:
            out.append((value >> bit) & 1)
    return out


def pack(flat: list[int]) -> tuple:
    padded = list(flat) + [0] * (-len(flat) % 32)
    return tuple(
        subring.from_constants(tuple(padded[start : start + 32]), SMILE)
        for start in range(0, len(padded), 32)
    )


def relation_for(bit_count: int, range_count: int):
    """`carry - sum 2^i * plane_i = 0`, with negative positions over range-then-carry rows."""
    carry_position = -(range_count + 1)          # the first carry row
    plane_positions = tuple(-(index + 1) for index in range(range_count))
    return S.LinearRelation(
        weights=(ring.constant(1, SMILE),)
        + tuple(ring.constant(-(1 << bit), SMILE) for bit in range(bit_count)),
        positions=(carry_position,) + plane_positions,
        constant=ring.zero(SMILE),
    )


def test_a_four_input_carry_is_bounded_by_its_bits():
    """Four inputs give a carry of at most 4, so three bits per position are enough.

    The relation is `1*carry - 1*b_0 - 2*b_1 - 4*b_2 = 0`, and it is the whole reason the
    carry is bounded: it IS the sum of three proven bits.
    """
    bit_count = 3                       # ceil(log2(4 + 1))
    range_count = bit_count             # one packed polynomial per plane
    values = [index % 5 for index in range(POSITIONS)]   # every value in [0, 4]

    bit_polys = pack(planes_of(values, bit_count))
    assert len(bit_polys) == range_count

    carry_poly = subring.from_constants(tuple(values), SMILE)
    relation = relation_for(bit_count, range_count)

    keys, statement, secret = build(range_count, 1)
    proof = S.prove(
        keys, statement, secret, 2, b"carry", random.Random(9), None, None,
        bit_polys, (relation,), (carry_poly,),
    )

    assert S.verify(keys, statement, proof, b"carry", relations=(relation,)) is True


def test_a_carry_that_does_not_match_its_bits_is_refused():
    """Without this the decomposition would be decorative.

    A prover could otherwise commit binary bits and an unrelated carry value.
    """
    bit_count = 3
    range_count = bit_count
    values = [1] * POSITIONS
    bit_polys = pack(planes_of(values, bit_count))
    relation = relation_for(bit_count, range_count)

    keys, statement, secret = build(range_count, 1)
    # Claim a carry of 2 while the bits still say 1.
    wrong = subring.from_constants(tuple(2 for _ in range(POSITIONS)), SMILE)
    proof = S.prove(
        keys, statement, secret, 2, b"carry", random.Random(9), None, None,
        bit_polys, (relation,), (wrong,),
    )

    assert S.verify(keys, statement, proof, b"carry", relations=(relation,)) is False


def test_a_non_binary_bit_plane_is_refused():
    """The bits are range rows, so the binaryness check applies to them as usual."""
    values = [1] * POSITIONS
    bits = planes_of(values, 1)
    bits[0] = 2                                     # one position is not a bit
    bit_polys = pack(bits)
    carry_poly = ring.constant(1, SMILE)
    relation = S.LinearRelation(
        weights=(ring.constant(1, SMILE), ring.constant(-1, SMILE)),
        positions=(-2, -1),
        constant=ring.zero(SMILE),
    )

    keys, statement, secret = build(1, 1)
    proof = S.prove(
        keys, statement, secret, 2, b"carry", random.Random(9), None, None,
        bit_polys, (relation,), (carry_poly,),
    )

    assert S.verify(keys, statement, proof, b"carry", relations=(relation,)) is False
