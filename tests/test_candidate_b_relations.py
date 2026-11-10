"""A linear relation among committed messages, proven inside the proof.

This is the primitive the `m`-input carry needs, and it is the last one missing from the
range layer. C1's eighth-pass note described it exactly: "`a + b - c = f*(X-4)` is linear in
the committed values, so it rides on the existing masked opening for one row."

How it is checked, and why it costs one challenge rather than a proof:

The verifier can form `sum_j weight_j * f_j = sum_j weight_j * a_j - c * rho`, where `a_j`
is the masked value it cannot see and `rho` is what the relation should force to zero. So
the relation is premultiplied by `c`: the prover puts `sum_j weight_j * a_j` into `psi`, the
equation subtracts it with its own factor of `c`, and the survivor is `-c^2 * rho`. Since
`c` must be a unit, the verifier's equality forces `rho = 0`.

The tests are the point. A relation that holds must not disturb verification, and a relation
that does not hold must be refused *by the proof* -- that second test is the one that
distinguishes a real constraint from a decorative one.
"""

import random

import pytest

from radix_core.candidate_b.lattice import digits, ring, setmembership as S, subring
from radix_core.candidate_b.lattice.params import SMILE

DEPTH = 2
ROWS = 4


def build(range_count: int = 1, seed: int = 51):
    rng = random.Random(seed)
    keys = S.setup(rng, DEPTH, None, ROWS, range_count=range_count)
    matrix = tuple(
        tuple(ring.sample_uniform(rng) for _ in range(SMILE.matrix_cols)) for _ in range(ROWS)
    )
    secret = ring.sample_vector(rng, SMILE.matrix_cols, small=True, parameters=SMILE)
    public = tuple(ring.dot(row, secret, SMILE) for row in matrix)
    ring_keys = [
        tuple(ring.sample_uniform(rng) for _ in range(ROWS)) for _ in range(1024)
    ]
    ring_keys[3] = public
    statement = S.Statement(matrix=matrix, keys=tuple(ring_keys), depth=DEPTH)
    return keys, statement, secret


def zero_bits():
    """A committed message whose value is zero everywhere: the relation `m_0 - 0 = 0`."""
    return ring.zero(SMILE)


def one_bits(position: int = 0):
    """The message `1` in every CRT slot.

    `ring.constant(1)` is the identity in every slot, which is what a scalar constant in a
    relation is compared against. `subring.from_constants((1,0,0,...))` is *not* the same
    object: it sets slot 0 to 1 and every other slot to 0. The first version of this test
    used the latter and then compared it against the former, which is why a relation that
    looked like it should hold did not.
    """
    if position != 0:
        raise ValueError("only the constant message is used by these tests")
    return ring.constant(1, SMILE)


def relation(message_is_zero: bool):
    """`1 * m_0 - 0 = 0`, referencing range row 0 as position -1."""
    constant = ring.zero(SMILE) if message_is_zero else ring.constant(1, SMILE)
    return S.LinearRelation(
        weights=(ring.constant(1, SMILE),),
        positions=(-1,),
        constant=constant,
    )


def test_a_relation_that_holds_does_not_disturb_verification():
    keys, statement, secret = build()
    bits = (zero_bits(),)
    proof = S.prove(
        keys, statement, secret, 3, b"rel", random.Random(6), None, None, bits,
        (relation(message_is_zero=True),),
    )
    assert S.verify(keys, statement, proof, b"rel", relations=(relation(True),)) is True


def test_a_relation_that_does_not_hold_is_refused_by_the_proof():
    """The message is 1 and the relation claims it is 0, so the residual is non-zero.

    This is the whole point: without it, a "relation" would be a comment.
    """
    keys, statement, secret = build()
    bits = (one_bits(),)
    proof = S.prove(
        keys, statement, secret, 3, b"rel", random.Random(6), None, None, bits,
        (relation(message_is_zero=True),),
    )
    assert S.verify(keys, statement, proof, b"rel", relations=(relation(True),)) is False


def test_the_same_relation_holds_when_the_constant_matches_the_message():
    """The relation is only as strong as the constant: `m - 1 = 0` accepts a message of 1."""
    keys, statement, secret = build()
    bits = (one_bits(),)
    holds = S.LinearRelation(
        weights=(ring.constant(1, SMILE),),
        positions=(-1,),
        constant=ring.constant(1, SMILE),
    )
    proof = S.prove(
        keys, statement, secret, 3, b"rel", random.Random(6), None, None, bits, (holds,)
    )
    assert S.verify(keys, statement, proof, b"rel", relations=(holds,)) is True


def test_a_relation_over_two_messages_checks_their_sum():
    """`m_0 + m_1 - 1 = 0` holds when exactly one of the two is set."""
    keys, statement, secret = build(range_count=2)
    bits = (ring.constant(1, SMILE), zero_bits())
    relation_sum = S.LinearRelation(
        weights=(ring.constant(1, SMILE), ring.constant(1, SMILE)),
        positions=(-1, -2),
        constant=ring.constant(1, SMILE),
    )
    proof = S.prove(
        keys, statement, secret, 3, b"rel", random.Random(6), None, None, bits,
        (relation_sum,),
    )
    assert S.verify(keys, statement, proof, b"rel", relations=(relation_sum,)) is True

    # Both set: the sum is 2, so the relation fails.
    both = (ring.constant(1, SMILE), ring.constant(1, SMILE))
    bad = S.prove(
        keys, statement, secret, 3, b"rel", random.Random(6), None, None, both,
        (relation_sum,),
    )
    assert S.verify(keys, statement, bad, b"rel", relations=(relation_sum,)) is False


def test_a_zero_weight_makes_the_relation_vacuous():
    """Documented rather than surprising: weight 0 means the message does not enter."""
    keys, statement, secret = build()
    vacuous = S.LinearRelation(
        weights=(ring.zero(SMILE),),
        positions=(-1,),
        constant=ring.zero(SMILE),
    )
    proof = S.prove(
        keys, statement, secret, 3, b"rel", random.Random(6), None, None, (one_bits(),),
        (vacuous,),
    )
    assert S.verify(keys, statement, proof, b"rel", relations=(vacuous,)) is True
