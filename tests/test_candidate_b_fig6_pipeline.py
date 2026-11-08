"""End-to-end assembly of the pieces Fig. 6 uses, in the order it uses them.

This is an integration test, not a new protocol: it proves that the layers added
separately compose into the shape SMILE needs, at m = 2. Anything not present
(the zero-knowledge proofs of the constraints) is absent here too.
"""

import random

import pytest

from radix_core.candidate_b.lattice import bdlop, params, recursion as R, ring, subring

RNG = random.Random(505)
P = params.SMILE
BLOCK = 32


def _quartic(rng):
    return tuple(rng.randrange(P.modulus) for _ in range(4))


def _matrix(rng, m):
    width = BLOCK**m
    return tuple(tuple(_quartic(rng) for _ in range(width)) for _ in range(BLOCK))


def test_the_six_steps_of_a_membership_witness():
    """v one-hot -> lifted -> committed -> P.u = w -> challenge -> (7) closes."""
    rng = random.Random(506)

    # 1. the witness: a hidden index, expressed as one-hot vectors
    v1, lifted1 = R.one_hot_and_lifted(6)
    v2, _lifted2 = R.one_hot_and_lifted(29)
    assert R.is_one_hot(v1) and R.is_one_hot(v2)

    # 2. the constraint half that is checkable today: g(NTT^-1(v)) = 1
    assert subring.g(lifted1) == (1, 0, 0, 0)

    # 3. omega commits to (m, V, w~, -w) under one randomness
    rows = tuple(tuple(ring.sample_uniform(rng) for _ in range(13)) for _ in range(4))
    messages = (ring.sample_small(rng), lifted1, ring.sample_small(rng), ring.sample_small(rng))
    opening = bdlop.opening(rng)
    omega = bdlop.commit_vector(rows, messages, opening)
    assert bdlop.verify_vector(rows, omega, messages, opening)

    # 4. the public set and the selected element
    matrix = _matrix(rng, 2)
    u = R.tensor((v1, v2))
    w = R.matrix_vector(matrix, u)
    assert w == tuple(row[6 * BLOCK + 29] for row in matrix)

    # 5. Fiat-Shamir challenge (a stand-in here: the challenge derivation itself
    #    belongs to the proof layer and is not claimed by this test)
    gamma = tuple(_quartic(rng) for _ in range(BLOCK))

    # 6. equation (7) closes, and closes to zero for the honest witness
    reduced = R.reduce_matrix(gamma, matrix, 2)
    difference = R.add(
        R.pairing(v1, R.matrix_vector(reduced, v2)), R.negate(R.pairing(w, gamma))
    )
    assert difference == R.constant(0)
    assert R.pairing(
        tuple(R.add(a, R.negate(b)) for a, b in zip(R.matrix_vector(matrix, u), w)), gamma
    ) == R.constant(0)


def test_claiming_the_wrong_member_breaks_the_assembly():
    rng = random.Random(507)
    matrix = _matrix(rng, 2)
    v1, _ = R.one_hot_and_lifted(6)
    v2, _ = R.one_hot_and_lifted(29)
    w = R.matrix_vector(matrix, R.tensor((v1, v2)))
    gamma = tuple(_quartic(rng) for _ in range(BLOCK))
    reduced = R.reduce_matrix(gamma, matrix, 2)
    impostor, _ = R.one_hot_and_lifted(7)
    difference = R.add(
        R.pairing(impostor, R.matrix_vector(reduced, v2)), R.negate(R.pairing(w, gamma))
    )
    assert difference != R.constant(0)


def test_a_non_one_hot_index_vector_is_caught_by_the_constraint():
    """A two-hot vector encodes fine: only the constraint separates it from one-hot."""
    vector = [R.constant(0) for _ in range(BLOCK)]
    vector[6] = vector[29] = R.constant(1)
    vector = tuple(vector)
    assert R.is_binary(vector) and not R.is_one_hot(vector)
    lifted = subring.from_constants(tuple(element[0] for element in vector))
    assert subring.g(lifted) == (2, 0, 0, 0)
