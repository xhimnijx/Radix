"""Tests for the set-membership recursion, equation (7) of SMILE (p. 6)."""

import random

import pytest

from radix_core.candidate_b.lattice import params, recursion as R

RNG = random.Random(303)
P = params.SMILE
BLOCK = 32


def _random_quartic(rng):
    return tuple(rng.randrange(P.modulus) for _ in range(4))


def _one_hot(index):
    return tuple(R.constant(1 if position == index else 0) for position in range(BLOCK))


def _random_matrix(rng, m=2):
    width = BLOCK**m
    return tuple(tuple(_random_quartic(rng) for _ in range(width)) for _ in range(BLOCK))


def test_tensor_of_one_hots_is_one_hot():
    left = _one_hot(3)
    right = _one_hot(7)
    flat = R.tensor((left, right))
    assert len(flat) == BLOCK**2
    occupied = [index for index, value in enumerate(flat) if value[0]]
    assert occupied == [3 * BLOCK + 7]
    assert flat[3 * BLOCK + 7][0] == 1


def test_matrix_vector_selects_the_expected_column():
    matrix = _random_matrix(RNG, m=2)
    flat = R.one_hot_tensor((5, 9))
    assert R.matrix_vector(matrix, flat) == tuple(row[5 * BLOCK + 9] for row in matrix)


def test_split_has_thirty_two_blocks_of_the_right_shape():
    matrix = _random_matrix(RNG, m=2)
    blocks = R.split(matrix, 2)
    assert len(blocks) == BLOCK
    assert all(len(block) == BLOCK for block in blocks)
    assert all(len(row) == BLOCK for block in blocks for row in block)
    rebuilt = tuple(
        tuple(element for block in blocks for element in block[row])
        for row in range(BLOCK)
    )
    assert rebuilt == matrix


def test_equation_seven_holds():
    """<P(v1 (x) v2) - w, gamma> = <v1, P'(v2)> - <w, gamma>."""
    matrix = _random_matrix(RNG, m=2)
    v1, v2 = _one_hot(4), _one_hot(11)
    u = R.tensor((v1, v2))
    gamma = tuple(_random_quartic(RNG) for _ in range(BLOCK))
    w = R.matrix_vector(matrix, u)

    left = R.pairing(
        tuple(R.add(a, R.negate(b)) for a, b in zip(R.matrix_vector(matrix, u), w)), gamma
    )
    reduced = R.reduce_matrix(gamma, matrix, 2)
    right = R.add(
        R.pairing(v1, R.matrix_vector(reduced, v2)),
        R.negate(R.pairing(w, gamma)),
    )
    assert left == right


def test_membership_makes_both_sides_vanish():
    matrix = _random_matrix(RNG, m=2)
    v1, v2 = _one_hot(0), _one_hot(31)
    u = R.tensor((v1, v2))
    w = R.matrix_vector(matrix, u)
    gamma = tuple(_random_quartic(RNG) for _ in range(BLOCK))
    reduced = R.reduce_matrix(gamma, matrix, 2)
    assert R.add(
        R.pairing(v1, R.matrix_vector(reduced, v2)), R.negate(R.pairing(w, gamma))
    ) == R.constant(0)


def test_a_wrong_witness_is_rejected_by_g_almost_surely():
    matrix = _random_matrix(RNG, m=2)
    v1, v2 = _one_hot(2), _one_hot(3)
    w = R.matrix_vector(matrix, R.tensor((v1, v2)))
    wrong = list(w)
    wrong[0] = R.add(wrong[0], R.constant(1))
    gamma = tuple(_random_quartic(RNG) for _ in range(BLOCK))
    reduced = R.reduce_matrix(gamma, matrix, 2)
    difference = R.add(
        R.pairing(v1, R.matrix_vector(reduced, v2)), R.negate(R.pairing(tuple(wrong), gamma))
    )
    assert difference != R.constant(0)


def test_pairing_is_symmetric_and_bilinear():
    left = tuple(_random_quartic(RNG) for _ in range(BLOCK))
    right = tuple(_random_quartic(RNG) for _ in range(BLOCK))
    assert R.pairing(left, right) == R.pairing(right, left)
    total = tuple(R.add(a, b) for a, b in zip(left, right))
    assert R.pairing(total, right) == R.add(R.pairing(left, right), R.pairing(right, right))


def test_tensor_rejects_non_constant_factors():
    with pytest.raises(R.RecursionError):
        R.tensor((((1, 2, 3, 4),) + tuple(R.constant(0) for _ in range(31)),))


def test_shape_mismatches_are_rejected():
    matrix = _random_matrix(RNG, m=2)
    with pytest.raises(R.RecursionError):
        R.matrix_vector(matrix, _one_hot(0))
    with pytest.raises(R.RecursionError):
        R.split(matrix, 3)
    with pytest.raises(R.RecursionError):
        R.pairing(_one_hot(0), _one_hot(1)[:31])
    with pytest.raises(R.RecursionError):
        R.one_hot_tensor((BLOCK,))
