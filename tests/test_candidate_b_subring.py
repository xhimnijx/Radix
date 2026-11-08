"""Tests for the quartic slot decomposition, SMILE's M_q (p. 6)."""

import random

import pytest

from radix_core.candidate_b.lattice import ntt, params, ring, subring

RNG = random.Random(202)


def test_there_are_thirty_two_distinct_quartic_factors():
    table = subring.roots(params.PROTOTYPE_MODULUS, params.RING_DEGREE)
    q = params.PROTOTYPE_MODULUS
    assert len(table) == params.RING_DEGREE // 4 == 32
    assert len(set(table)) == 32
    assert all(pow(value, 32, q) == q - 1 for value in table)


def test_root_product_is_the_constant_term_of_y_to_the_32_plus_one():
    q = params.PROTOTYPE_MODULUS
    product = 1
    for value in subring.roots(q, params.RING_DEGREE):
        product = product * value % q
    assert product == 1


def test_g_is_thirty_two_times_the_first_four_coefficients():
    """p. 7: g(y) = 32(y_0 + y_1 X + y_2 X^2 + y_3 X^3), reproduced exactly."""
    q = params.PROTOTYPE_MODULUS
    for _ in range(2):
        poly = ring.sample_uniform(RNG)
        assert subring.g(poly) == tuple(32 * poly[i] % q for i in range(4))


def test_slots_and_glue_are_inverse():
    for _ in range(2):
        poly = ring.sample_uniform(RNG)
        assert subring.glue(subring.slots(poly)) == poly


def test_slot_residues_reduce_modulo_their_own_quartic():
    poly = ring.sample_uniform(RNG)
    table = subring.roots(params.PROTOTYPE_MODULUS, params.RING_DEGREE)
    q = params.PROTOTYPE_MODULUS
    for index, residue in enumerate(subring.slots(poly)):
        # y = sum_t X^(4t) y^(t) and X^4 = r_index inside slot `index`.
        expected = [0, 0, 0, 0]
        for block in range(32):
            power = pow(table[index], block, q)
            for offset in range(4):
                expected[offset] = (expected[offset] + power * poly[4 * block + offset]) % q
        assert residue == tuple(expected)


def test_slot_map_is_a_ring_homomorphism():
    left = ring.sample_uniform(RNG)
    right = ring.sample_uniform(RNG)
    assert subring.slots(ring.add(left, right)) == tuple(
        tuple((a + b) % params.PROTOTYPE_MODULUS for a, b in zip(x, y))
        for x, y in zip(subring.slots(left), subring.slots(right))
    )
    assert subring.slots(ring.mul(left, right)) == subring.slot_multiply(
        subring.slots(left), subring.slots(right)
    )


def test_quartic_multiplication_folds_at_the_fourth_power():
    q = params.PROTOTYPE_MODULUS
    table = subring.roots(q, params.RING_DEGREE)
    r = table[0]
    # X^3 * (1 + 2X + 3X^2 + 4X^3) = X^3 + 2X^4 + 3X^5 + 4X^6 = X^3 + r(2 + 3X + 4X^2)
    assert subring.quartic_multiply((0, 0, 0, 1), (1, 2, 3, 4), r, q) == (
        2 * r % q,
        3 * r % q,
        4 * r % q,
        1,
    )


def test_constant_lift_has_constant_slot_residues():
    one_hot = (0,) * 7 + (1,) + (0,) * 24
    poly = subring.from_constants(one_hot)
    assert subring.slots(poly) == tuple(
        (value, 0, 0, 0) for value in one_hot
    )


def test_constant_lift_of_all_ones_is_the_plain_constant():
    assert subring.from_constants((1,) * 32) == ring.constant(1)


def test_inner_product_of_constant_vectors_is_their_scalar_dot_product():
    """<w, w'> = g(NTT^-1(w) NTT^-1(w')) collapses to the dot product, as p. 6 claims."""
    q = params.PROTOTYPE_MODULUS
    left = tuple(RNG.randrange(q) for _ in range(32))
    right = tuple(RNG.randrange(q) for _ in range(32))
    product = ring.mul(subring.from_constants(left), subring.from_constants(right))
    expected = sum(a * b for a, b in zip(left, right)) % q
    assert subring.g(product) == (expected, 0, 0, 0)
    assert sum(slot[0] for slot in subring.slots(product)) % q == expected
    assert all(slot[1:] == (0, 0, 0) for slot in subring.slots(product))


def test_malformed_inputs_are_rejected():
    with pytest.raises(subring.SubringError):
        subring.slot(ring.zero(), 32)
    with pytest.raises(subring.SubringError):
        subring.slot((1, 2, 3), 0)
    with pytest.raises(subring.SubringError):
        subring.glue(tuple((1, 0, 0, 0) for _ in range(31)))
    with pytest.raises(subring.SubringError):
        subring.from_constants((1, 2, 3))
    with pytest.raises(subring.SubringError):
        subring.glue(tuple((1, 0) for _ in range(32)))


def test_transform_and_roots_agree_on_the_same_parameter_set():
    """The quartic constants are fourth powers of the transform's roots."""
    table = ntt.transform()
    q = table.modulus
    quartic = subring.roots(q, table.degree)
    for index, value in enumerate(quartic):
        point = pow(table.root, 2 * index + 1, q)
        assert pow(point, 4, q) == value
