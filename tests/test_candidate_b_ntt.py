"""Tests for the negacyclic NTT (the substrate of the Fig. 6 recursion)."""

import random

import pytest

from radix_core.candidate_b.lattice import ntt, params, ring

RNG = random.Random(101)


def _evaluations(poly):
    """Direct O(d^2) evaluation at every root of X^d + 1, for comparison."""
    table = ntt.transform()
    q = table.modulus
    root = table.root
    return tuple(
        sum(
            coefficient * pow(root, index * (2 * turn + 1), q)
            for index, coefficient in enumerate(poly)
        )
        % q
        for turn in range(table.degree)
    )


def test_transform_matches_direct_evaluation():
    poly = ring.sample_uniform(RNG)
    assert ntt.forward(poly) == _evaluations(poly)


def test_root_is_primitive_and_order_two_d():
    table = ntt.transform()
    assert pow(table.root, 2 * table.degree, table.modulus) == 1
    assert pow(table.root, table.degree, table.modulus) == table.modulus - 1


def test_forward_then_inverse_is_identity():
    for _ in range(3):
        poly = ring.sample_uniform(RNG)
        assert ntt.inverse(ntt.forward(poly)) == poly


def test_multiply_agrees_with_the_naive_convolution():
    for _ in range(3):
        left = ring.sample_uniform(RNG)
        right = ring.sample_uniform(RNG)
        assert ntt.multiply(left, right) == ring.mul_naive(left, right)


def test_multiplication_is_pointwise_in_the_transform_domain():
    left = ring.sample_uniform(RNG)
    right = ring.sample_uniform(RNG)
    product = ntt.forward(ntt.multiply(left, right))
    q = ntt.transform().modulus
    assert product == tuple(a * b % q for a, b in zip(ntt.forward(left), ntt.forward(right)))


def test_negacyclic_wrap_is_preserved():
    degree = params.SMILE.ring_degree
    top = tuple(1 if index == degree - 1 else 0 for index in range(degree))
    x = tuple(1 if index == 1 else 0 for index in range(degree))
    assert ntt.multiply(top, x) == ring.neg(ring.constant(1))


def test_constant_multiplication_commutes_with_mul():
    poly = ring.sample_uniform(RNG)
    for value in (0, 1, 7, params.PROTOTYPE_MODULUS - 1):
        assert ring.mul(poly, ring.constant(value)) == ring.scalar(value, poly)


def test_transform_tables_are_cached_and_deterministic():
    assert ntt.transform() is ntt.transform()
    assert ntt.transform(params.SMILE) is ntt.transform()


def test_supports_reports_missing_roots():
    assert ntt.supports() is True
    unsupported = params.SmileParameters(modulus=4294962688)
    assert ntt.supports(unsupported) is False
    left = (1,) + (0,) * (params.RING_DEGREE - 1)
    right = (0, 1) + (0,) * (params.RING_DEGREE - 2)
    assert ring.mul(left, right, unsupported) == ring.mul_naive(left, right, unsupported)


def test_malformed_inputs_are_rejected():
    with pytest.raises(ntt.TransformError):
        ntt.forward((1, 2, 3))
    with pytest.raises(ntt.TransformError):
        ntt.inverse((1, 2, 3))
    with pytest.raises(ntt.TransformError):
        ntt.multiply(ring.zero(), (1,) * (params.RING_DEGREE - 1) + (1.5,))
