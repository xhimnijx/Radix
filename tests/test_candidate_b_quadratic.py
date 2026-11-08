"""Tests for the p. 23 quadratic form (k = 1, m = 1)."""

import random

from radix_core.candidate_b.lattice import params, quadratic as Q, ring

P = params.SMILE


def _fixture():
    rng = random.Random(607)
    rows = tuple(tuple(ring.sample_uniform(rng) for _ in range(13)) for _ in range(3))
    mask = ring.sample_vector(rng, 13, small=True)
    randomness = ring.sample_vector(rng, 13, small=True)
    values = tuple(ring.sample_small(rng) for _ in range(3))
    gamma = ring.sample_uniform(rng)
    return rows, mask, randomness, values, gamma


def _form(rows, mask, randomness, values, gamma, challenge):
    return Q.evaluate(rows, mask, randomness, values, gamma, challenge, P)[0]


def test_masked_response_equals_the_clear_form():
    rng = random.Random(608)
    b = ring.sample_vector(rng, 13)
    mask = ring.sample_vector(rng, 13, small=True)
    randomness = ring.sample_vector(rng, 13, small=True)
    value = ring.sample_small(rng)
    challenge = ring.sample_small(rng)
    z = tuple(ring.add(a, ring.mul(challenge, b, P), P) for a, b in zip(mask, randomness))
    t = Q.commit(b, randomness, value, P)
    assert Q.masked_response(b, z, t, challenge, P) == ring.sub(
        ring.dot(b, mask, P), ring.mul(challenge, value, P), P
    )


def test_third_coefficient_is_equation_twenty():
    """The c^2 coefficient of F_1 is exactly y_1 = v_1 x_2 - gamma x_1."""
    rows, mask, randomness, values, gamma = _fixture()
    v_one, x_one, x_two = values
    at_zero, at_one, at_two = (
        _form(rows, mask, randomness, values, gamma, ring.constant(value, P))
        for value in (0, 1, 2)
    )
    assert Q.quadratic_coefficient(at_zero, at_one, at_two, P) == (
        Q.expected_quadratic_coefficient(v_one, x_two, gamma, x_one, P)
    )


def test_form_is_quadratic_not_higher_degree():
    """The third forward difference of F vanishes, so F is degree <= 2 in c."""
    rows, mask, randomness, values, gamma = _fixture()
    samples = [
        _form(rows, mask, randomness, values, gamma, ring.constant(value, P))
        for value in (0, 1, 2, 3)
    ]
    third = ring.add(
        ring.sub(samples[3], ring.scalar(3, samples[2], P), P),
        ring.sub(ring.scalar(3, samples[1], P), samples[0], P),
        P,
    )
    assert third == ring.zero(P)


def test_the_quadratic_coefficient_is_zero_when_v_one_x_two_equals_gamma_x_one():
    rows, mask, randomness, values, gamma = _fixture()
    v_one, x_one, _x_two = values
    adjusted = (v_one, x_one, v_one)  # arbitrary replacement for x_2
    at_zero, at_one, at_two = (
        _form(rows, mask, randomness, adjusted, gamma, ring.constant(value, P))
        for value in (0, 1, 2)
    )
    coefficient = Q.quadratic_coefficient(at_zero, at_one, at_two, P)
    assert coefficient == Q.expected_quadratic_coefficient(v_one, v_one, gamma, x_one, P)
