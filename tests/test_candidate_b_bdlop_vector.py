"""Tests for multi-message BDLOP commitments (the omega of Fig. 5/Fig. 6)."""

import random

import pytest

from radix_core.candidate_b.lattice import bdlop, ring

RNG = random.Random(404)


def _rows(count):
    return tuple(tuple(ring.sample_uniform(RNG) for _ in range(13)) for _ in range(count))


def test_vector_commitment_verifies_and_round_trips():
    rows = _rows(3)
    messages = tuple(ring.sample_small(RNG) for _ in range(3))
    randomness = bdlop.opening(RNG)
    commitment = bdlop.commit_vector(rows, messages, randomness)
    assert len(commitment.components) == 3
    assert bdlop.verify_vector(rows, commitment, messages, randomness)


def test_components_are_independent_linear_functions_of_the_same_randomness():
    rows = _rows(2)
    messages = tuple(ring.sample_small(RNG) for _ in range(2))
    randomness = bdlop.opening(RNG)
    commitment = bdlop.commit_vector(rows, messages, randomness)
    for row, message, component in zip(rows, messages, commitment.components):
        assert component == ring.add(ring.dot(row, randomness), message)


def test_tampering_is_detected():
    rows = _rows(2)
    messages = tuple(ring.sample_small(RNG) for _ in range(2))
    randomness = bdlop.opening(RNG)
    commitment = bdlop.commit_vector(rows, messages, randomness)
    shifted = (ring.add(messages[0], ring.constant(1)), messages[1])
    assert not bdlop.verify_vector(rows, commitment, shifted, randomness)
    wrong = list(commitment.components)
    wrong[1] = ring.add(wrong[1], ring.constant(1))
    assert not bdlop.verify_vector(
        rows, bdlop.VectorCommitment(tuple(wrong)), messages, randomness
    )


def test_shape_mismatches_are_rejected():
    rows = _rows(2)
    messages = tuple(ring.sample_small(RNG) for _ in range(2))
    randomness = bdlop.opening(RNG)
    with pytest.raises(ValueError):
        bdlop.commit_vector(rows, messages[:1], randomness)
    with pytest.raises(ValueError):
        bdlop.commit_vector(rows, messages, randomness[:3])
    with pytest.raises(ValueError):
        bdlop.commit_vector(rows + (rows[0][:4],), messages + (messages[0],), randomness)
    with pytest.raises(ValueError):
        bdlop.VectorCommitment(())
    assert not bdlop.verify_vector(rows, bdlop.VectorCommitment((ring.zero(),)), messages, randomness)


def test_four_messages_match_fig_six_shape():
    """Fig. 6 commits to m, V, w~ and -w in one vector commitment."""
    rows = _rows(4)
    messages = tuple(ring.sample_small(RNG) for _ in range(4))
    randomness = bdlop.opening(RNG)
    commitment = bdlop.commit_vector(rows, messages, randomness)
    assert len(commitment.encode()) == 4 * 128 * 4
    assert bdlop.verify_vector(rows, commitment, messages, randomness)

