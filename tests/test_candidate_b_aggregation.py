"""Tests for aggregation of k BDLOP commitments (SMILE Fig. 5)."""

import random
from functools import lru_cache

import pytest

from radix_core.candidate_b.lattice import aggregation, bdlop, params, ring, sigma

CONTEXT = b"radix/b/test/aggregate"
COUNT = 2


@lru_cache(maxsize=1)
def _fixture():
    rng = random.Random(31)
    key = aggregation.setup(rng, COUNT)
    messages = tuple(ring.sample_small(rng) for _ in range(COUNT))
    secrets = tuple(bdlop.opening(rng) for _ in range(COUNT))
    inputs = tuple(
        bdlop.commit(key.commitment, message, secret)
        for message, secret in zip(messages, secrets)
    )
    proof = aggregation.prove(key, inputs, messages, secrets, CONTEXT, rng)
    return key, inputs, messages, secrets, proof


def test_honest_proof_verifies():
    key, inputs, _messages, _secrets, proof = _fixture()
    assert aggregation.verify(key, inputs, proof, CONTEXT)


def test_proof_is_randomised():
    key, inputs, messages, secrets, proof = _fixture()
    second = aggregation.prove(
        key, inputs, messages, secrets, CONTEXT, random.Random(32)
    )
    assert second != proof
    assert aggregation.verify(key, inputs, second, CONTEXT)


def test_single_input_aggregation_verifies():
    rng = random.Random(33)
    key = aggregation.setup(rng, 1)
    message = ring.sample_small(rng)
    secret = bdlop.opening(rng)
    inputs = (bdlop.commit(key.commitment, message, secret),)
    proof = aggregation.prove(key, inputs, (message,), (secret,), CONTEXT, rng)
    assert aggregation.verify(key, inputs, proof, CONTEXT)


def test_wrong_context_is_rejected():
    key, inputs, _messages, _secrets, proof = _fixture()
    assert not aggregation.verify(key, inputs, proof, b"another context")


def test_reordered_inputs_are_rejected():
    key, inputs, _messages, _secrets, proof = _fixture()
    assert inputs[0] != inputs[1]
    assert not aggregation.verify(key, inputs[::-1], proof, CONTEXT)


def test_tampered_omega_is_rejected():
    key, inputs, _messages, _secrets, proof = _fixture()
    shifted = ring.add(proof.omega.g_w, ring.constant(1))
    bad = aggregation.AggregationProof(
        w=proof.w,
        omega=aggregation.Omega(f=proof.omega.f, g=proof.omega.g, g_w=shifted),
        response=proof.response,
        pi=proof.pi,
    )
    assert not aggregation.verify(key, inputs, bad, CONTEXT)


def test_out_of_norm_response_is_rejected():
    key, inputs, _messages, _secrets, proof = _fixture()
    oversized = (sigma.ACCEPT_BOUND + 1,) + proof.response[0][1:]
    bad = aggregation.AggregationProof(
        w=proof.w,
        omega=proof.omega,
        response=(oversized, *proof.response[1:]),
        pi=proof.pi,
    )
    assert not aggregation.verify(key, inputs, bad, CONTEXT)


def test_tampered_inner_proof_is_rejected():
    key, inputs, _messages, _secrets, proof = _fixture()
    response = list(proof.pi.response[0])
    response[0] = (response[0] + 1) % params.PROTOTYPE_MODULUS
    forged = sigma.OpeningProof(
        challenge=proof.pi.challenge, response=(tuple(response), *proof.pi.response[1:])
    )
    bad = aggregation.AggregationProof(
        w=proof.w, omega=proof.omega, response=proof.response, pi=forged
    )
    assert not aggregation.verify(key, inputs, bad, CONTEXT)


def test_challenges_are_sparse_ternary():
    _key, _inputs, _messages, _secrets, proof = _fixture()
    challenges = aggregation._challenges(CONTEXT, proof.w, proof.omega)
    assert len(challenges) == COUNT
    for challenge in challenges:
        assert set(challenge) <= {-1, 0, 1}
        assert sum(1 for value in challenge if value) == params.CHALLENGE_DIM


def test_response_norm_dominates_the_masking_bound():
    _key, _inputs, _messages, _secrets, proof = _fixture()
    assert all(ring.norm_inf(poly) <= sigma.ACCEPT_BOUND for poly in proof.response)


def test_masked_opening_identity():
    """b.z - w~ = sum_i c_i (u_i - m_i): the step that makes mu = sum c_i u_i public."""
    key, inputs, messages, secrets, proof = _fixture()
    challenges = aggregation._challenges(CONTEXT, proof.w, proof.omega)
    p = params.SMILE
    mask = sigma._mask_vector(random.Random(37), p.matrix_cols, p)
    w_tilde = ring.dot(key.commitment.vector, mask, p)
    response = tuple(
        ring.add(
            mask[column],
            aggregation._sum_scaled(
                challenges, tuple(secret[column] for secret in secrets), p
            ),
            p,
        )
        for column in range(p.matrix_cols)
    )
    right = tuple(
        ring.sub(item.u, message, p) for item, message in zip(inputs, messages)
    )
    assert ring.dot(key.commitment.vector, response, p) == ring.add(
        w_tilde, aggregation._sum_scaled(challenges, right, p), p
    )


def test_proof_encoding_roundtrip_and_rejection():
    key, _inputs, _messages, _secrets, proof = _fixture()
    encoded = proof.encode()
    assert len(encoded) == aggregation.size_bytes(COUNT)
    assert aggregation.AggregationProof.decode(encoded, COUNT) == proof
    with pytest.raises(aggregation.AggregationError):
        aggregation.AggregationProof.decode(encoded[:-1], COUNT)
    with pytest.raises(aggregation.AggregationError):
        aggregation.AggregationProof.decode(encoded, COUNT + 1)


def test_key_and_proof_shape_mismatch_is_refused():
    key, inputs, messages, secrets, _proof = _fixture()
    with pytest.raises(aggregation.AggregationError):
        aggregation.prove(key, inputs[:1], messages[:1], secrets[:1], CONTEXT, random.Random(34))


def test_input_without_a_valid_opening_is_refused():
    key, inputs, messages, secrets, _proof = _fixture()
    wrong = (ring.add(secrets[0][0], ring.constant(3)),) + secrets[0][1:]
    with pytest.raises(aggregation.AggregationError, match="does not match"):
        aggregation.prove(
            key, inputs, messages, (wrong,) + secrets[1:], CONTEXT, random.Random(35)
        )

