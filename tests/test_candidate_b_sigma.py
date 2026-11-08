"""Tests for the BDLOP opening proof (Sigma-protocol layer of SMILE)."""

import random
from functools import lru_cache

import pytest

from radix_core.candidate_b.lattice import bdlop, params, ring, sigma

CONTEXT = b"radix/b/test/transfer"


@lru_cache(maxsize=1)
def _fixture():
    rng = random.Random(19)
    key = bdlop.setup(rng)
    message = ring.sample_small(rng)
    randomness = bdlop.opening(rng)
    commitment = bdlop.commit(key, message, randomness)
    proof = sigma.prove(key, commitment, message, randomness, CONTEXT, rng)
    return key, commitment, message, randomness, proof


def test_honest_proof_verifies():
    key, commitment, message, _randomness, proof = _fixture()
    assert sigma.verify(key, commitment, message, proof, CONTEXT)


def test_proof_is_randomised():
    key, commitment, message, randomness, proof = _fixture()
    second = sigma.prove(
        key, commitment, message, randomness, CONTEXT, random.Random(20)
    )
    assert second != proof
    assert sigma.verify(key, commitment, message, second, CONTEXT)


def test_wrong_context_is_rejected():
    key, commitment, message, _randomness, proof = _fixture()
    assert not sigma.verify(key, commitment, message, proof, b"other context")


def test_wrong_message_is_rejected():
    key, commitment, message, _randomness, proof = _fixture()
    other = ring.add(message, ring.constant(1))
    assert not sigma.verify(key, commitment, other, proof, CONTEXT)


def test_tampered_response_is_rejected():
    key, commitment, message, _randomness, proof = _fixture()
    tampered = list(proof.response[0])
    tampered[0] = (tampered[0] + 1) % params.PROTOTYPE_MODULUS
    bad = sigma.OpeningProof(challenge=proof.challenge, response=tuple(tampered))
    assert not sigma.verify(key, commitment, message, bad, CONTEXT)


def test_tampered_challenge_is_rejected():
    key, commitment, message, _randomness, proof = _fixture()
    challenge = list(proof.challenge)
    challenge[0] = 1 if challenge[0] != 1 else -1
    bad = sigma.OpeningProof(challenge=tuple(challenge), response=proof.response)
    assert not sigma.verify(key, commitment, message, bad, CONTEXT)


def test_out_of_norm_response_is_rejected():
    key, commitment, message, _randomness, proof = _fixture()
    oversized_first = (sigma.ACCEPT_BOUND + 1,) + proof.response[0][1:]
    oversized = (oversized_first, *proof.response[1:])
    bad = sigma.OpeningProof(challenge=proof.challenge, response=oversized)
    assert not sigma.verify(key, commitment, message, bad, CONTEXT)


def test_challenge_coefficients_are_ternary_and_response_is_small():
    _key, _commitment, _message, _randomness, proof = _fixture()
    assert set(proof.challenge) <= {-1, 0, 1}
    assert len(proof.challenge) == 128
    assert all(ring.norm_inf(poly) <= sigma.ACCEPT_BOUND for poly in proof.response)


def test_proof_encoding_roundtrip_and_rejection():
    _key, _commitment, _message, _randomness, proof = _fixture()
    encoded = proof.encode()
    assert len(encoded) == 128 + 13 * 128 * 4
    assert sigma.OpeningProof.decode(encoded) == proof
    with pytest.raises(sigma.SigmaError):
        sigma.OpeningProof.decode(encoded[:-1])
    corrupt = bytearray(encoded)
    corrupt[0] = 3  # outside {-1,0,1} after the +1 offset
    with pytest.raises(sigma.SigmaError):
        sigma.OpeningProof.decode(bytes(corrupt))


def test_proving_with_a_wrong_opening_is_refused():
    key, commitment, message, randomness, _proof = _fixture()
    with pytest.raises(sigma.SigmaError, match="does not match"):
        sigma.prove(
            key,
            commitment,
            ring.add(message, ring.constant(2)),
            randomness,
            CONTEXT,
            random.Random(21),
        )
