"""Tests for the Candidate-B ring signature (App. C API over the Fig. 7 proof).

Ring members other than the signer are sampled as uniform public keys rather than
as ``A s``: the verifier cannot tell the difference, and 1024 honest keygens would
cost ~50 s of pointless multiplications. The signer's key is real.
"""

import random

import pytest

from radix_core.candidate_b.lattice import params, ring, ring_signature as RS

P_ = params.SMILE
DEPTH = 2
MESSAGE = b"pay 10 to bob"


def _random_key(rng):
    return tuple(ring.sample_uniform(rng) for _ in range(P_.matrix_rows))


@pytest.fixture(scope="module")
def built():
    rng = random.Random(11)
    parameters = RS.setup(rng, DEPTH)
    signer_secret, signer_public = RS.keygen(parameters, rng)
    ring_keys = [_random_key(rng) for _ in range(parameters.ring_size)]
    index = 200
    ring_keys[index] = signer_public
    ring_keys = tuple(ring_keys)
    signature = RS.sign(parameters, signer_secret, signer_public, ring_keys, MESSAGE, rng)
    return parameters, signer_secret, signer_public, ring_keys, signature


def test_signature_verifies(built):
    parameters, _secret, _public, ring_keys, signature = built
    assert RS.verify(parameters, ring_keys, MESSAGE, signature)


def test_size_matches_the_formula(built):
    _parameters, _secret, _public, _ring_keys, signature = built
    assert signature.size_bytes == RS.size_bytes(DEPTH)
    assert 30_000 <= signature.size_bytes <= 35_000


def test_a_different_message_is_rejected_fast(built):
    parameters, _secret, _public, ring_keys, signature = built
    assert not RS.verify(parameters, ring_keys, b"pay 10 to mallory", signature)


def test_an_out_of_ring_key_is_refused(built):
    parameters, secret, public, _ring_keys, _signature = built
    other = tuple(_random_key(random.Random(12)) for _ in range(parameters.ring_size))
    with pytest.raises(RS.RingSignatureError, match="not in the ring"):
        RS.sign(parameters, secret, public, other, MESSAGE, random.Random(13))


def test_a_short_ring_is_rejected(built):
    parameters, _secret, _public, ring_keys, signature = built
    assert not RS.verify(parameters, ring_keys[:-1], MESSAGE, signature)


def test_parameters_reject_bad_shapes():
    rng = random.Random(14)
    parameters = RS.setup(rng, DEPTH)
    with pytest.raises(RS.RingSignatureError):
        RS.Parameters(keys=parameters.keys, matrix=parameters.matrix[:-1], depth=DEPTH)
    with pytest.raises(RS.RingSignatureError):
        RS.Parameters(
            keys=parameters.keys,
            matrix=tuple(row[:-1] for row in parameters.matrix),
            depth=DEPTH,
        )
    with pytest.raises((RS.RingSignatureError, ValueError)):
        RS.sign(parameters, (), (), tuple(), MESSAGE, rng)


def test_replacing_a_non_signer_member_breaks_the_signature(built):
    """The ring is bound even though it is not hashed: P is derived from it.

    Only the selected column has to match for the tensor relation, but the Fig. 8
    recursion aggregates *every* column through gamma, so changing another member
    moves x_2, hence y_1, hence h's zero prefix.
    """
    parameters, _secret, _public, ring_keys, signature = built
    rng = random.Random(31)
    tampered = list(ring_keys)
    tampered[5] = tuple(ring.sample_uniform(rng) for _ in range(P_.matrix_rows))
    assert not RS.verify(parameters, tuple(tampered), MESSAGE, signature)


def test_reordering_the_ring_breaks_the_signature(built):
    """Reordering moves the signer to a different tensor index, which is committed."""
    parameters, _secret, _public, ring_keys, signature = built
    reordered = list(ring_keys)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    assert not RS.verify(parameters, tuple(reordered), MESSAGE, signature)
