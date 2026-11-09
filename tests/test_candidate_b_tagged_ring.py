"""The same-witness tag: A_ext = [A; A'], one proof, no separate tag proof.

This replaces the withdrawn separate-tag construction. The tag T = A' s is a row
of the same relation the ring signature already proves, so a forger cannot choose
it independently of the secret it opened.
"""

import random

import pytest

from radix_core.candidate_b.lattice import params, ring, ring_signature as RS

pytestmark = pytest.mark.slow

P_ = params.SMILE
DEPTH = 2
TAG_ROWS = 4  # C1: the first row count with a comfortable collision margin
MESSAGE = b"spend once"


def _random_key(rng):
    return tuple(ring.sample_uniform(rng) for _ in range(P_.matrix_rows))


@pytest.fixture(scope="module")
def built():
    rng = random.Random(31)
    parameters = RS.setup(rng, DEPTH, None, TAG_ROWS)
    secret, public = RS.keygen(parameters, rng)
    ring_keys = [_random_key(rng) for _ in range(parameters.ring_size)]
    ring_keys[200] = public
    ring_keys = tuple(ring_keys)
    proof, tag = RS.sign_tagged(parameters, secret, public, ring_keys, MESSAGE, rng)
    second, second_tag = RS.sign_tagged(parameters, secret, public, ring_keys, MESSAGE, rng)
    return parameters, secret, public, ring_keys, proof, tag, second, second_tag


def test_tagged_proof_verifies(built):
    parameters, _s, _p, ring_keys, proof, tag, _second, _st = built
    assert RS.verify_tagged(parameters, ring_keys, tag, MESSAGE, proof)


def test_the_tag_is_a_linear_image_of_the_note_secret(built):
    parameters, secret, _p, _rk, _proof, tag, _second, _st = built
    assert tag == RS.tag_of(parameters, secret)


def test_the_same_note_gives_the_same_tag_every_time(built):
    """Linkability: the tag is deterministic in s, not in the mask."""
    _parameters, _s, _p, _rk, _proof, tag, second, second_tag = built
    assert second != _proof  # different mask, different proof
    assert second_tag == tag


def test_a_modified_tag_is_rejected(built):
    parameters, _s, _p, ring_keys, proof, tag, _second, _st = built
    rng = random.Random(32)
    forged = tuple(ring.add(t, ring.constant(1, P_)) for t in tag)
    assert not RS.verify_tagged(parameters, ring_keys, forged, MESSAGE, proof)
    # and a tag that is not even the right shape
    assert not RS.verify_tagged(parameters, ring_keys, (), MESSAGE, proof)


def test_the_untagged_api_refuses_tagged_parameters(built):
    parameters, secret, public, ring_keys, _proof, _tag, _second, _st = built
    with pytest.raises(RS.RingSignatureError, match="sign_tagged"):
        RS.sign(parameters, secret, public, ring_keys, MESSAGE, random.Random(33))
    assert not RS.verify(parameters, ring_keys, b"x", _proof)


def test_the_extended_proof_is_only_slightly_larger(built):
    _parameters, _s, _p, _rk, proof, tag, _second, _st = built
    total = proof.size_bytes + len(tag) * P_.ring_degree * 4
    assert total == RS.tagged_size_bytes(DEPTH, TAG_ROWS)
    assert 36_000 <= total <= 40_000
