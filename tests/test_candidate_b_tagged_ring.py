"""A tagged ring signature: the B3 linkability layer end to end."""

import random

import pytest

from radix_core.candidate_b.lattice import params, ring, setmembership as S, tag as T

pytestmark = pytest.mark.slow

P_ = params.SMILE
DEPTH = 2
MESSAGE = b"spend once"


@pytest.fixture(scope="module")
def built():
    rng = random.Random(61)
    keys = S.setup(rng, DEPTH)
    tag_keys = T.setup(rng, P_)
    matrix = tuple(
        tuple(ring.sample_uniform(rng) for _ in range(P_.matrix_cols))
        for _ in range(P_.matrix_rows)
    )
    secret, public = S.keygen(rng, matrix)
    ring_keys = [
        tuple(ring.sample_uniform(rng) for _ in range(P_.matrix_rows))
        for _ in range(32**DEPTH)
    ]
    ring_keys[42] = public
    statement = S.Statement(matrix=matrix, keys=tuple(ring_keys), depth=DEPTH)
    proof = S.prove(keys, statement, secret, 42, MESSAGE, rng, None, tag_keys)
    return keys, tag_keys, statement, secret, proof


def test_tagged_proof_verifies(built):
    keys, tag_keys, statement, _secret, proof = built
    assert S.verify(keys, statement, proof, MESSAGE, None, tag_keys)


def test_the_tag_is_the_committed_linear_image(built):
    _keys, tag_keys, _statement, secret, proof = built
    assert proof.tag_proof is not None
    assert proof.tag_proof.tag == T.tag_of(tag_keys, secret, P_)


def test_a_tagged_proof_is_not_silently_accepted_untagged(built):
    """A ledger that forgets to check the tag would accept it; this forbids that."""
    keys, _tag_keys, statement, _secret, proof = built
    assert not S.verify(keys, statement, proof, MESSAGE)


def test_a_tampered_tag_is_rejected(built):
    keys, tag_keys, statement, _secret, proof = built
    rng = random.Random(62)
    forged_tag = T.TagProof(
        t=proof.tag_proof.t,
        u=proof.tag_proof.u,
        tag=ring.sample_small(rng),
        proof=proof.tag_proof.proof,
    )
    forged = S.Proof(
        commitment=proof.commitment,
        h=proof.h,
        omega=proof.omega,
        challenge=proof.challenge,
        challenge_prime=proof.challenge_prime,
        response_prime=proof.response_prime,
        response=proof.response,
        tag_proof=forged_tag,
    )
    assert not S.verify(keys, statement, forged, MESSAGE, None, tag_keys)


def test_the_tagged_proof_is_larger_by_the_mask_commitment(built):
    _keys, _tag_keys, _statement, _secret, proof = built
    # 32,512 + kappa + ell (mask commitment) + 1 (tag) + ell (opening response)
    assert proof.size_bytes == 51_584
