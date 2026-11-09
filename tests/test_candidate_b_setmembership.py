"""Tests for the SMILE set-membership proof (Figs. 7-9).

The honest path costs ~20 s to prove and ~20 s to verify at m = 2 (a 1024-member
ring): it builds a 128 x 1024 set matrix over M_q and runs the Fig. 8 recursion.
That is the real protocol, so the tests are grouped around one cached proof and
spend their budget on falsification rather than on repetition.
"""

import random

import pytest

from radix_core.candidate_b.lattice import params, ring, setmembership as S

pytestmark = pytest.mark.slow

P_ = params.SMILE
DEPTH = 2
UPDATED = False


@pytest.fixture(scope="module")
def built():
    rng = random.Random(7)
    keys = S.setup(rng, DEPTH)
    matrix = tuple(
        tuple(ring.sample_uniform(rng) for _ in range(P_.matrix_cols))
        for _ in range(P_.matrix_rows)
    )
    secret, public = S.keygen(rng, matrix)
    ring_keys = [
        tuple(ring.sample_uniform(rng) for _ in range(P_.matrix_rows))
        for _ in range(32**DEPTH)
    ]
    index = 123
    ring_keys[index] = public
    statement = S.Statement(matrix=matrix, keys=tuple(ring_keys), depth=DEPTH)
    proof = S.prove(keys, statement, secret, index, b"transfer-1", rng)
    return keys, statement, secret, index, proof


def test_honest_proof_verifies(built):
    keys, statement, _secret, _index, proof = built
    assert S.verify(keys, statement, proof, b"transfer-1")


def test_the_proof_is_compact_and_encodable(built):
    _keys, _statement, _secret, _index, proof = built
    encoded = proof.encode()
    assert len(encoded) == proof.size_bytes
    # kappa + k + 2m + 2 full elements plus z' and z, as the paper counts them
    elements = P_.challenge_dim + P_.matrix_rows + 2 * DEPTH + 2
    assert proof.size_bytes >= elements * P_.ring_degree * 4
    assert proof.size_bytes < 64_000


def test_a_different_message_is_rejected(built):
    keys, statement, _secret, _index, proof = built
    assert not S.verify(keys, statement, proof, b"transfer-2")


def test_tampered_omega_is_rejected(built):
    keys, statement, _secret, _index, proof = built
    forged = S.Proof(
        commitment=proof.commitment,
        h=proof.h,
        omega=ring.add(proof.omega, ring.constant(1), P_),
        challenge=proof.challenge,
        challenge_prime=proof.challenge_prime,
        response_prime=proof.response_prime,
        response=proof.response,
    )
    assert not S.verify(keys, statement, forged, b"transfer-1")


def test_tampered_h_is_rejected(built):
    keys, statement, _secret, _index, proof = built
    forged = S.Proof(
        commitment=proof.commitment,
        h=ring.add(proof.h, ring.constant(1), P_),
        omega=proof.omega,
        challenge=proof.challenge,
        challenge_prime=proof.challenge_prime,
        response_prime=proof.response_prime,
        response=proof.response,
    )
    assert not S.verify(keys, statement, forged, b"transfer-1")


def test_a_wrong_index_is_refused(built):
    keys, statement, secret, index, _proof = built
    rng = random.Random(9)
    with pytest.raises(S.SetMembershipError, match="does not open"):
        S.prove(keys, statement, secret, index + 1, b"transfer-1", rng)


def test_depth_one_is_refused():
    rng = random.Random(10)
    with pytest.raises(S.SetMembershipError):
        S.setup(rng, 1)


def test_index_vectors_are_one_hot():
    for index in (0, 123, 1023):
        vectors = S._index_vectors(index, DEPTH)
        assert len(vectors) == DEPTH
        assert all(sum(vector) == 1 for vector in vectors)
        flat = 0
        for vector in vectors:
            flat = flat * 32 + vector.index(1)
        assert flat == index

