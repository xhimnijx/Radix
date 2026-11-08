"""Tests for the challenge unit checks (review finding, 2026-11-08).

The line-13 argument divides by c squared and the tag argument by c', so both
must be units of R_q. At this modulus every quartic factor splits, so a unit is
exactly a polynomial with no vanishing NTT coordinate -- and without the check a
non-unit challenge leaves one coordinate where the binaryness constraint is
vacuous.
"""

import random

import pytest

from radix_core.candidate_b.lattice import ntt, params, ring, setmembership as S

P_ = params.SMILE
DEPTH = 2


def _statement(seed: int) -> S.Statement:
    matrix = tuple(
        tuple(ring.sample_uniform(random.Random(seed * 100 + i)) for _ in range(P_.matrix_cols))
        for i in range(P_.matrix_rows)
    )
    keys = tuple(
        tuple(ring.sample_uniform(random.Random(seed * 10_000 + j)) for _ in range(P_.matrix_rows))
        for j in range(32**DEPTH)
    )
    return S.Statement(matrix=matrix, keys=keys, depth=DEPTH)


def test_a_unit_is_exactly_a_polynomial_with_no_vanishing_ntt_coordinate():
    assert S._is_unit(ring.constant(1, P_), P_)
    assert not S._is_unit(ring.zero(P_), P_)
    # X - root vanishes at a root of X^128 + 1, so it is not a unit.
    root = ntt.transform().root
    x_minus_root = ((-root) % P_.modulus, 1 % P_.modulus) + tuple(0 for _ in range(P_.ring_degree - 2))
    assert not S._is_unit(x_minus_root, P_)


def _fake_proof(challenge, challenge_prime) -> S.Proof:
    commitments = S.SMILE.challenge_dim + S.SMILE.matrix_rows + 2 * DEPTH + 1
    return S.Proof(
        commitment=tuple(ring.zero(P_) for _ in range(commitments)),
        h=ring.zero(P_),
        omega=ring.zero(P_),
        challenge=challenge,
        challenge_prime=challenge_prime,
        response_prime=tuple(ring.zero(P_) for _ in range(P_.matrix_cols)),
        response=tuple(ring.zero(P_) for _ in range(S.masking_width(DEPTH))),
    )


def test_a_non_unit_challenge_is_rejected_before_any_work():
    keys = S.setup(random.Random(3), DEPTH)
    proof = _fake_proof(ring.zero(P_), ring.zero(P_))
    assert not S.verify(keys, _statement(1), proof, b"m")


def test_a_non_unit_challenge_prime_is_rejected_too():
    keys = S.setup(random.Random(3), DEPTH)
    proof = _fake_proof(ring.constant(1, P_), ring.zero(P_))
    assert not S.verify(keys, _statement(1), proof, b"m")


@pytest.mark.slow
def test_an_honest_proof_still_verifies_with_the_checks_in_place():
    rng = random.Random(9)
    keys = S.setup(rng, DEPTH)
    matrix = tuple(
        tuple(ring.sample_uniform(rng) for _ in range(P_.matrix_cols))
        for _ in range(P_.matrix_rows)
    )
    secret, public = S.keygen(rng, matrix)
    ring_keys = [
        tuple(ring.sample_uniform(rng) for _ in range(P_.matrix_rows)) for _ in range(32**DEPTH)
    ]
    ring_keys[7] = public
    statement = S.Statement(matrix=matrix, keys=tuple(ring_keys), depth=DEPTH)
    proof = S.prove(keys, statement, secret, 7, b"m", rng)
    assert S._is_unit(proof.challenge, P_) and S._is_unit(proof.challenge_prime, P_)
    assert S.verify(keys, statement, proof, b"m")
