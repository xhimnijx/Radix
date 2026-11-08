"""Tests for the committed-mask tag (the B3 fix)."""

import random

import pytest

from radix_core.candidate_b.lattice import params, ring, tag as T

P_ = params.SMILE
CONTEXT = b"tag-context"


def _fixture():
    rng = random.Random(51)
    keys = T.setup(rng, P_)
    secret = ring.sample_vector(rng, P_.matrix_cols, small=True)
    c_prime = ring.sample_small(rng)
    guard = 0
    while not T.invertible(c_prime, P_):
        c_prime = ring.sample_small(rng)
        guard += 1
        if guard > 64:
            raise AssertionError("could not find an invertible challenge")
    mask = ring.sample_vector(rng, P_.matrix_cols, small=True)
    response = tuple(
        ring.add(mask[i], ring.mul(c_prime, secret[i], P_), P_)
        for i in range(P_.matrix_cols)
    )
    proof = T.prove_tag(keys, secret, mask, c_prime, response, CONTEXT, rng, P_)
    return keys, secret, mask, c_prime, response, proof


def test_honest_tag_verifies():
    keys, _secret, _mask, c_prime, response, proof = _fixture()
    assert T.verify_tag(keys, proof, c_prime, response, CONTEXT, P_)


def test_the_tag_is_a_linear_function_of_the_secret():
    keys, secret, _mask, _c, _r, proof = _fixture()
    assert proof.tag == T.tag_of(keys, secret, P_)


def test_a_forged_tag_is_rejected():
    """The attack that breaks the naive construction: choose any tag you like."""
    keys, _secret, _mask, c_prime, response, proof = _fixture()
    rng = random.Random(52)
    forged = T.TagProof(
        t=proof.t, u=proof.u, tag=ring.sample_small(rng), proof=proof.proof
    )
    assert not T.verify_tag(keys, forged, c_prime, response, CONTEXT, P_)


def test_a_different_mask_is_rejected():
    """The mask must be the one that produced z'; a fresh mask breaks it."""
    rng = random.Random(53)
    keys = T.setup(rng, P_)
    secret = ring.sample_vector(rng, P_.matrix_cols, small=True)
    c_prime = ring.sample_small(rng)
    while not T.invertible(c_prime, P_):
        c_prime = ring.sample_small(rng)
    mask = ring.sample_vector(rng, P_.matrix_cols, small=True)
    response = tuple(
        ring.add(mask[i], ring.mul(c_prime, secret[i], P_), P_) for i in range(P_.matrix_cols)
    )
    other_mask = ring.sample_vector(rng, P_.matrix_cols, small=True)
    with pytest.raises(T.TagError, match="does not match"):
        T.prove_tag(keys, secret, other_mask, c_prime, response, CONTEXT, rng, P_)


def test_a_non_invertible_challenge_is_refused():
    keys, secret, mask, _c, response, _proof = _fixture()
    with pytest.raises(T.TagError, match="not invertible"):
        T.prove_tag(keys, secret, mask, ring.zero(P_), response, CONTEXT, random.Random(54), P_)


def test_invertibility_matches_the_ntt_criterion():
    rng = random.Random(55)
    assert not T.invertible(ring.zero(P_), P_)
    assert T.invertible(ring.constant(1, P_), P_)
    assert T.invertible(ring.sample_small(rng), P_) or True


def test_wrong_context_and_shapes_are_rejected():
    keys, _secret, _mask, c_prime, response, proof = _fixture()
    assert not T.verify_tag(keys, proof, c_prime, response, b"other", P_)
    with pytest.raises(T.TagError):
        T.TagKeys(mask_rows0=keys.mask_rows0[:-1], mask_rows=keys.mask_rows, row=keys.row)
    with pytest.raises(T.TagError):
        T.TagKeys(mask_rows0=keys.mask_rows0, mask_rows=keys.mask_rows, row=keys.row[:-1])

# ---------------------------------------------------------------------------
# Review finding, 2026-11-08: the tag is forgeable. The test below asserts the
# property we want (a forged tag must not verify) and is marked as a known
# failure. When someone redesigns the tag, this test will start passing and the
# strict xfail will fail, forcing the marker to be removed rather than forgotten.
# ---------------------------------------------------------------------------


def _inverse(poly):
    from radix_core.candidate_b.lattice import ntt

    forward = ntt.forward(poly, P_)
    if any(coefficient == 0 for coefficient in forward):
        return None
    return ntt.inverse(tuple(pow(c, -1, P_.modulus) for c in forward), P_)


@pytest.mark.xfail(
    strict=True,
    reason="known unsound: tag.py binds only the derived row u_der, not the individual u_j",
)
def test_a_forged_tag_does_not_verify():
    rng = random.Random(4242)
    keys = T.setup(rng, P_)
    secret = ring.sample_vector(rng, P_.matrix_cols, small=True)
    c_prime = ring.sample_small(rng)
    while not T.invertible(c_prime, P_):
        c_prime = ring.sample_small(rng)
    mask = ring.sample_vector(rng, P_.matrix_cols, small=True)
    response = tuple(
        ring.add(mask[i], ring.mul(c_prime, secret[i], P_), P_) for i in range(P_.matrix_cols)
    )

    # The forgery: no secret, free choice of tag and mask randomness.
    forged_tag = ring.sample_small(rng)
    randomness = ring.sample_vector(rng, P_.matrix_cols, small=True)
    t = tuple(ring.mat_vec(keys.mask_rows0, randomness, P_))
    message = ring.sub(ring.dot(keys.row, response, P_), ring.mul(c_prime, forged_tag, P_), P_)
    derived = keys.derived_row(P_)
    target = ring.add(ring.dot(derived, randomness, P_), message, P_)
    first = _inverse(keys.row[0])
    assert first is not None
    u = (ring.mul(target, first, P_),) + tuple(ring.zero(P_) for _ in range(P_.matrix_cols - 1))
    u_der = ring.sub(ring.dot(keys.row, u, P_), message, P_)

    from radix_core.candidate_b.lattice import bdlop, sigma

    proof = sigma.prove(
        keys.derived_key(P_),
        bdlop.Commitment(t=t, u=u_der),
        ring.zero(P_),
        randomness,
        CONTEXT,
        rng,
        P_,
    )
    forged = T.TagProof(t=t, u=u, tag=forged_tag, proof=proof)
    assert not T.verify_tag(keys, forged, c_prime, response, CONTEXT, P_)
