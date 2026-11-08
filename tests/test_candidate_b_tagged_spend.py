"""Tagged spends: the double-spend check that SMILE does not provide on its own."""

import random

import pytest

from radix_core.candidate_b.lattice import params, ring, ring_signature as RS, spend as SP, tag as T

pytestmark = pytest.mark.slow

P_ = params.SMILE
DEPTH = 2
ANCHOR = bytes(range(32))


def _random_key(rng):
    return tuple(ring.sample_uniform(rng) for _ in range(P_.matrix_rows))


@pytest.fixture(scope="module")
def built():
    rng = random.Random(71)
    parameters = RS.setup(rng, DEPTH)
    tag_keys = T.setup(rng, P_)
    secret, public = RS.keygen(parameters, rng)
    ring_keys = [_random_key(rng) for _ in range(parameters.ring_size)]
    ring_keys[5] = public
    outputs = tuple(SP.Output(key=_random_key(rng), value=value) for value in (4, 5))
    spend = SP.build_spend(
        parameters,
        (secret,),
        (public,),
        (tuple(ring_keys),),
        (9,),
        outputs,
        0,
        ANCHOR,
        rng,
        None,
        tag_keys,
    )
    return parameters, tag_keys, secret, spend


def test_tagged_spend_verifies(built):
    parameters, tag_keys, _secret, spend = built
    assert SP.verify_spend(parameters, spend, None, tag_keys)


def test_the_tag_is_a_linear_image_of_the_note_secret(built):
    _parameters, tag_keys, secret, spend = built
    tags = spend.tags
    assert tags is not None and len(tags) == 1
    assert tags[0] == ring.encode(T.tag_of(tag_keys, secret, P_))


def test_a_replayed_tag_is_rejected(built):
    _parameters, _tag_keys, _secret, spend = built
    ledger = SP.TagSet().accept(spend)
    assert len(ledger.tags) == 1
    with pytest.raises(SP.SpendError, match="already been spent"):
        ledger.accept(spend)


def test_an_untagged_spend_cannot_be_settled(built):
    """Silently accepting it is exactly the bug that would allow double spending."""
    parameters, _tag_keys, _secret, _spend = built
    rng = random.Random(72)
    secret, public = RS.keygen(parameters, rng)
    ring_keys = [_random_key(rng) for _ in range(parameters.ring_size)]
    ring_keys[1] = public
    outputs = (SP.Output(key=_random_key(rng), value=9),)
    untagged = SP.build_spend(
        parameters, (secret,), (public,), (tuple(ring_keys),), (9,), outputs, 0, ANCHOR, rng
    )
    assert untagged.tags is None
    assert SP.verify_spend(parameters, untagged)  # still a valid authorisation
    with pytest.raises(SP.SpendError, match="untagged"):
        SP.TagSet().accept(untagged)


def test_a_tampered_tag_is_rejected(built):
    parameters, tag_keys, _secret, spend = built
    rng = random.Random(73)
    signature = spend.signatures[0]
    forged = T.TagProof(
        t=signature.tag_proof.t,
        u=signature.tag_proof.u,
        tag=ring.sample_small(rng),
        proof=signature.tag_proof.proof,
    )
    from radix_core.candidate_b.lattice import setmembership as S

    bad_signature = S.Proof(
        commitment=signature.commitment,
        h=signature.h,
        omega=signature.omega,
        challenge=signature.challenge,
        challenge_prime=signature.challenge_prime,
        response_prime=signature.response_prime,
        response=signature.response,
        tag_proof=forged,
    )
    tampered = SP.Spend(
        anchor=spend.anchor,
        input_values=spend.input_values,
        rings=spend.rings,
        outputs=spend.outputs,
        fee=spend.fee,
        signatures=(bad_signature,),
    )
    assert not SP.verify_spend(parameters, tampered, None, tag_keys)
