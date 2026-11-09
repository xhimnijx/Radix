"""The withdrawn tagged-spend path is gone, and cannot come back quietly.

These tests used to exercise `spend.build_spend(..., tag_keys=...)`, which reached the
separate tag proof that C1 showed to be forgeable: it bound only a derived row, not
the individual components, so a cheater could supply an unrelated witness. The path is
removed rather than merely deprecated, because "reachable" and "safe" are different
things and a forgotten caller is how a withdrawn construction gets deployed.

A tagged spend is `radix_testnet.tagged.TaggedSpend`, built on
`ring_signature.sign_tagged`, where `T = A' s` is proved inside the same relation.
"""

import random

import pytest

from radix_core.candidate_b.lattice import params, ring, ring_signature as RS
from radix_core.candidate_b.lattice import setmembership as S
from radix_core.candidate_b.lattice.spend import Output, Spend, build_spend, verify_spend

P_ = params.SMILE


def _rig():
    rng = random.Random(21)
    parameters = RS.setup(rng, 2)
    keys = S.setup(rng, 2)
    # The public key must open parameters.matrix, because that is the matrix
    # RS.sign proves the statement over.
    matrix = parameters.matrix
    secret, public = S.keygen(rng, matrix)
    ring_keys = [
        tuple(ring.sample_uniform(rng) for _ in range(P_.matrix_rows))
        for _ in range(32**2)
    ]
    ring_keys[5] = public
    statement = S.Statement(matrix=matrix, keys=tuple(ring_keys), depth=2)
    return rng, parameters, keys, statement, secret, public, tuple(ring_keys)


@pytest.fixture(scope="module")
def built_spend():
    """One real spend, shared. Building it costs a full proof -- about 100 seconds here.

    The first version of this file built a spend inside each test, which made two of
    them 214 of the 320 seconds in the whole fast suite. The suite was slow because of
    that duplication, not because the protocol tests are expensive.
    """
    rng, parameters, _keys, _statement, secret, public, ring_keys = _rig()
    spend = build_spend(
        parameters,
        (secret,),
        (public,),
        (ring_keys,),
        (1000,),
        (Output(key=public, value=1000),),
        0,
        b"\x00" * 32,
        rng,
        P_,
    )
    return parameters, spend


def test_build_spend_does_not_accept_tag_keys():
    """The argument is gone, so a stale caller fails loudly instead of silently."""
    rng, parameters, _keys, _statement, secret, public, ring_keys = _rig()
    with pytest.raises(TypeError):
        build_spend(
            parameters,
            (secret,),
            (public,),
            (ring_keys,),
            (1000,),
            (Output(key=public, value=1000),),
            0,
            b"\x00" * 32,
            rng,
            P_,
            tag_keys=None,
        )


def test_verify_spend_does_not_accept_tag_keys(built_spend):
    parameters, spend = built_spend
    assert verify_spend(parameters, spend, P_)
    with pytest.raises(TypeError):
        verify_spend(parameters, spend, P_, tag_keys=None)


def test_a_spend_never_reports_tags(built_spend):
    """`Spend.tags` used to read `tag_proof`, which the extension does not populate.

    A tagged spend built the new way would have reported `None` there, and a ledger
    checking `if spend.tags is None: skip` would have skipped its tag checks.
    """
    _parameters, spend = built_spend
    assert spend.tags is None


def test_setmembership_refuses_the_withdrawn_tag_keys():
    """Even the low-level entry point refuses, so no caller can reach tag.py's proof."""
    rng, _parameters, keys, statement, secret, _public, _ring_keys = _rig()
    with pytest.raises(S.SetMembershipError, match="WITHDRAWN"):
        S.prove(keys, statement, secret, 5, b"m", rng, P_, tag_keys=object())


def test_the_supported_tagged_type_has_real_tags():
    """The replacement has a tags field of its own, which is the point."""
    from radix_testnet.tagged import TaggedSpend

    assert "tags" in TaggedSpend.__dataclass_fields__
    assert "tags" not in Spend.__dataclass_fields__
