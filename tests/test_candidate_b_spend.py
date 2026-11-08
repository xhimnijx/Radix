"""Tests for the spend layer: lattice ring signatures over a transaction message."""

import random

import pytest

from radix_core.candidate_b.lattice import params, ring, ring_signature as RS, spend as SP

P_ = params.SMILE
DEPTH = 2
ANCHOR = bytes(range(32))


def _random_key(rng):
    return tuple(ring.sample_uniform(rng) for _ in range(P_.matrix_rows))


@pytest.fixture(scope="module")
def built():
    rng = random.Random(21)
    parameters = RS.setup(rng, DEPTH)
    secret, public = RS.keygen(parameters, rng)
    ring_keys = [_random_key(rng) for _ in range(parameters.ring_size)]
    ring_keys[77] = public
    outputs = tuple(
        SP.Output(key=_random_key(rng), value=value) for value in (4, 5)
    )
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
    )
    return parameters, spend


def test_spend_verifies(built):
    parameters, spend = built
    assert spend.balanced
    assert SP.verify_spend(parameters, spend)


def test_message_is_canonical_and_binds_the_outputs(built):
    parameters, spend = built
    message = spend.message()
    assert message == spend.message()
    assert ANCHOR in message
    changed = SP.Spend(
        anchor=spend.anchor,
        input_values=spend.input_values,
        rings=spend.rings,
        outputs=tuple(reversed(spend.outputs)),
        fee=spend.fee,
        signatures=spend.signatures,
    )
    assert changed.message() != message
    assert not SP.verify_spend(parameters, changed)


def test_an_unbalanced_spend_is_rejected(built):
    parameters, spend = built
    greedy = SP.Spend(
        anchor=spend.anchor,
        input_values=spend.input_values,
        rings=spend.rings,
        outputs=spend.outputs,
        fee=1,  # 9 in, 9 + 1 out
        signatures=spend.signatures,
    )
    assert not greedy.balanced
    assert not SP.verify_spend(parameters, greedy)


def test_a_different_anchor_breaks_the_signature(built):
    parameters, spend = built
    moved = SP.Spend(
        anchor=b"\x01" * 32,
        input_values=spend.input_values,
        rings=spend.rings,
        outputs=spend.outputs,
        fee=spend.fee,
        signatures=spend.signatures,
    )
    assert not SP.verify_spend(parameters, moved)


def test_shape_errors_are_rejected():
    with pytest.raises(SP.SpendError):
        SP.Spend(anchor=ANCHOR, input_values=(1,), rings=tuple(), outputs=tuple(), fee=0, signatures=tuple())
    with pytest.raises(SP.SpendError):
        SP.Spend(
            anchor=b"short",
            input_values=(1,),
            rings=tuple(),
            outputs=tuple(),
            fee=0,
            signatures=tuple(),
        )
    with pytest.raises(SP.SpendError):
        SP._u64(-1)
    with pytest.raises(SP.SpendError):
        SP.Output(key=(ring.zero(P_),), value=1).encode()
