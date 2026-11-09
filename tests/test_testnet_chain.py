"""The testnet chain: genesis, submission, mining, double-spend rejection.

Fast tests. The verifier is a stub so the harness logic is tested in seconds
rather than the two minutes a real proof costs; the real-crypto path is covered by
`tests/test_testnet_end_to_end.py`, which is marked slow.
"""

import random
from dataclasses import replace

import pytest

from radix_core.candidate_b.lattice import ring, ring_signature as RS
from radix_core.candidate_b.lattice.spend import Output
from radix_testnet import chain as C
from radix_testnet.tagged import TaggedSpend


@pytest.fixture(autouse=True)
def stub_signature_codec(monkeypatch):
    monkeypatch.setattr(C, "SIGNATURE_ENCODER", lambda signature: b"")
    monkeypatch.setattr(C, "SIGNATURE_DECODER", lambda blob, depth, rows: None)


@pytest.fixture
def built():
    rng = random.Random(7)
    parameters = RS.setup(rng, 2, None, 4)
    secret, public = RS.keygen(parameters, rng)
    chain = C.Chain(parameters=parameters, depth=2, verify=lambda p, s: True)
    chain.genesis([(public, 1000)])
    return rng, parameters, secret, public, chain


def _spend(chain, public, rng, value_in=1000, value_out=990, fee=10, tag=None):
    indices = chain.ring_for(public, rng)
    ring_keys = tuple(chain.pool[index] for index in indices)
    note = Output(key=public, value=value_out)
    spend = TaggedSpend(
        anchor=chain.anchor,
        input_values=(value_in,),
        rings=(ring_keys,),
        outputs=(note,),
        fee=fee,
        signatures=(None,),
        tags=((ring.constant(1) if tag is None else tag,),),
    )
    return spend, (indices,)


def test_genesis_creates_the_allocation_and_the_decoy_pool(built):
    _rng, _parameters, _secret, public, chain = built
    assert chain.height == 0
    assert len(chain.outputs) == 1
    assert len(chain.pool) == C.DECOYS + 1
    assert chain.pool[-1] == public
    assert chain.anchor == chain.tip.block_hash()


def test_a_ring_is_1024_distinct_pool_positions_including_the_key(built):
    rng, _parameters, _secret, public, chain = built
    indices = chain.ring_for(public, rng)
    assert len(indices) == C.DECOYS
    assert len(set(indices)) == C.DECOYS
    assert chain.pool.index(public) in indices


def test_submit_admits_a_valid_spend_and_mine_applies_it(built):
    rng, _parameters, _secret, public, chain = built
    spend, indices = _spend(chain, public, rng)
    identifier = chain.submit(spend, indices)
    assert len(chain.mempool) == 1
    assert chain.mempool[identifier]["fee"] == 10

    block = chain.mine()
    assert block.height == 1
    assert block.meets_power()
    assert len(chain.mempool) == 0
    # the output is now spendable and its key joined the ring pool
    assert len(chain.outputs) == 2
    assert chain.pool[-1] == spend.outputs[0].key


def test_a_spend_whose_signature_fails_is_refused(built):
    rng, parameters, _secret, public, _chain = built
    chain = C.Chain(parameters=parameters, depth=2, verify=lambda p, s: False)
    chain.genesis([(public, 1000)])
    spend, indices = _spend(chain, public, rng)
    with pytest.raises(C.ChainError, match="does not verify"):
        chain.submit(spend, indices)


def test_a_second_spend_of_the_same_note_is_refused_by_its_tag(built):
    rng, _parameters, _secret, public, chain = built
    first, indices = _spend(chain, public, rng)
    chain.submit(first, indices)
    chain.mine()

    # re-anchor to the new tip so only the tag stands between this and acceptance
    second, second_indices = _spend(chain, public, rng, tag=ring.constant(1))
    assert second.anchor == chain.anchor
    with pytest.raises(C.ChainError, match="double spend"):
        chain.submit(second, second_indices)


def test_an_unbalanced_spend_is_refused(built):
    rng, _parameters, _secret, public, chain = built
    spend, indices = _spend(chain, public, rng, value_in=1000, value_out=1000, fee=0)
    # forge the values so the totals disagree
    broken = TaggedSpend(
        anchor=spend.anchor,
        input_values=(999,),
        rings=spend.rings,
        outputs=spend.outputs,
        fee=0,
        signatures=spend.signatures,
        tags=spend.tags,
    )
    with pytest.raises(C.ChainError, match="does not balance"):
        chain.submit(broken, indices)


def test_a_spend_anchored_to_another_block_is_refused(built):
    rng, _parameters, _secret, public, chain = built
    spend, indices = _spend(chain, public, rng)
    old_anchor = chain.anchor
    chain.submit(spend, indices)
    chain.mine()
    # A fresh tag and the *old* anchor, so only the anchor check can fire.
    fresh, fresh_indices = _spend(chain, public, rng, tag=ring.constant(2))
    stale = replace(fresh, anchor=old_anchor)
    with pytest.raises(C.ChainError, match="anchored"):
        chain.submit(stale, fresh_indices)


def test_mining_an_empty_mempool_is_refused(built):
    _rng, _parameters, _secret, _public, chain = built
    with pytest.raises(C.ChainError, match="nothing to mine"):
        chain.mine()


def test_a_ring_with_a_repeated_key_is_refused(built):
    rng, _parameters, _secret, public, chain = built
    spend, (indices,) = _spend(chain, public, rng)
    bad = tuple(list(indices)[:1023] + [indices[0]])
    with pytest.raises(C.ChainError, match="distinct"):
        chain.submit(spend, (bad,))
