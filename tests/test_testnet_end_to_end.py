"""End to end with the real proof: wallet -> node -> mempool -> block.

One test, marked slow, and it is the one that matters: everything else in the
harness suite uses a stub verifier, which tests the plumbing but proves nothing
about the cryptography. This runs an actual tagged ring signature over 1024 ring
members, submits it to a node, mines it into a block, and checks that the recipient
can see the note and the sender the change.

It also checks the double spend, because that is what the tag exists for.
"""

import random

import pytest

from radix_core.candidate_b.lattice import params as core_params
from radix_core.candidate_b.lattice.spend import Output
from radix_testnet import params as P
from radix_testnet.chain import Chain, ChainError
from radix_testnet.wallet import Wallet, address_of, parse_address

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def world():
    parameters = P.parameters()
    faucet = Wallet(seed=P.faucet_seed(), parameters=parameters)
    recipient = Wallet(seed=b"radix-testnet-recipient-v1", parameters=parameters)
    chain = Chain(parameters=parameters, depth=P.DEPTH)
    chain.genesis([(faucet.accounts[0].public, 4000)])
    faucet.scan(chain)
    assert faucet.balance == 4000

    rng = random.Random(11)
    spend, indices = faucet.build_spend(chain, address_of(recipient.accounts[0].public), 100, 10, rng)
    return parameters, faucet, recipient, chain, spend, indices


def test_the_spend_envelope_round_trips(world):
    parameters, _faucet, _recipient, chain, spend, indices = world
    from radix_testnet.chain import spend_from_wire, spend_to_wire

    payload = spend_to_wire(spend, indices)
    rebuilt, rebuilt_indices = spend_from_wire(payload, chain.pool, chain.depth, chain.rows)
    assert rebuilt_indices == indices
    assert rebuilt.anchor == spend.anchor
    assert rebuilt.input_values == spend.input_values
    assert rebuilt.fee == spend.fee
    assert rebuilt.outputs == spend.outputs
    assert rebuilt.tags == spend.tags
    assert rebuilt.message() == spend.message()


def test_the_real_verifier_accepts_the_real_proof(world):
    parameters, _faucet, _recipient, chain, spend, _indices = world
    from radix_testnet.tagged import verify_tagged_spend

    assert verify_tagged_spend(parameters, spend)


def test_a_tampered_spend_is_rejected_by_the_real_verifier(world):
    parameters, faucet, recipient, chain, spend, indices = world
    from radix_testnet.tagged import TaggedSpend, verify_tagged_spend

    forged = TaggedSpend(
        anchor=spend.anchor,
        input_values=spend.input_values,
        rings=spend.rings,
        outputs=(Output(key=recipient.accounts[0].public, value=1000),),
        fee=spend.fee,
        signatures=spend.signatures,
        tags=spend.tags,
    )
    assert not verify_tagged_spend(parameters, forged)


def test_the_node_accepts_mines_and_settles_the_real_spend(world):
    _parameters, faucet, recipient, chain, spend, indices = world
    identifier = chain.submit(spend, indices)
    assert identifier in chain.mempool

    block = chain.mine()
    assert block.height == 1
    assert len(block.transactions) == 1
    assert chain.mempool == {}

    # the recipient's account 0 holds the payment
    assert recipient.scan(chain) == 1
    assert recipient.accounts[0].balance == 100
    # the sender's account 0 is now spent (its tag is burned), and the change
    # sits in account 1, because the tag belongs to the key, not the note
    assert faucet.scan(chain) == 1
    assert faucet.accounts[0].balance == 0
    assert faucet.accounts[1].balance == 3890  # 4000 - 100 - 10


def test_a_second_spend_of_the_same_note_is_refused_by_the_tag(world):
    _parameters, _faucet, _recipient, chain, spend, indices = world
    with pytest.raises(ChainError, match="double spend"):
        chain.submit(spend, indices)


def test_the_ring_is_rebuilt_from_indices_not_transmitted(world):
    _parameters, _faucet, _recipient, chain, spend, indices = world
    reconstructed = tuple(tuple(chain.pool[index] for index in ring_) for ring_ in indices)
    assert reconstructed == spend.rings
    # 1024 members, each a 4-polynomial key
    assert len(reconstructed[0]) == 1024
    assert len(reconstructed[0][0]) == core_params.SMILE.matrix_rows


def test_the_faucet_address_round_trips(world):
    _parameters, faucet, _recipient, _chain, _spend, _indices = world
    decoded = parse_address(address_of(faucet.accounts[0].public))
    assert decoded == faucet.accounts[0].public
