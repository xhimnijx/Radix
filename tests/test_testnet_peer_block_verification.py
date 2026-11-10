"""S-02 / P0-2: a peer's block is verified by default, and a bad proof is refused.

`Chain.append` used to default `verify_transactions=False`, and `node.py` took the default, so a
miner could push blocks full of arbitrary unsigned spends into every peer. This builds a real
signed spend, puts it in a block, and appends it with the flag **omitted** -- the path a peer's
block takes -- against a verifier that rejects.

The point is not that a bad verifier rejects things. It is that omitting the flag consults the
verifier at all: the safe behaviour must be what a new caller gets without thinking about it.
"""

import random

import pytest

from radix_core.candidate_b.lattice.spend import Output
from radix_testnet import params as P
from radix_testnet import tagged as T
from radix_testnet.chain import (
    TARGET_INTERVAL,
    Block,
    Chain,
    ChainError,
    spend_to_wire,
)
from radix_testnet.wallet import Wallet, address_of, parse_address

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def signed_block():
    """A real signed spend, in a block, built once for both tests."""
    parameters = P.parameters()
    faucet = Wallet(seed=P.faucet_seed(), parameters=parameters)
    recipient = Wallet(seed=b"radix-peer-verify-recipient", parameters=parameters)

    chain = Chain(parameters=parameters, depth=P.DEPTH, verify=lambda *a, **k: True)
    chain.genesis([(faucet.accounts[0].public, 4000)])
    faucet.scan(chain)

    # Mine one empty block FIRST, so the spend is anchored to the tip it will be spent from
    # and the coinbase encoding and target come from the chain rather than being invented.
    chain.miner_key = tuple(tuple([5] * 128) for _ in range(4))
    chain.mine(timestamp=chain.tip.timestamp + TARGET_INTERVAL, allow_empty=True)
    tip = chain.tip

    source = faucet.accounts[0]
    indices = (tuple(chain.ring_for(source.public, random.Random(3))),)
    ring_keys = tuple(chain.pool[index] for index in indices[0])
    spend = T.build_tagged_spend(
        parameters,
        secrets=(source.secret,),
        publics=(source.public,),
        rings=(ring_keys,),
        input_values=(source.notes[0].value,),
        # 4000 in = 100 to the recipient + 3890 change + 10 fee.
        outputs=(
            Output(key=parse_address(address_of(recipient.accounts[0].public)), value=100),
            Output(key=source.public, value=source.notes[0].value - 110),
        ),
        fee=10,
        anchor=chain.anchor,
        rng=random.Random(4),
    )
    payload = spend_to_wire(spend, indices)

    fields = dict(
        height=tip.height + 1,
        previous=tip.block_hash(),
        anchor=chain.anchor,
        transactions=(payload,),
        timestamp=tip.timestamp + TARGET_INTERVAL,
        target=tip.target,
        coinbase=tip.coinbase,
    )
    # Mine the nonce: `append` checks the proof of work before anything else.
    block = Block(nonce=0, **fields)
    while not block.meets_power():
        block = Block(nonce=block.nonce + 1, **fields)
        if block.nonce > 1 << 32:
            raise AssertionError("could not mine the test block")
    return chain, block


def test_a_peer_block_with_a_bad_proof_is_refused_by_default(signed_block):
    """The flag is omitted here on purpose: this is the call a peer's block makes."""
    chain, block = signed_block
    chain.verify = lambda *a, **k: False

    with pytest.raises(ChainError, match="signature does not verify"):
        chain.append(block)


def test_the_same_block_is_accepted_when_verification_is_skipped(signed_block):
    """The control: the block itself is well formed, so only verification refuses it."""
    chain, block = signed_block
    chain.verify = lambda *a, **k: False

    chain.append(block, verify_transactions=False)
    assert chain.tip.transactions, "the block's transaction must have been applied"
