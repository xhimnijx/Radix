"""S-01: the inflation failure, reproduced as a test that currently PASSES.

This test asserts that the forgery is **accepted**. That is not a mistake -- it is the whole
point of S-01. An independent review demonstrated that a spend claiming a 1,000,000,000-atom
input against a 4,000-atom genesis is built by the real prover, accepted by the real verifier,
admitted by `Chain.submit`, and mined into a block. This file pins that behaviour so it cannot be
quietly forgotten, and so that the fix has something to turn red.

**When P0-1 lands, invert this test**: the assertions below become `pytest.raises(ChainError)`
and the module loses its `xfail`-like framing. Until then, a passing run of this file is a
statement that the currency can mint.

What is and is not forged:

- The ring membership proof is **real**. The secret genuinely opens a ring member and the
  signature verifies. Nothing about the cryptography is bypassed.
- The `input_values` are **fabricated**. They are bound into the signed message
  (`SP._message(anchor, input_values, outputs, fee)`), so the prover signs the lie rather than
  having it bolted on afterwards -- the proof is valid *for those values*.

That is exactly why this is a design defect and not a coding slip: nothing in the system has a
notion of which note the input values came from.
"""

import random

import pytest

from radix_core.candidate_b.lattice import params as core_params
from radix_core.candidate_b.lattice.spend import Output
from radix_testnet import params as P
from radix_testnet import tagged as T
from radix_testnet.chain import Chain
from radix_testnet.wallet import Wallet, address_of, parse_address

pytestmark = pytest.mark.slow

GENESIS_ATOMS = 4000
FORGED_INPUT = 1_000_000_000
RECIPIENT_ATOMS = 999_999_990
FEE = 10


def forged_world():
    """A genesis-sized wallet, and a spend that claims far more than exists."""
    parameters = P.parameters()
    faucet = Wallet(seed=P.faucet_seed(), parameters=parameters)
    recipient = Wallet(seed=b"radix-testnet-forgery-recipient", parameters=parameters)
    chain = Chain(parameters=parameters, depth=P.DEPTH)
    chain.genesis([(faucet.accounts[0].public, GENESIS_ATOMS)])
    faucet.scan(chain)
    assert faucet.balance == GENESIS_ATOMS, "the fixture must start poor"

    source = faucet.accounts[0]
    generator = random.Random(2026)
    # One ring's indices per input: the shape `submit` expects.
    indices = (tuple(chain.ring_for(source.public, generator)),)
    ring_keys = tuple(chain.pool[index] for index in indices[0])

    spend = T.build_tagged_spend(
        parameters,
        secrets=(source.secret,),
        publics=(source.public,),
        rings=(ring_keys,),
        # The forgery: the note is worth 4,000, the claim is 1,000,000,000.
        input_values=(FORGED_INPUT,),
        outputs=(Output(key=parse_address(address_of(recipient.accounts[0].public)),
                        value=RECIPIENT_ATOMS),),
        fee=FEE,
        anchor=chain.anchor,
        rng=random.Random(7),
    )
    return chain, spend, indices, recipient


def test_the_forgery_is_accepted_by_the_chain():
    """INVERT THIS WHEN P0-1 LANDS. A pass here means the ledger cannot count."""
    chain, spend, indices, _recipient = forged_world()

    # The declared values balance, which is all the chain checks.
    assert sum(spend.input_values) == sum(note.value for note in spend.outputs) + spend.fee
    assert spend.input_values[0] > GENESIS_ATOMS * 1000

    identifier = chain.submit(spend, indices)      # accepted
    assert identifier is not None

    chain.miner_key = tuple(tuple([9] * 128) for _ in range(4))
    chain.mine(timestamp=1_800_000_000, allow_empty=False)

    assert len(chain.blocks) == 2
    assert chain.blocks[1].transactions, "the forged spend must be in the block"


def test_the_recipient_end_up_richer_than_the_whole_chain_ever_minted():
    """The consequence, stated numerically so a regression is unmistakable."""
    chain, spend, indices, recipient = forged_world()
    chain.submit(spend, indices)
    chain.miner_key = tuple(tuple([9] * 128) for _ in range(4))
    chain.mine(timestamp=1_800_000_000, allow_empty=False)

    recipient.scan(chain)
    minted = chain.minted
    held = recipient.balance

    assert held == RECIPIENT_ATOMS
    assert held > minted, (
        f"the recipient holds {held} atoms and the chain has only ever minted {minted}; "
        "this is the inflation, and it is expected to FAIL once value is bound to notes"
    )
