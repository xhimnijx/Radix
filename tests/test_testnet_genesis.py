"""Genesis is a protocol constant, not a property of the node.

Before this, the genesis allocation came from whatever wallet the node happened to
create, so two independently started nodes were on different chains and the sync had to
transmit an allocation list -- a shortcut recorded in `p2p.py`. The consequence was
structural: a network only worked if every node was given the same wallet.

Now block zero is derived from a constant in `params.py`, and the phrase is the standard
BIP-39 test vector, which is unmistakably public. **That is a faucet, not a launch**: a
mainnet needs an allocation specified and audited before genesis.
"""

import tempfile

import pytest

from radix_testnet import params as P
from radix_testnet.node import Node


def fresh_node():
    return Node(data_dir=tempfile.mkdtemp(), persist=True, peers=[])


def test_two_independent_nodes_agree_on_block_zero():
    """The claim the item exists for: no communication, same chain."""
    first = fresh_node()
    second = fresh_node()
    assert first.chain.blocks[0].block_hash() == second.chain.blocks[0].block_hash()


def test_the_genesis_allocation_is_derived_from_the_protocol():
    node = fresh_node()
    expected = P.genesis_allocations(node.parameters)
    assert node.chain.genesis_allocations == expected
    assert sum(note.value for note in node.chain.outputs.values()) == (
        P.GENESIS_VALUE * P.GENESIS_NOTES
    )


def test_every_node_holds_the_same_faucet_key():
    """Which means every node can spend the genesis coins -- the faucet model."""
    first = fresh_node()
    second = fresh_node()
    assert first.faucet.accounts[0].public == second.faucet.accounts[0].public
    assert first.faucet.seed == second.faucet.seed
    assert first.faucet.accounts[0].balance > 0


def test_a_node_with_its_own_wallet_still_gets_the_protocol_genesis():
    """The allocation does not follow the operator's wallet, which is the point."""
    from radix_testnet import mnemonic as M
    from radix_testnet.wallet import Wallet

    custom = Wallet.from_mnemonic(M.new_phrase(128), P.parameters())
    node = Node(data_dir=tempfile.mkdtemp(), persist=True, peers=[], faucet=custom)

    assert node.chain.blocks[0].block_hash() == fresh_node().chain.blocks[0].block_hash()
    # And the custom wallet owns none of it, so it has no balance from genesis.
    assert custom.accounts[0].balance == 0


def test_the_sync_payload_no_longer_carries_an_allocation():
    node = fresh_node()
    reply = node.handle_p2p({"type": "getchain"})
    assert "allocations" not in reply
    assert reply["blocks"][0]["height"] == 0
