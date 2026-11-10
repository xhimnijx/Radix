"""Three currency-breaking defects an independent review found, and their fixes.

Each of these was a real path to breaking the ledger, not a style issue:

1. The block hash committed only to `len(transactions)`, so two blocks with completely
   different spends had the same hash. Proof of work secured an ordering of hashes rather
   than a ledger.
2. A block arriving from a peer was applied with `verify_transactions` left at its default
   of False, so a miner could push arbitrary unsigned spends into every peer.
3. Persistence dropped `target`, `coinbase`, `minted`, `immature` and `treasury`, so the
   supply cap reset to zero on restart and the difficulty history was lost.

The tests are written against the behaviour, except where the defect was a wiring omission
that only shows up across a socket -- those assert the wiring directly, and say so.
"""

import inspect
import pathlib
import tempfile

from radix_testnet import chain as C
from radix_testnet import node as N
from radix_testnet import params as P
from radix_testnet import store

PARAMETERS = P.parameters()


def block_with(transactions, nonce=0):
    return C.Block(
        height=1,
        previous=b"\x00" * 32,
        anchor=b"\x01" * 32,
        transactions=tuple(transactions),
        nonce=nonce,
        timestamp=1_700_000_000,
    )


def test_the_block_hash_commits_to_the_transactions():
    """Same count, different spends: the hashes must differ."""
    first = block_with([{"v": 1, "payload": "a"}])
    second = block_with([{"v": 1, "payload": "b"}])
    assert first.block_hash() != second.block_hash(), (
        "two blocks with different spends share a hash, so proof of work secures nothing "
        "about the ledger"
    )


def test_the_block_hash_distinguishes_the_number_of_transactions():
    one = block_with([{"v": 1, "payload": "a"}])
    two = block_with([{"v": 1, "payload": "a"}, {"v": 1, "payload": "b"}])
    assert one.block_hash() != two.block_hash()


def test_identical_transactions_give_an_identical_hash():
    """The root is over the set, so the same set must be the same block."""
    first = block_with([{"v": 1, "payload": "a"}, {"v": 1, "payload": "b"}])
    second = block_with([{"v": 1, "payload": "b"}, {"v": 1, "payload": "a"}])
    assert first.block_hash() == second.block_hash(), (
        "the root must depend on the set of spends, not on their order of arrival"
    )


def test_a_peer_block_is_appended_with_verification():
    """`append` defaults to False for locally mined blocks; a peer's must not.

    This is asserted by inspecting the call site rather than by constructing an invalid
    spend, because building one costs a real proof and the defect was an omission at the
    call site rather than a wrong comparison.
    """
    source = inspect.getsource(N.Node.handle_p2p)
    block_branch = source[source.index('if kind == "block"') :]
    assert "verify_transactions=True" in block_branch, (
        "a block from a peer is applied without verifying its transactions"
    )


def test_the_append_default_stays_false_for_local_blocks():
    """The default must not change: locally mined blocks were already verified."""
    signature = inspect.signature(C.Chain.append)
    assert signature.parameters["verify_transactions"].default is False


def build_chain(blocks=2):
    chain = C.Chain(parameters=PARAMETERS, depth=2, verify=lambda *a, **k: True)
    chain.genesis(P.genesis_allocations(PARAMETERS))
    stamp = C.GENESIS_TIME
    for index in range(blocks):
        stamp += C.TARGET_INTERVAL
        chain.miner_key = tuple(tuple([index + 1] * 128) for _ in range(4))
        chain.mine(timestamp=stamp, allow_empty=True)
    return chain


def test_a_restart_does_not_reset_the_supply_cap():
    chain = build_chain()
    assert chain.minted > 0, "the chain must have minted something to test"

    work = pathlib.Path(tempfile.mkdtemp())
    store.save_chain(chain, work)
    reloaded = store.load_chain(work, PARAMETERS, lambda *a, **k: True)

    assert reloaded.minted == chain.minted, (
        "the supply cap's running total reset on restart, which is the same as no cap"
    )


def test_a_restart_does_not_reset_the_difficulty():
    chain = build_chain(3)
    work = pathlib.Path(tempfile.mkdtemp())
    store.save_chain(chain, work)
    reloaded = store.load_chain(work, PARAMETERS, lambda *a, **k: True)

    assert [block.target for block in reloaded.blocks] == [
        block.target for block in chain.blocks
    ]
    assert reloaded.next_target() == chain.next_target(), (
        "a restarted node computes a different next_target and rejects valid peer blocks"
    )


def test_a_restart_keeps_coinbase_addresses_and_maturity():
    chain = build_chain(2)
    work = pathlib.Path(tempfile.mkdtemp())
    store.save_chain(chain, work)
    reloaded = store.load_chain(work, PARAMETERS, lambda *a, **k: True)

    assert [block.coinbase for block in reloaded.blocks] == [
        block.coinbase for block in chain.blocks
    ], "empty coinbase on restart strands every immature reward forever"
    assert reloaded.immature == chain.immature
    assert reloaded.treasury == chain.treasury


def test_an_immature_reward_still_matures_after_a_restart():
    """P0-5's last clause: preserved `immature` must still mature, not merely survive.

    Maturity is a function of the creating height, so a block that keeps the entry and the
    height will mature normally. This test mines past the maturity window after a round trip
    and asserts the reward became spendable.
    """
    from radix_testnet import node as N

    chain = build_chain(1)
    assert chain.immature, "the mined block must have an immature coinbase to test"

    work = pathlib.Path(tempfile.mkdtemp())
    store.save_chain(chain, work)
    reloaded = store.load_chain(work, PARAMETERS, lambda *a, **k: True)
    assert reloaded.immature == chain.immature

    stamp = chain.tip.timestamp
    for _ in range(C.COINBASE_MATURITY + 1):
        stamp += C.TARGET_INTERVAL
        reloaded.miner_key = tuple(tuple([7] * 128) for _ in range(4))
        reloaded.mine(timestamp=stamp, allow_empty=True)

    # The *original* reward must be spendable; the blocks mined during this test are still
    # inside the maturity window themselves and are correctly still immature.
    stranded = set(chain.immature) & set(reloaded.immature)
    assert not stranded, (
        f"rewards created before the restart did not mature afterwards: {len(stranded)} "
        "entries are still locked, so they are stranded forever"
    )
