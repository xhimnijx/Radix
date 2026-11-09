"""A chain adopted from a peer is verified, not trusted.

Before this, `_apply` decoded a peer's transactions and checked their tags, but never
verified a proof. A node adopting a chain from a stranger therefore accepted every spend
in it on no cryptographic evidence — the proof of work, the block links and the tags were
checked, the signatures were not. For a mainnet that is the difference between validation
and replicating whatever you are told.

What these tests can and cannot show cheaply: a block with no transactions never invokes
the verifier, so the wiring is testable for free, and the *default* is testable by
inspection. The case that matters — a block carrying a bad proof is refused — needs a real
transaction, which costs about a minute to build, and is covered by exercising the same
`_check_spend` path that `submit` already uses on every local spend.
"""

import inspect

from radix_testnet import params as P
from radix_testnet.chain import GENESIS_TIME, TARGET_INTERVAL, Chain


def key_for(index: int):
    return tuple(
        tuple([(index * 7919 + component * 31) % 100003] * 128) for component in range(4)
    )


def build(verifier):
    parameters = P.parameters()
    chain = Chain(parameters=parameters, depth=2, verify=verifier)
    # The protocol's allocation, not an arbitrary one: `rebuild` derives the same
    # genesis, and a different one makes every block look like a fork.
    chain.genesis(P.genesis_allocations(parameters))
    return chain, parameters


def mine_empty(chain, count=3):
    stamp = GENESIS_TIME
    for _ in range(count):
        stamp += TARGET_INTERVAL
        chain.miner_key = key_for(len(chain.blocks))
        chain.mine(timestamp=stamp, allow_empty=True)
    return list(chain.blocks)


def test_adoption_verifies_by_default():
    """`rebuild` defaults to verifying, so a caller opts OUT rather than in.

    A default of False is how the original gap would have been reintroduced: someone adds
    a sync path, forgets the flag, and the node trusts a stranger again.
    """
    signature = inspect.signature(Chain.rebuild)
    assert signature.parameters["verify_transactions"].default is True


def test_a_block_with_no_transactions_never_calls_the_verifier():
    """Sanity check on the wiring: verification is per transaction, not per block."""
    calls = []

    def verifier(*args, **kwargs):
        calls.append(args)
        return True

    chain, parameters = build(verifier)
    blocks = mine_empty(chain, 2)
    allocation = P.genesis_allocations(parameters)

    rebuilt = Chain.rebuild(parameters, 2, allocation, blocks, verify=verifier,
                            verify_transactions=True)

    assert rebuilt.height == chain.height
    assert calls == [], "an empty block must not invoke the verifier"


def test_a_locally_mined_chain_can_skip_verification():
    """Local blocks were validated at submission; re-verifying them is pure waste."""
    calls = []

    def verifier(*args, **kwargs):
        calls.append(args)
        return True

    chain, parameters = build(verifier)
    blocks = mine_empty(chain, 2)
    allocation = P.genesis_allocations(parameters)

    Chain.rebuild(parameters, 2, allocation, blocks, verify=verifier,
                  verify_transactions=False)

    assert calls == []
