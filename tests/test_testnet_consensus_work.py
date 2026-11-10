"""Consensus and wiring defects from the independent review.

Four more, all confirmed in code before being fixed:

1. `cumulative_work` returned `len(self.blocks)`, so a chain of easy blocks beat a chain of
   hard ones -- "most work" was really "most blocks", and a miner who lowered the difficulty
   could outrun everyone by producing more headers.
2. `relay_tx` omitted the p2p secret, so with `RADIX_P2P_SECRET` set, block broadcast was
   authenticated and transaction relay was not. The peer rejected every relayed transaction
   and the sender saw only "unreachable".
3. A peer's block was applied outside `node.lock`, so a peer thread could mutate the chain
   while the miner produced a block or the state was serialised.
4. The verifier carried debug prints in its reject paths, and three functions in
   `ring_signature` were defined twice.
"""

import inspect
import pathlib
import re

from radix_testnet import chain as C
from radix_testnet import node as N
from radix_testnet import params as P

PARAMETERS = P.parameters()


def test_work_is_not_block_count():
    """A harder block must be worth more than an easier one."""
    genesis = C.GENESIS_TARGET
    easy = C.block_work(genesis * 2)
    hard = C.block_work(genesis // 4)
    assert hard > easy, "a harder block must count for more work"
    assert C.block_work(genesis // 2) == 2 * C.block_work(genesis)


def test_cumulative_work_sums_over_blocks_and_targets():
    """Two chains of equal length but different difficulty must not tie."""
    chain = C.Chain(parameters=PARAMETERS, depth=2, verify=lambda *a, **k: True)
    chain.genesis(P.genesis_allocations(PARAMETERS))

    before = chain.cumulative_work()
    assert before == C.block_work(chain.blocks[0].target)

    stamp = C.GENESIS_TIME + C.TARGET_INTERVAL
    chain.miner_key = tuple(tuple([3] * 128) for _ in range(4))
    chain.mine(timestamp=stamp, allow_empty=True)

    after = chain.cumulative_work()
    assert after > before
    assert after == sum(C.block_work(block.target) for block in chain.blocks)


def test_a_chain_of_hard_blocks_beats_a_longer_chain_of_easy_ones():
    """The rule that makes "most work" mean something, stated as an inequality."""
    genesis = C.GENESIS_TARGET
    easy_chain_work = 10 * C.block_work(genesis * 8)      # ten easy blocks
    hard_chain_work = 3 * C.block_work(genesis // 4)      # three hard ones
    assert hard_chain_work > easy_chain_chain if False else hard_chain_work > easy_chain_work


def test_relay_authenticates_like_everything_else():
    source = inspect.getsource(N.Node.relay_tx)
    assert "secret=self.secret" in source, (
        "transaction relay omits the p2p secret, so it silently fails whenever the secret is set"
    )


def test_a_peer_block_is_applied_under_the_lock():
    source = inspect.getsource(N.Node.handle_p2p)
    branch = source[source.index('if kind == "block"') :]
    assert "with self.lock:" in branch, (
        "a peer thread may mutate the chain while the miner is producing a block"
    )


def test_the_verifier_has_no_debug_output():
    source = pathlib.Path(
        "radix_core/candidate_b/lattice/setmembership.py"
    ).read_text(encoding="utf-8")
    assert "RADIX_DEBUG_VERIFY" not in source, "the verifier still prints in its reject paths"
    assert "print(" not in source, "the verifier must not print"


def test_no_function_is_defined_twice_in_ring_signature():
    source = pathlib.Path(
        "radix_core/candidate_b/lattice/ring_signature.py"
    ).read_text(encoding="utf-8")
    for name in ("tag_of", "sign_tagged", "verify_tagged"):
        count = len(re.findall(rf"^def {name}\(", source, re.M))
        assert count == 1, f"{name} is defined {count} times"
