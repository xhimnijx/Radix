"""The miner: pop the mempool into a block, find a nonce, repeat.

No difficulty adjustment, no competition, no reward. The proof of work exists so
that a block has to be *found* rather than merely assembled, which keeps the
harness honest about what a block is.
"""

from __future__ import annotations

import time

from .chain import Chain, ChainError


def mine_once(chain: Chain) -> dict:
    block = chain.mine()
    return {
        "height": block.height,
        "hash": block.block_hash().hex(),
        "nonce": block.nonce,
        "transactions": len(block.transactions),
    }


def mine_forever(chain: Chain, interval: float = 2.0, idle_limit: int = 0) -> None:
    """Mine whenever the mempool is non-empty, otherwise wait."""
    mined = 0
    while True:
        if chain.mempool:
            result = mine_once(chain)
            mined += 1
            print(
                f"block {result['height']}  {result['hash'][:16]}…  "
                f"{result['transactions']} tx  nonce {result['nonce']}"
            )
            if idle_limit and mined >= idle_limit:
                return
        time.sleep(interval)


def mine_until_stable(chain: Chain, rounds: int = 1) -> list[dict]:
    """Mine up to `rounds` blocks, stopping as soon as the mempool is empty."""
    out = []
    for _ in range(rounds):
        if not chain.mempool:
            break
        try:
            out.append(mine_once(chain))
        except ChainError:
            break
    return out
