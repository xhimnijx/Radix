"""A local chain: blocks, mempool, ring pool, and tag-based double-spend rejection.

This is a harness, not a consensus protocol. One process, one chain, no peers, no
fork choice beyond "the longest chain I have", and a proof of work whose only job
is to make a block hash look like a block hash.

What it does do properly: every transaction is checked by the real Candidate-B
verifier before it enters the mempool, and a tag that has already been spent is
refused. That is the whole point of running a node at all -- it exercises the
proof, not a placeholder for it.
"""

from __future__ import annotations

import hashlib
import random
import time
from dataclasses import dataclass, field

from radix_core.candidate_b.lattice import ring, ring_signature as RS
from radix_core.candidate_b.lattice.params import SMILE, SmileParameters
from radix_core.candidate_b.lattice.spend import Output

from . import tagged as T

GENESIS_PREVIOUS = b"\x00" * 32
#: The first 8 bytes of a block hash, read as an integer, must be below the target.
#: Difficulty is the reciprocal of that probability, so `work = 2^64 // target`.
GENESIS_TARGET = 1 << 50
MIN_TARGET = 1 << 32  #: hardest the chain will ever ask for
MAX_TARGET = (1 << 64) - 1  #: easiest, and the width of the field
#: Target spacing, and the LWMA window, from docs/CONSENSUS.md section 3.
TARGET_INTERVAL = 120
LWMA_WINDOW = 90
MEDIAN_WINDOW = 11
FUTURE_DRIFT = 7200

#: Emission, from docs/CONSENSUS.md section 5. Amounts are integer atoms with 100
#: atoms to a unit, so the tail of 0.6 units is representable at all.
ATOMS_PER_UNIT = 100
INITIAL_REWARD_ATOMS = 20 * ATOMS_PER_UNIT  # 20 units
TAIL_REWARD_ATOMS = 60  # 0.6 units, forever
DECAY_BLOCKS = 525_600  # two years at a 120-second block
TREASURY_BPS = 1000  # 10% of every reward
COINBASE_MATURITY = 100  # blocks before a reward can be spent
#: Fixed, so two nodes can agree on the genesis block. `int(time.time())` made every
#: node's genesis unique, which made a shared chain impossible.
GENESIS_TIME = 1_700_000_000
DECOYS = 1024
HASH_BYTES = 32

Poly = tuple[int, ...]


class ChainError(ValueError):
    """A block or transaction the chain refuses."""


def _hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


@dataclass(frozen=True)
class Block:
    height: int
    previous: bytes
    anchor: bytes
    transactions: tuple[dict, ...]
    nonce: int
    timestamp: int
    #: The difficulty this block was mined against, in the first 8 bytes of its hash.
    target: int = GENESIS_TARGET
    #: Encoded public key that receives the block reward, empty for genesis.
    coinbase: bytes = b""

    def header(self) -> bytes:
        return b"".join(
            [
                self.height.to_bytes(8, "little"),
                self.previous,
                self.anchor,
                self.nonce.to_bytes(8, "little"),
                self.timestamp.to_bytes(8, "little"),
                self.target.to_bytes(8, "little"),
                self.coinbase,
                str(len(self.transactions)).encode(),
            ]
        )

    def block_hash(self) -> bytes:
        return _hash(self.header())

    def to_wire(self) -> dict:
        return {
            "height": self.height,
            "previous": self.previous.hex(),
            "anchor": self.anchor.hex(),
            "transactions": list(self.transactions),
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "target": self.target,
            "coinbase": self.coinbase.hex(),
        }

    @classmethod
    def from_wire(cls, payload: dict) -> "Block":
        try:
            return cls(
                height=int(payload["height"]),
                previous=bytes.fromhex(payload["previous"]),
                anchor=bytes.fromhex(payload["anchor"]),
                transactions=tuple(payload["transactions"]),
                nonce=int(payload["nonce"]),
                timestamp=int(payload["timestamp"]),
                target=int(payload.get("target", GENESIS_TARGET)),
                coinbase=bytes.fromhex(payload.get("coinbase", "")),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ChainError(f"malformed block: {error}") from None

    def work(self) -> int:
        """Expected number of hashes this block is worth. Difficulty, in one number."""
        return ((1 << 64) + self.target - 1) // self.target if self.target else 0

    def meets_power(self) -> bool:
        """The first 8 bytes of the hash must be below the target.

        Comparing a fixed prefix keeps the check exact and cheap; the whole 256-bit
        hash would only make low targets marginally more precise.
        """
        return int.from_bytes(self.block_hash()[:8], "big") < self.target


def emission(height: int) -> int:
    """The total reward for a block at `height`, in atoms.

    Linear decay from the initial reward to the tail over `DECAY_BLOCKS`, then the tail
    forever. Linear rather than a halving schedule because a halving cliff is a sudden
    change in the security budget and this chain is small enough that smoothness
    matters more than the Bitcoin resemblance.
    """
    if height < 0:
        raise ChainError("height must not be negative")
    if height >= DECAY_BLOCKS:
        return TAIL_REWARD_ATOMS
    span = INITIAL_REWARD_ATOMS - TAIL_REWARD_ATOMS
    return INITIAL_REWARD_ATOMS - span * height // DECAY_BLOCKS


def split_reward(height: int) -> tuple[int, int]:
    """`(miner_atoms, treasury_atoms)` for a block at `height`."""
    total = emission(height)
    treasury = total * TREASURY_BPS // 10000
    return total - treasury, treasury


def output_id(note: Output, p: SmileParameters = SMILE) -> bytes:
    return _hash(note.encode(p))


@dataclass
class Chain:
    parameters: RS.Parameters
    depth: int
    verify: object = None
    blocks: list[Block] = field(default_factory=list)
    #: Every output ever created. The chain cannot remove a spent one: a ring
    #: signature hides which output it spends, so pruning is impossible without
    #: revealing the link. Double spends are prevented by tags, not by removal.
    outputs: dict[bytes, Output] = field(default_factory=dict)
    spent_tags: set[bytes] = field(default_factory=set)
    pending_tags: set[bytes] = field(default_factory=set)
    mempool: dict[bytes, dict] = field(default_factory=dict)
    pool: list[tuple[Poly, ...]] = field(default_factory=list)
    allocations: dict[bytes, int] = field(default_factory=dict)
    #: The genesis allocation, kept so a replica can be rebuilt from it.
    genesis_allocations: list = field(default_factory=list)
    #: Treasury atoms by the height that credited them. Auditable, unspendable.
    treasury: dict = field(default_factory=dict)
    #: Coinbase outputs that exist but cannot be spent yet: id -> creating height.
    immature: dict = field(default_factory=dict)
    #: The key this node mines to. A foreign block names its own recipient.
    miner_key: tuple | None = None

    # ---------------------------------------------------------------- genesis
    def __post_init__(self) -> None:
        if self.verify is None:
            from . import prover

            self.verify = prover.verify_tagged
        if not self.pool:
            rng = random.Random(1024)
            self.pool = [
                tuple(ring.sample_uniform(rng) for _ in range(SMILE.matrix_rows))
                for _ in range(DECOYS)
            ]

    @property
    def decoy_count(self) -> int:
        """The deterministic decoys, which the store does not need to write out."""
        return DECOYS

    def genesis(self, allocations: list[tuple[tuple[Poly, ...], int]]) -> None:
        """The first block: no transactions, one block hash to anchor against.

        The block's `anchor` field commits to the allocation. Without that, the genesis
        hash depends only on the height, the fixed timestamp and the link value -- so
        two chains whose initial ownership differs completely would share a genesis
        hash, and the network identifier would not determine who owns what at height 0.
        """
        if self.blocks:
            raise ChainError("the chain already has a genesis block")
        for key, value in allocations:
            note = Output(key=key, value=value)
            # Identical outputs hash identically, so only the first survives. The
            # pool must likewise not admit the same key twice: a ring of 1024
            # *distinct* members is a soundness condition, not a preference.
            self.outputs[output_id(note)] = note
            if key not in self.pool:
                self.pool = [*self.pool, key]
        # Canonical order, so the digest does not depend on how the caller listed them.
        canonical = sorted(
            (
                b"".join(ring.encode(poly, SMILE) for poly in key),
                int(value),
            )
            for key, value in allocations
        )
        digest = _hash(
            b"radix/genesis/v1"
            + b"".join(
                key_bytes + int(value).to_bytes(8, "little") for key_bytes, value in canonical
            )
        )
        block = Block(
            height=0,
            previous=GENESIS_PREVIOUS,
            anchor=digest,
            transactions=(),
            nonce=0,
            timestamp=GENESIS_TIME,
            target=GENESIS_TARGET,
        )
        self.blocks.append(block)
        self.allocations[block.block_hash()] = sum(value for _key, value in allocations)
        self.genesis_allocations = list(allocations)

    # ---------------------------------------------------------------- queries
    @property
    def tip(self) -> Block:
        return self.blocks[-1]

    @property
    def rows(self) -> int:
        """The height of the proved matrix: k, or k + k' when tags are folded in."""
        return len(self.parameters.matrix) + self.parameters.tag_rows

    @property
    def anchor(self) -> bytes:
        return self.tip.block_hash()

    @property
    def height(self) -> int:
        return len(self.blocks) - 1

    def ring_for(self, key: tuple[Poly, ...], rng: random.Random) -> tuple[int, ...]:
        """1024 distinct pool indices, including the one that holds `key`."""
        try:
            mine = self.pool.index(key)
        except ValueError:
            raise ChainError("the key is not in the ring pool") from None
        others = [index for index in range(len(self.pool)) if index != mine]
        rng.shuffle(others)
        return tuple([mine, *others[: DECOYS - 1]])

    # ---------------------------------------------------------------- mempool
    def submit(self, spend: T.TaggedSpend, indices: tuple[tuple[int, ...], ...]) -> bytes:
        """Validate and admit a transaction. Returns its id."""
        self._check_spend(spend, indices)
        payload = spend_to_wire(spend, indices)
        identifier = _hash(str(payload).encode())
        self.mempool[identifier] = payload
        self.pending_tags.update(spend.tag_bytes())
        return identifier

    def _check_spend(self, spend: T.TaggedSpend, indices: tuple[tuple[int, ...], ...]) -> None:
        # Tags first: a double spend is the more specific complaint, and a stale
        # anchor would otherwise mask it on a spend that was already mined.
        for tag in spend.tag_bytes():
            if tag in self.spent_tags or tag in self.pending_tags:
                raise ChainError("double spend: this tag has already been used")
        if spend.anchor != self.anchor:
            raise ChainError("the spend is anchored to a different block")
        if not spend.balanced:
            raise ChainError("the spend does not balance")
        for ring_ in indices:
            if len(set(ring_)) != DECOYS:
                raise ChainError("a ring must be 1024 distinct keys")
        if not bool(self.verify(self.parameters, spend)):
            raise ChainError("the ring signature does not verify")

    # ---------------------------------------------------------------- mining
    def median_time_past(self) -> int:
        """Median of the last 11 timestamps; the floor for a new block's time."""
        recent = [block.timestamp for block in self.blocks[-MEDIAN_WINDOW:]]
        ordered = sorted(recent)
        return ordered[len(ordered) // 2]

    def next_target(self) -> int:
        """LWMA over the last 90 solve times, clamped to a factor of two.

        `docs/CONSENSUS.md` section 3. Linear weighting means the newest solve time
        counts 90 times the oldest, which is what lets the chain absorb a hashrate
        change within the window instead of after it.
        """
        if len(self.blocks) < 2:
            return GENESIS_TARGET

        window = min(LWMA_WINDOW, len(self.blocks) - 1)
        weighted = 0
        weights = 0
        for position in range(1, window + 1):
            # `position` counts solve times, so it must index the *earlier* block at
            # `position - 1`. Getting this off by one reverses every interval, which
            # clamps them all to 1 second and tightens the target by the maximum factor
            # on every block -- the chain becomes unmineable within about twenty.
            previous = self.blocks[-(window + 1) + position - 1]
            current = self.blocks[-(window + 1) + position]
            # A zero or negative solve time is a timestamp lie, not a fast block.
            solve = max(1, current.timestamp - previous.timestamp)
            weighted += position * solve
            weights += position
        average = weighted / weights

        base = self.tip.target
        # Blocks arriving faster than TARGET_INTERVAL mean the work per block must go
        # UP, which means the target goes DOWN. The ratio is average / interval, not
        # the other way round -- getting this backwards makes a rush of blocks make
        # the chain easier, which is the opposite of a difficulty adjustment.
        scaled = int(base * (average / TARGET_INTERVAL)) if average else base // 2
        # A single block may move the target by at most 2x, so one bad timestamp
        # cannot collapse the difficulty.
        clamped = max(base // 2, min(base * 2, scaled))
        return max(MIN_TARGET, min(MAX_TARGET, clamped))

    def mine(self, timestamp: int | None = None, allow_empty: bool = False) -> Block:
        """Take the mempool, find a nonce, append the block.

        Empty blocks are refused by default because the wallet's mine button should
        not manufacture them, but a real chain must permit them -- a miner with
        nothing to include still has to produce a block, or the chain stalls.
        `allow_empty` is that path, used by the consensus tests.
        """
        if not self.mempool and not allow_empty:
            raise ChainError("nothing to mine")
        target = self.next_target()
        when = int(time.time()) if timestamp is None else timestamp
        floor = self.median_time_past()
        if when <= floor:
            when = floor + 1
        block = Block(
            height=self.height + 1,
            previous=self.anchor,
            anchor=self.anchor,
            transactions=tuple(self.mempool.values()),
            nonce=0,
            timestamp=when,
            target=target,
            coinbase=(
                b"".join(ring.encode(poly, SMILE) for poly in self.miner_key)
                if self.miner_key is not None
                else b""
            ),
        )
        # Mine against the target, not a fixed number of bits. The nonce bound is a
        # sanity limit rather than a difficulty: at a realistic target the loop exits
        # in thousands of attempts, and a target this chain would never set is the
        # only way to reach it.
        while not block.meets_power():
            block = Block(
                height=block.height,
                previous=block.previous,
                anchor=block.anchor,
                transactions=block.transactions,
                nonce=block.nonce + 1,
                timestamp=block.timestamp,
                target=block.target,
                coinbase=block.coinbase,
            )
            if block.nonce > 1 << 32:
                raise ChainError("no nonce found")
        self._apply(block)
        self.mempool.clear()
        return block

    def append(self, block: Block) -> None:
        """Validate a block that came from somewhere else, then apply it.

        This is the only entry point for foreign blocks, and it refuses anything that
        is not the direct successor of our tip. A fork is reported as a fork rather
        than silently applied -- the chain has no undo journal, so applying a block
        from a competing branch would corrupt state irrecoverably.
        """
        if block.height != self.height + 1:
            raise ChainError(
                f"block height {block.height} does not follow our tip {self.height}"
            )
        if block.previous != self.anchor:
            raise ChainError(
                "block does not build on our tip; this is a fork, and fork "
                "reconciliation is not implemented"
            )
        expected = self.next_target()
        if block.target != expected:
            raise ChainError(
                f"block claims target {block.target} but the chain requires {expected}"
            )
        if not block.meets_power():
            raise ChainError("block does not meet the proof-of-work target")
        floor = self.median_time_past()
        if block.timestamp <= floor:
            raise ChainError(
                f"block timestamp {block.timestamp} is not after the median {floor}"
            )
        if block.timestamp > int(time.time()) + FUTURE_DRIFT:
            raise ChainError("block timestamp is too far in the future")
        self._apply(block)

    def allocations_wire(self) -> list:
        """The genesis allocation, as hex, so a replica can rebuild from it."""
        return [
            [b"".join(ring.encode(poly, SMILE) for poly in key).hex(), value]
            for key, value in self.genesis_allocations
        ]

    @staticmethod
    def allocations_from_wire(payload: list) -> list:
        """Decode the hex allocation list back to keys."""
        chunk = SMILE.ring_degree * 4
        out = []
        for key_hex, value in payload:
            blob = bytes.fromhex(key_hex)
            if len(blob) % chunk:
                raise ChainError("allocation key has the wrong length")
            key = tuple(
                ring.decode(blob[offset : offset + chunk], SMILE)
                for offset in range(0, len(blob), chunk)
            )
            out.append((key, int(value)))
        return out

    def cumulative_work(self) -> int:
        """Sum of difficulty over the chain.

        Difficulty is 1 for every block today, so this equals the height. It is written
        as a sum anyway, so that adding a real difficulty target does not require
        rewriting every caller -- only this function.
        """
        return len(self.blocks)

    @classmethod
    def rebuild(
        cls,
        parameters: RS.Parameters,
        depth: int,
        allocations: list[tuple[tuple[Poly, ...], int]],
        blocks: list[Block],
        verify=None,
    ) -> "Chain":
        """Replay a whole chain from genesis, from another node's view.

        A replica cannot reconstruct the genesis allocation from the blocks, because
        blocks do not carry it; the caller passes the peer's allocation list. On a real
        network that allocation would be fixed by the protocol rather than transmitted,
        and this parameter is the honest marker of the shortcut.
        """
        fresh = cls(parameters=parameters, depth=depth, verify=verify)
        fresh.genesis(allocations)
        for block in blocks[1:]:
            fresh.append(block)
        return fresh

    def _apply(self, block: Block) -> None:
        # Coinbase first: the miner is paid for the block, and the treasury takes its
        # slice. Genesis carries no recipient, so it pays nobody.
        if block.coinbase and block.height > 0:
            miner_atoms, treasury_atoms = split_reward(block.height)
            if treasury_atoms:
                self.treasury[block.height] = treasury_atoms
            if miner_atoms:
                key = self._decode_key(block.coinbase)
                note = Output(key=key, value=miner_atoms)
                identifier = output_id(note)
                self.outputs[identifier] = note
                # A reward is not spendable until COINBASE_MATURITY blocks later, so a
                # chain that reorgs out the block cannot be spent into the new chain.
                self.immature[identifier] = block.height

        for payload in block.transactions:
            spend, indices = spend_from_wire(payload, self.pool, self.depth, self.rows)
            for tag in spend.tag_bytes():
                if tag in self.spent_tags:
                    raise ChainError("double spend: this tag has already been used")
            for note in spend.outputs:
                self.outputs[output_id(note)] = note
                self.pool = [*self.pool, note.key]
            for tag in spend.tag_bytes():
                self.spent_tags.add(tag)
                self.pending_tags.discard(tag)
        self.blocks.append(block)
        self._mature_coinbase()

    def _decode_key(self, blob: bytes) -> tuple:
        chunk = SMILE.ring_degree * 4
        if len(blob) != SMILE.matrix_rows * chunk:
            raise ChainError("coinbase key has the wrong length")
        return tuple(
            ring.decode(blob[offset : offset + chunk], SMILE)
            for offset in range(0, len(blob), chunk)
        )

    def _mature_coinbase(self) -> None:
        """Move coinbase outputs into the ring pool once they are deep enough.

        Maturity is enforced structurally rather than by a check: an immature key is
        not in `pool`, and a ring can only reference the pool. A ring proof hides which
        member is real, so checking a specific output's age is not possible -- making
        every member eligible is what makes the rule sound.
        """
        tip = self.height
        ready = [
            identifier
            for identifier, created in self.immature.items()
            if tip - created >= COINBASE_MATURITY
        ]
        for identifier in ready:
            note = self.outputs[identifier]
            if note.key not in self.pool:
                self.pool = [*self.pool, note.key]
            del self.immature[identifier]


#: Signature codec, as a pair of callables so tests can substitute a stub.
#: The real ones are `codec.encode_proof` and `codec.decode_proof`.
SIGNATURE_ENCODER = None
SIGNATURE_DECODER = None


def _encode_signature(signature) -> bytes:
    if SIGNATURE_ENCODER is not None:
        return SIGNATURE_ENCODER(signature)
    from .codec import encode_proof

    return encode_proof(signature)


def _decode_signature(blob: bytes, depth: int, rows: int):
    if SIGNATURE_DECODER is not None:
        return SIGNATURE_DECODER(blob, depth, rows)
    from .codec import decode_proof

    return decode_proof(blob, depth=depth, rows=rows)


def spend_to_wire(spend: T.TaggedSpend, indices: tuple[tuple[int, ...], ...]) -> dict:

    sm = SMILE
    return {
        "v": 1,
        "anchor": spend.anchor.hex(),
        "input_values": list(spend.input_values),
        "ring_indices": [list(ring_) for ring_ in indices],
        "outputs": [
            {"key": [list(poly) for poly in note.key], "value": note.value}
            for note in spend.outputs
        ],
        "fee": spend.fee,
        "signatures": [_encode_signature(signature).hex() for signature in spend.signatures],
        "tags": [
            [list(poly) for poly in tag] for tag in spend.tags
        ],
        "params": {"ring_degree": sm.ring_degree},
    }


def spend_from_wire(
    payload: dict, pool: list, depth: int, rows: int
) -> tuple[T.TaggedSpend, tuple[tuple[int, ...], ...]]:
    sm = SMILE
    try:
        indices = tuple(tuple(int(index) for index in ring_) for ring_ in payload["ring_indices"])
        rings = tuple(tuple(pool[index] for index in ring_) for ring_ in indices)
        outputs = tuple(
            Output(
                key=tuple(tuple(int(value) for value in poly) for poly in note["key"]),
                value=int(note["value"]),
            )
            for note in payload["outputs"]
        )
        signatures = tuple(
            _decode_signature(bytes.fromhex(blob), depth, rows)
            for blob in payload["signatures"]
        )
        tags = tuple(
            tuple(tuple(int(value) for value in poly) for poly in tag) for tag in payload["tags"]
        )
        spend = T.TaggedSpend(
            anchor=bytes.fromhex(payload["anchor"]),
            input_values=tuple(int(value) for value in payload["input_values"]),
            rings=rings,
            outputs=outputs,
            fee=int(payload["fee"]),
            signatures=signatures,
            tags=tags,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ChainError(str(error)) from None
    return spend, indices
