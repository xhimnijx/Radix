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
#: Fixed, so two nodes can agree on the genesis block. `int(time.time())` made every
#: node's genesis unique, which made a shared chain impossible.
GENESIS_TIME = 1_700_000_000
POW_BITS = 10
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

    def header(self) -> bytes:
        return b"".join(
            [
                self.height.to_bytes(8, "little"),
                self.previous,
                self.anchor,
                self.nonce.to_bytes(8, "little"),
                self.timestamp.to_bytes(8, "little"),
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
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ChainError(f"malformed block: {error}") from None

    def meets_power(self) -> bool:
        leading = int.from_bytes(self.block_hash()[:2], "big")
        return leading >> (16 - POW_BITS) == 0


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
    def mine(self, timestamp: int | None = None) -> Block:
        """Take the mempool, find a nonce, append the block."""
        if not self.mempool:
            raise ChainError("nothing to mine")
        block = Block(
            height=self.height + 1,
            previous=self.anchor,
            anchor=self.anchor,
            transactions=tuple(self.mempool.values()),
            nonce=0,
            timestamp=int(time.time()) if timestamp is None else timestamp,
        )
        while not block.meets_power():
            block = Block(
                height=block.height,
                previous=block.previous,
                anchor=block.anchor,
                transactions=block.transactions,
                nonce=block.nonce + 1,
                timestamp=block.timestamp,
            )
            if block.nonce > 1 << 24:
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
        if not block.meets_power():
            raise ChainError("block does not meet the proof-of-work target")
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
