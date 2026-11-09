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
        """The first block: no transactions, one block hash to anchor against."""
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
        block = Block(
            height=0,
            previous=GENESIS_PREVIOUS,
            anchor=GENESIS_PREVIOUS,
            transactions=(),
            nonce=0,
            timestamp=int(time.time()),
        )
        self.blocks.append(block)
        self.allocations[block.block_hash()] = sum(value for _key, value in allocations)

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
