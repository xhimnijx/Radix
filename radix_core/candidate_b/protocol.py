"""Candidate-B protocol prototype: notes, anchored rings, spends, atomic ledger.

Scope of this prototype, stated honestly:

* **Implemented**: one-time note keys, a depth-64 anchored note tree, linkable
  ring signatures over equal-value notes, deterministic per-note tags, atomic
  block application with double-spend rejection, and a wallet that can build a
  spend from decoys.
* **Not implemented**: post-quantum signatures (the backend is the classical LSAG
  in `lsag.py`), amount hiding and range proofs (values are public, and rings are
  restricted to equal values so the amount does not identify the signer), and
  recipient discovery (a note is addressed to a published one-time key; the PQ
  stealth-address construction is a separate milestone).

The value model is CryptoNote-era: public amounts, denomination-equal rings. That
is a deliberate stepping stone, not the destination. Do not use this to protect
value.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, replace
from hashlib import shake_256

from radix_core.crypto import shake_frame
from radix_core.encoding import frame, u16, u64
from radix_core.merkle import DEPTH, OutputTree, verify_membership

from . import group, lsag

NOTE_TAG = "radix/b/note/v1"
SPEND_TAG = "radix/b/spend/v1"
TAG_BYTES = 32
MIN_ANCHOR_AGE = 60
MAX_INPUTS = 4
MAX_OUTPUTS = 8
MIN_RING_SIZE = 2
MAX_RING_SIZE = 16


class ProtocolError(ValueError):
    """A Candidate-B note, ring, spend, or block is invalid."""


def _point_bytes(point: int) -> bytes:
    return point.to_bytes(TAG_BYTES, "big")


def _check_value(value: int) -> None:
    if type(value) is not int or value < 1:
        raise ProtocolError("note value must be a positive integer")


@dataclass(frozen=True)
class NoteRecord:
    """A note is addressed to a one-time verification key and carries a value."""

    verification_key: int
    value: int

    def __post_init__(self) -> None:
        if not group.is_valid_point(self.verification_key):
            raise ProtocolError("note verification key is not a valid group element")
        _check_value(self.value)

    def leaf(self) -> bytes:
        return shake_frame(NOTE_TAG, _point_bytes(self.verification_key), u64(self.value))


@dataclass(frozen=True)
class NoteKeypair:
    secret: int
    verification_key: int

    def __post_init__(self) -> None:
        if group.scalar_mul(self.secret) != self.verification_key:
            raise ProtocolError("note keypair does not match")


def generate_note_keypair() -> NoteKeypair:
    secret = secrets.randbelow(group.Q - 2) + 1
    return NoteKeypair(secret=secret, verification_key=group.scalar_mul(secret))


@dataclass(frozen=True)
class RingMember:
    index: int
    record: NoteRecord


@dataclass(frozen=True)
class RingInput:
    """One input: a ring of equal-value notes plus its membership paths and signature."""

    ring: tuple[RingMember, ...]
    paths: tuple[tuple[bytes, ...], ...]
    signature: lsag.LinkableRingSignature

    @property
    def value(self) -> int:
        return self.ring[0].record.value

    def tag_bytes(self) -> bytes:
        return self.signature.tag.to_bytes(TAG_BYTES, "big")


@dataclass(frozen=True)
class Transaction:
    anchor_height: int
    root: bytes
    outputs: tuple[NoteRecord, ...]
    fee: int
    inputs: tuple[RingInput, ...] = ()

    def message(self) -> bytes:
        """Canonical bytes every input signature commits to."""
        ring_fields: list[bytes] = []
        for ring_input in self.inputs:
            ring_fields.append(u16(len(ring_input.ring)))
            ring_fields.extend(
                u64(member.index) + member.record.leaf()
                for member in ring_input.ring
            )
        output_fields: list[bytes] = []
        for note in self.outputs:
            output_fields.append(
                _point_bytes(note.verification_key) + u64(note.value)
            )
        return frame(
            SPEND_TAG,
            [u64(self.anchor_height), self.root]
            + ring_fields
            + [u16(len(self.outputs)), *output_fields, u64(self.fee)],
        )

    def replace_signatures(self, signatures: tuple[lsag.LinkableRingSignature, ...]) -> Transaction:
        if len(signatures) != len(self.inputs):
            raise ProtocolError("one signature per input is required")
        inputs = tuple(
            replace(ring_input, signature=signature)
            for ring_input, signature in zip(self.inputs, signatures)
        )
        return replace(self, inputs=inputs)


class LedgerState:
    """Immutable note tree, tag set, and index. Not a persistent node."""

    __slots__ = ("_tree", "tags", "_notes", "_by_value", "_keys", "height", "total_value")

    def __init__(
        self,
        tree: OutputTree,
        tags: frozenset[bytes],
        notes: tuple[NoteRecord, ...],
        height: int,
        total_value: int,
    ) -> None:
        if type(tree) is not OutputTree:
            raise ProtocolError("ledger tree must be the canonical OutputTree type")
        if type(tags) is not frozenset:
            raise ProtocolError("tag set must be a frozenset")
        if type(notes) is not tuple:
            raise ProtocolError("note index must be a tuple")
        if len(notes) != tree.leaf_count:
            raise ProtocolError("note index length does not match the tree")
        self._tree = tree.clone()
        self.tags = tags
        self._notes = notes
        self._by_value: dict[int, tuple[int, ...]] = {}
        by_value: dict[int, list[int]] = {}
        for index, note in enumerate(notes):
            by_value.setdefault(note.value, []).append(index)
        self._by_value = {value: tuple(indices) for value, indices in by_value.items()}
        self._keys = frozenset(note.verification_key for note in notes)
        self.height = height
        self.total_value = total_value

    @classmethod
    def empty(cls) -> LedgerState:
        return cls(OutputTree(), frozenset(), (), 0, 0)

    @classmethod
    def from_notes(
        cls, notes: tuple[NoteRecord, ...], *, height: int = 0
    ) -> LedgerState:
        """Genesis-style fixture: seed the tree with notes and no spends."""
        tree = OutputTree()
        tree.append_many(note.leaf() for note in notes)
        return cls(
            tree=tree,
            tags=frozenset(),
            notes=notes,
            height=height,
            total_value=sum(note.value for note in notes),
        )

    @property
    def root(self) -> bytes:
        return self._tree.root

    @property
    def note_count(self) -> int:
        return len(self._notes)

    def note(self, index: int) -> NoteRecord:
        if type(index) is not int or not 0 <= index < len(self._notes):
            raise ProtocolError("note index out of range")
        return self._notes[index]

    def candidates(self, value: int) -> tuple[int, ...]:
        return self._by_value.get(value, ())

    def authentication_path(self, index: int) -> tuple[bytes, ...]:
        return self._tree.authentication_path(index)

    def contains_key(self, verification_key: int) -> bool:
        return verification_key in self._keys


def _validate_ring_shape(ring: tuple[RingMember, ...], paths: tuple[tuple[bytes, ...], ...]) -> None:
    if not isinstance(ring, tuple) or not MIN_RING_SIZE <= len(ring) <= MAX_RING_SIZE:
        raise ProtocolError(f"ring must contain {MIN_RING_SIZE}..{MAX_RING_SIZE} members")
    if not isinstance(paths, tuple) or len(paths) != len(ring):
        raise ProtocolError("one authentication path per ring member is required")
    indices = [member.index for member in ring]
    if indices != sorted(indices) or len(set(indices)) != len(indices):
        raise ProtocolError("ring indices must be strictly ascending and distinct")
    values = {member.record.value for member in ring}
    if len(values) != 1:
        raise ProtocolError("all ring members must share one value")
    if len({member.record.verification_key for member in ring}) != len(ring):
        raise ProtocolError("ring members must have distinct keys")
    for path in paths:
        if not isinstance(path, tuple) or len(path) != DEPTH:
            raise ProtocolError("each membership path must contain 64 siblings")


def _validate_input(
    transaction: Transaction,
    ring_input: RingInput,
    state: LedgerState,
    staged_tags: set[bytes],
) -> None:
    _validate_ring_shape(ring_input.ring, ring_input.paths)
    if ring_input.value < 1:
        raise ProtocolError("input value must be positive")
    if transaction.root != state.root:
        raise ProtocolError("transaction root does not match the ledger root")
    if not group.is_valid_point(ring_input.signature.tag):
        raise ProtocolError("ring signature tag is not a valid group element")
    tag = ring_input.tag_bytes()
    if tag in state.tags or tag in staged_tags:
        raise ProtocolError("tag has already been spent (double spend)")
    # This prototype keeps only the current note tree, so it anchors at the
    # current root. Branch-relative historical anchors (with root history and
    # old-tree retention) are implemented in Candidate A's `rules.anchor_ok`
    # and are deliberately out of scope here.
    if transaction.anchor_height != state.height:
        raise ProtocolError("prototype anchors at the current block height")
    for member, path in zip(ring_input.ring, ring_input.paths):
        note = state.note(member.index)
        if note != member.record:
            raise ProtocolError("ring member does not match the ledger note")
        if not verify_membership(member.record.leaf(), member.index, path, transaction.root):
            raise ProtocolError("ring member is not in the anchored note tree")

    # Linkability: the tag must be the one derived from the signed ring member.
    keys = tuple(member.record.verification_key for member in ring_input.ring)
    if not lsag.verify(transaction.message(), keys, ring_input.signature):
        raise ProtocolError("ring signature does not verify")

    staged_tags.add(tag)


def validate_transaction(state: LedgerState, transaction: Transaction) -> None:
    if type(transaction) is not Transaction:
        raise ProtocolError("transaction has the wrong type")
    if type(transaction.root) is not bytes or len(transaction.root) != 64:
        raise ProtocolError("transaction root must be 64 bytes")
    if not 1 <= len(transaction.inputs) <= MAX_INPUTS:
        raise ProtocolError(f"transaction needs 1..{MAX_INPUTS} inputs")
    if not 1 <= len(transaction.outputs) <= MAX_OUTPUTS:
        raise ProtocolError(f"transaction needs 1..{MAX_OUTPUTS} outputs")
    if type(transaction.fee) is not int or transaction.fee < 0:
        raise ProtocolError("fee must be a non-negative integer")

    staged_tags: set[bytes] = set()
    for ring_input in transaction.inputs:
        _validate_input(transaction, ring_input, state, staged_tags)

    output_keys = [note.verification_key for note in transaction.outputs]
    if len(set(output_keys)) != len(output_keys):
        raise ProtocolError("transaction outputs must have distinct keys")
    for key in output_keys:
        if state.contains_key(key):
            raise ProtocolError("output key has already been used")
    input_total = sum(ring_input.value for ring_input in transaction.inputs)
    output_total = sum(note.value for note in transaction.outputs)
    if input_total != output_total + transaction.fee:
        raise ProtocolError("input total does not equal output total plus fee")


def apply_block(
    state: LedgerState, height: int, transactions: tuple[Transaction, ...]
) -> LedgerState:
    """Validate every transaction, then commit atomically. No partial state."""
    if type(height) is not int or height <= state.height:
        raise ProtocolError("block height must increase")
    if not isinstance(transactions, tuple):
        raise ProtocolError("block transactions must be a tuple")
    if not transactions:
        raise ProtocolError("block must contain at least one transaction")

    # Anchor age is measured against the block being applied, so transactions
    # are validated against the parent state they were built on.
    staged_tags: set[bytes] = set()
    staged_keys: set[int] = set()
    appended: list[NoteRecord] = []
    minted_value = 0
    for transaction in transactions:
        # Same-block conflicts: tags and output keys must not collide.
        for ring_input in transaction.inputs:
            if ring_input.tag_bytes() in staged_tags:
                raise ProtocolError("duplicate tag within the block")
        for note in transaction.outputs:
            if note.verification_key in staged_keys:
                raise ProtocolError("duplicate output key within the block")
        validate_transaction(state, transaction)
        for ring_input in transaction.inputs:
            staged_tags.add(ring_input.tag_bytes())
        for note in transaction.outputs:
            staged_keys.add(note.verification_key)
            appended.append(note)
        minted_value += sum(note.value for note in transaction.outputs)

    tree = state._tree.clone()
    tree.append_many(note.leaf() for note in appended)
    notes = state._notes + tuple(appended)
    return LedgerState(
        tree=tree,
        tags=state.tags | frozenset(staged_tags),
        notes=notes,
        height=height,
        total_value=state.total_value + minted_value - sum(
            ring_input.value
            for transaction in transactions
            for ring_input in transaction.inputs
        ),
    )


def _decoy_indices(seed: bytes, candidates: tuple[int, ...], exclude: int, count: int) -> list[int]:
    ranked = sorted(
        (index for index in candidates if index != exclude),
        key=lambda index: shake_256(seed + index.to_bytes(8, "big")).digest(16),
    )
    return ranked[:count]


def build_spend(
    keypair: NoteKeypair,
    state: LedgerState,
    spent_index: int,
    outputs: tuple[NoteRecord, ...],
    fee: int,
    *,
    ring_size: int = 4,
    anchor_height: int | None = None,
) -> Transaction:
    """Build and sign a one-input spend with deterministic decoys.

    Decoy selection here is a deterministic hash ranking. That is adequate to
    exercise the protocol, but it is not a privacy-preserving decoy distribution:
    a real deployment must sample decoys from the age/value distribution of
    unspent notes or the ring leaks the true signer.
    """
    note = state.note(spent_index)
    if note.verification_key != keypair.verification_key:
        raise ProtocolError("keypair does not own the note being spent")
    if not MIN_RING_SIZE <= ring_size <= MAX_RING_SIZE:
        raise ProtocolError("ring size out of range")
    candidates = state.candidates(note.value)
    if len(candidates) < ring_size:
        raise ProtocolError("not enough equal-value notes for the requested ring")
    if anchor_height is None:
        anchor_height = state.height
    if anchor_height != state.height:
        raise ProtocolError("prototype anchors at the current block height")

    decoys = _decoy_indices(
        note.leaf(), candidates, spent_index, ring_size - 1
    )
    indices = sorted([spent_index, *decoys])
    ring = tuple(RingMember(index=index, record=state.note(index)) for index in indices)
    paths = tuple(state.authentication_path(index) for index in indices)
    signer_index = indices.index(spent_index)

    unsigned = Transaction(
        anchor_height=anchor_height,
        root=state.root,
        outputs=outputs,
        fee=fee,
        inputs=(
            RingInput(
                ring=ring,
                paths=paths,
                signature=lsag.LinkableRingSignature(tag=0, c0=0, responses=()),
            ),
        ),
    )
    signature = lsag.sign(
        unsigned.message(),
        tuple(member.record.verification_key for member in ring),
        signer_index,
        keypair.secret,
    )
    return unsigned.replace_signatures((signature,))
