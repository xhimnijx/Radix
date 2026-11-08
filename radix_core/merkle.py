"""Sparse, append-only depth-64 output Merkle tree for reference testing."""
from __future__ import annotations

from collections.abc import Iterable

from .crypto import EMPTY_LEAF, TREE_NODE, shake_frame
from .encoding import U64_MAX, u8

DEPTH = 64
CAPACITY = 1 << DEPTH


def _check_digest(value: bytes, label: str) -> None:
    if type(value) is not bytes or len(value) != 64:
        raise ValueError(f"{label} must be exactly 64 bytes")


def empty_hashes() -> tuple[bytes, ...]:
    values = [shake_frame(EMPTY_LEAF)]
    for level in range(DEPTH):
        values.append(shake_frame(TREE_NODE, u8(level), values[-1], values[-1]))
    return tuple(values)


EMPTY_HASHES = empty_hashes()
EMPTY_ROOT = EMPTY_HASHES[DEPTH]


def check_append_capacity(current_count: int, append_count: int) -> int:
    """Return the resulting 65-bit count or reject an invalid/overflowing append."""
    if type(current_count) is not int or not 0 <= current_count <= CAPACITY:
        raise ValueError("current leaf count is outside [0, 2^64]")
    if type(append_count) is not int or append_count < 0:
        raise ValueError("append count must be a nonnegative integer")
    result = current_count + append_count
    if result > CAPACITY:
        raise ValueError("append exceeds depth-64 tree capacity")
    return result


class OutputTree:
    """Mutable test/reference tree with sparse per-level node maps.

    This keeps only non-default nodes, but cloning currently copies the maps; it
    is an executable correctness model, not a production database/index design.
    """

    __slots__ = ("_nodes", "_leaf_count")

    def __init__(self) -> None:
        self._nodes: list[dict[int, bytes]] = [dict() for _ in range(DEPTH + 1)]
        self._leaf_count = 0

    @property
    def leaf_count(self) -> int:
        return self._leaf_count

    @property
    def root(self) -> bytes:
        return self._nodes[DEPTH].get(0, EMPTY_HASHES[DEPTH])

    def validate_integrity(self) -> None:
        """Recompute every sparse level and reject inconsistent internal state."""
        if type(self._leaf_count) is not int or not 0 <= self._leaf_count <= CAPACITY:
            raise ValueError("tree leaf count is outside [0, 2^64]")
        if type(self._nodes) is not list or len(self._nodes) != DEPTH + 1:
            raise ValueError("tree node-level storage is malformed")
        if type(self._nodes[0]) is not dict or len(self._nodes[0]) != self._leaf_count:
            raise ValueError("tree populated leaves do not match leaf count")

        expected: list[dict[int, bytes]] = [dict() for _ in range(DEPTH + 1)]
        expected[0] = self._nodes[0].copy()
        for level, node_map in enumerate(self._nodes):
            if type(node_map) is not dict:
                raise ValueError("tree node level is not a dictionary")
            bound = 1 << (DEPTH - level)
            for index, digest in node_map.items():
                if type(index) is not int or not 0 <= index < bound:
                    raise ValueError("tree node index is outside its level capacity")
                _check_digest(digest, "tree node")
                if level == 0 and digest == EMPTY_HASHES[0]:
                    raise ValueError("populated leaf equals reserved empty-leaf digest")
            if level == 0:
                if any(index not in node_map for index in range(self._leaf_count)):
                    raise ValueError("tree leaves are not a contiguous append prefix")
                continue

        for level in range(DEPTH):
            parent_indices = {index >> 1 for index in expected[level]}
            for parent_index in parent_indices:
                left_index = parent_index << 1
                left = expected[level].get(left_index, EMPTY_HASHES[level])
                right = expected[level].get(left_index + 1, EMPTY_HASHES[level])
                parent = shake_frame(TREE_NODE, u8(level), left, right)
                if parent != EMPTY_HASHES[level + 1]:
                    expected[level + 1][parent_index] = parent

        if expected != self._nodes:
            raise ValueError("tree node maps are inconsistent with their leaves")

    def clone(self) -> OutputTree:
        duplicate = OutputTree()
        duplicate._nodes = [level.copy() for level in self._nodes]
        duplicate._leaf_count = self._leaf_count
        return duplicate

    def append(self, leaf: bytes) -> int:
        return self.append_many((leaf,))[0]

    def append_many(self, leaves: Iterable[bytes]) -> tuple[int, ...]:
        self.validate_integrity()
        items = tuple(leaves)
        for leaf in items:
            _check_digest(leaf, "tree leaf")
            if leaf == EMPTY_HASHES[0]:
                raise ValueError("populated leaf equals reserved empty-leaf digest")
        new_count = check_append_capacity(self.leaf_count, len(items))
        if not items:
            return ()

        staged = self.clone()
        indices: list[int] = []
        for leaf in items:
            index = staged.leaf_count
            indices.append(index)
            staged._append_one(index, leaf)
            staged._leaf_count += 1
        if staged.leaf_count != new_count:
            raise AssertionError("internal leaf-count invariant failed")
        self._nodes = staged._nodes
        self._leaf_count = staged._leaf_count
        return tuple(indices)

    def _append_one(self, index: int, leaf: bytes) -> None:
        self._nodes[0][index] = leaf
        node_index = index
        for level in range(DEPTH):
            parent_index = node_index >> 1
            left_index = parent_index << 1
            left = self._nodes[level].get(left_index, EMPTY_HASHES[level])
            right = self._nodes[level].get(left_index + 1, EMPTY_HASHES[level])
            parent = shake_frame(TREE_NODE, u8(level), left, right)
            if parent == EMPTY_HASHES[level + 1]:
                self._nodes[level + 1].pop(parent_index, None)
            else:
                self._nodes[level + 1][parent_index] = parent
            node_index = parent_index

    def leaf_at(self, index: int) -> bytes:
        if type(index) is not int or not 0 <= index < self.leaf_count:
            raise ValueError("leaf index is outside the populated range")
        return self._nodes[0][index]

    def authentication_path(self, index: int) -> tuple[bytes, ...]:
        if type(index) is not int or not 0 <= index < self.leaf_count:
            raise ValueError("leaf index is outside the populated range")
        siblings: list[bytes] = []
        node_index = index
        for level in range(DEPTH):
            siblings.append(self._nodes[level].get(node_index ^ 1, EMPTY_HASHES[level]))
            node_index >>= 1
        return tuple(siblings)


def root_from_path(leaf: bytes, index: int, siblings: Iterable[bytes]) -> bytes:
    """Recompute a depth-64 path while consuming at most 65 siblings."""
    _check_digest(leaf, "leaf")
    if type(index) is not int or not 0 <= index <= U64_MAX:
        raise ValueError("leaf index must be a U64")
    path = iter(siblings)
    node = leaf
    for level in range(DEPTH):
        try:
            sibling = next(path)
        except StopIteration as exc:
            raise ValueError("Merkle path must contain exactly 64 siblings") from exc
        _check_digest(sibling, "sibling")
        if (index >> level) & 1:
            node = shake_frame(TREE_NODE, u8(level), sibling, node)
        else:
            node = shake_frame(TREE_NODE, u8(level), node, sibling)

    try:
        next(path)
    except StopIteration:
        return node
    raise ValueError("Merkle path must contain exactly 64 siblings")


def verify_membership(leaf: bytes, index: int, siblings: Iterable[bytes], root: bytes) -> bool:
    try:
        _check_digest(root, "root")
        return root_from_path(leaf, index, siblings) == root
    except (TypeError, ValueError):
        return False
