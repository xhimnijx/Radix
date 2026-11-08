"""Deterministic Candidate-A relation/anchor checks suitable for a reference model."""
from __future__ import annotations

from dataclasses import dataclass

from .encoding import U64_MAX

MIN_ANCHOR_AGE = 60


def balance_ok(inputs: list[int] | tuple[int, ...], outputs: list[int] | tuple[int, ...], fee: int) -> bool:
    """Check exact integer conservation, not a field-modular equation."""
    if type(fee) is not int or not 0 <= fee <= U64_MAX:
        return False
    if type(inputs) not in (list, tuple) or type(outputs) not in (list, tuple):
        return False
    if not 1 <= len(inputs) <= 16 or not 1 <= len(outputs) <= 16:
        return False
    if any(type(value) is not int or not 1 <= value <= U64_MAX for value in (*inputs, *outputs)):
        return False
    return sum(inputs) == sum(outputs) + fee


@dataclass(frozen=True)
class BlockHeaderRef:
    """Minimal parent-linked header fixture; not a serialized consensus header."""

    block_id: bytes
    parent_id: bytes | None
    height: int
    output_root: bytes

    def __post_init__(self) -> None:
        if type(self.block_id) is not bytes or len(self.block_id) != 32:
            raise ValueError("block ID must be 32 bytes")
        if self.parent_id is not None and (type(self.parent_id) is not bytes or len(self.parent_id) != 32):
            raise ValueError("parent ID must be 32 bytes or None")
        if type(self.height) is not int or not 0 <= self.height <= U64_MAX:
            raise ValueError("height must be a U64")
        if type(self.output_root) is not bytes or len(self.output_root) != 64:
            raise ValueError("output root must be 64 bytes")


def _header_is_canonical(header: object) -> bool:
    try:
        return (
            type(header) is BlockHeaderRef
            and type(header.block_id) is bytes
            and len(header.block_id) == 32
            and (
                header.parent_id is None
                or (type(header.parent_id) is bytes and len(header.parent_id) == 32)
            )
            and type(header.height) is int
            and 0 <= header.height <= U64_MAX
            and type(header.output_root) is bytes
            and len(header.output_root) == 64
        )
    except AttributeError:
        return False


def anchor_ok(
    candidate_height: int,
    parent_id: bytes,
    anchor_height: int,
    supplied_root: bytes,
    headers: dict[bytes, BlockHeaderRef],
) -> bool:
    """Resolve anchor only on the candidate parent's exact branch ancestry."""
    if type(candidate_height) is not int or not 0 <= candidate_height <= U64_MAX:
        return False
    if type(anchor_height) is not int or not 0 <= anchor_height <= U64_MAX:
        return False
    # Future anchor is rejected before any subtraction.
    if anchor_height > candidate_height:
        return False
    if type(parent_id) is not bytes or len(parent_id) != 32:
        return False
    if type(supplied_root) is not bytes or len(supplied_root) != 64:
        return False
    if type(headers) is not dict:
        return False
    parent = headers.get(parent_id)
    if (
        not _header_is_canonical(parent)
        or parent.block_id != parent_id
        or parent.height != candidate_height - 1
    ):
        return False
    if candidate_height - anchor_height < MIN_ANCHOR_AGE:
        return False

    cursor = parent
    seen: set[bytes] = set()
    while cursor.height > anchor_height:
        if cursor.block_id in seen or cursor.parent_id is None:
            return False
        seen.add(cursor.block_id)
        previous = headers.get(cursor.parent_id)
        if (
            not _header_is_canonical(previous)
            or previous.block_id != cursor.parent_id
            or previous.height != cursor.height - 1
        ):
            return False
        cursor = previous
    return cursor.height == anchor_height and cursor.output_root == supplied_root
