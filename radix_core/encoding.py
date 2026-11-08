"""Strict, dependency-free canonical primitives for the experimental Radix v1 profile."""
from __future__ import annotations

from collections.abc import Iterable, Sequence

U8_MAX = (1 << 8) - 1
U16_MAX = (1 << 16) - 1
U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1
MAGIC = b"RADIX"
FRAME_VERSION = 1


def _uint(value: int, bits: int) -> int:
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ValueError(f"value must be an unsigned {bits}-bit integer")
    return value


def u8(value: int) -> bytes:
    return _uint(value, 8).to_bytes(1, "little")


def u16(value: int) -> bytes:
    return _uint(value, 16).to_bytes(2, "little")


def u32(value: int) -> bytes:
    return _uint(value, 32).to_bytes(4, "little")


def u64(value: int) -> bytes:
    return _uint(value, 64).to_bytes(8, "little")


def read_uint(data: bytes, offset: int, width: int) -> tuple[int, int]:
    if type(data) is not bytes or type(offset) is not int or type(width) is not int:
        raise ValueError("data, offset, and width must have exact bytes/int types")
    if width not in (1, 2, 4, 8) or not 0 <= offset <= len(data) - width:
        raise ValueError("truncated or invalid integer field")
    return int.from_bytes(data[offset : offset + width], "little"), offset + width


def bytes_field(value: bytes) -> bytes:
    if type(value) is not bytes:
        raise ValueError("byte field must be bytes")
    if len(value) > U32_MAX:
        raise ValueError("byte field exceeds U32 length")
    return u32(len(value)) + value


def encode_vec(values: Iterable[bytes], *, max_count: int = U16_MAX) -> bytes:
    """Encode a vector, consuming at most ``max_count + 1`` input items."""
    if type(max_count) is not int or not 0 <= max_count <= U16_MAX:
        raise ValueError("invalid vector count limit")
    encoded_items: list[bytes] = []
    for item in values:
        if len(encoded_items) >= max_count:
            raise ValueError("vector count exceeds limit")
        encoded_items.append(bytes_field(item))
    return u16(len(encoded_items)) + b"".join(encoded_items)


def _tag_bytes(tag: str) -> bytes:
    if type(tag) is not str:
        raise ValueError("frame tag must be a string")
    try:
        encoded = tag.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("frame tag must be ASCII") from exc
    if not encoded or len(encoded) > U16_MAX:
        raise ValueError("frame tag length is invalid")
    return encoded


def frame(tag: str, fields: Sequence[bytes]) -> bytes:
    tag_bytes = _tag_bytes(tag)
    if len(fields) > U16_MAX:
        raise ValueError("frame argument count exceeds U16")
    if any(type(field) is not bytes for field in fields):
        raise ValueError("frame fields must be bytes")
    return (
        MAGIC
        + u8(FRAME_VERSION)
        + u16(len(tag_bytes))
        + tag_bytes
        + u16(len(fields))
        + b"".join(bytes_field(field) for field in fields)
    )


def decode_vec(
    data: bytes,
    *,
    min_count: int,
    max_count: int,
    max_item_length: int,
    exact_item_length: int | None = None,
) -> list[bytes]:
    if type(data) is not bytes:
        raise ValueError("vector encoding must be bytes")
    if (
        type(min_count) is not int
        or type(max_count) is not int
        or not 0 <= min_count <= max_count <= U16_MAX
    ):
        raise ValueError("invalid vector count limits")
    if type(max_item_length) is not int or not 0 <= max_item_length <= U32_MAX:
        raise ValueError("invalid item length limit")
    if exact_item_length is not None and (
        type(exact_item_length) is not int
        or not 0 <= exact_item_length <= max_item_length
    ):
        raise ValueError("invalid exact item length")
    count, offset = read_uint(data, 0, 2)
    if not min_count <= count <= max_count:
        raise ValueError("vector count outside permitted range")
    items: list[bytes] = []
    for _ in range(count):
        length, offset = read_uint(data, offset, 4)
        if length > max_item_length:
            raise ValueError("vector item exceeds length limit")
        end = offset + length
        if end > len(data):
            raise ValueError("truncated vector item")
        item = data[offset:end]
        if exact_item_length is not None and len(item) != exact_item_length:
            raise ValueError("noncanonical vector item length")
        items.append(item)
        offset = end
    if offset != len(data):
        raise ValueError("trailing vector bytes")
    return items


def decode_frame(
    data: bytes,
    expected_tag: str,
    field_lengths: Sequence[int | tuple[int, int]],
) -> list[bytes]:
    """Decode a frame; each schema entry is an exact length or inclusive range."""
    if type(data) is not bytes:
        raise ValueError("frame encoding must be bytes")
    expected_tag_bytes = _tag_bytes(expected_tag)
    minimum_header = len(MAGIC) + 1 + 2 + len(expected_tag_bytes) + 2
    if len(data) < minimum_header or data[: len(MAGIC)] != MAGIC:
        raise ValueError("bad frame magic or truncated header")
    if data[len(MAGIC)] != FRAME_VERSION:
        raise ValueError("unsupported frame version")

    tag_len, offset = read_uint(data, len(MAGIC) + 1, 2)
    if tag_len != len(expected_tag_bytes):
        raise ValueError("unexpected frame tag length")
    tag_end = offset + tag_len
    if tag_end > len(data) or data[offset:tag_end] != expected_tag_bytes:
        raise ValueError("unexpected frame tag")
    count, offset = read_uint(data, tag_end, 2)
    if count != len(field_lengths):
        raise ValueError("unexpected frame argument count")

    result: list[bytes] = []
    for schema in field_lengths:
        length, offset = read_uint(data, offset, 4)
        if type(schema) is int:
            minimum = maximum = schema
        else:
            if len(schema) != 2:
                raise ValueError("invalid field length schema")
            minimum, maximum = schema
        if type(minimum) is not int or type(maximum) is not int or not 0 <= minimum <= maximum:
            raise ValueError("invalid field length schema")
        if not minimum <= length <= maximum:
            raise ValueError("frame field length outside permitted range")
        end = offset + length
        if end > len(data):
            raise ValueError("truncated frame field")
        result.append(data[offset:end])
        offset = end
    if offset != len(data):
        raise ValueError("trailing frame bytes")
    return result
