"""Note recovery plaintext layouts, deliberately separated by profile."""
from __future__ import annotations

from .encoding import U64_MAX, u32, u64

MEMO_MAX = 512
FIXED_PLAINTEXT_LENGTH = 652


def _validate_note(value: int, rho: bytes, randomness: bytes, memo: bytes) -> None:
    if type(value) is not int or not 1 <= value <= U64_MAX:
        raise ValueError("note value must be a nonzero U64")
    if type(rho) is not bytes or len(rho) != 64:
        raise ValueError("rho must be 64 bytes")
    if type(randomness) is not bytes or len(randomness) != 64:
        raise ValueError("note randomness must be 64 bytes")
    if type(memo) is not bytes or len(memo) > MEMO_MAX:
        raise ValueError("memo must be bytes of length at most 512")


def encode_plaintext_v1(value: int, rho: bytes, randomness: bytes, memo: bytes) -> bytes:
    """Variable-size v1 plaintext: U64(v)||rho||r||Bytes(memo)."""
    _validate_note(value, rho, randomness, memo)
    return u64(value) + rho + randomness + u32(len(memo)) + memo


def decode_plaintext_v1(data: bytes) -> tuple[int, bytes, bytes, bytes]:
    if type(data) is not bytes or not 140 <= len(data) <= 140 + MEMO_MAX:
        raise ValueError("v1 plaintext length is outside canonical bounds")
    value = int.from_bytes(data[:8], "little")
    rho, randomness = data[8:72], data[72:136]
    memo_length = int.from_bytes(data[136:140], "little")
    if value == 0 or memo_length > MEMO_MAX or len(data) != 140 + memo_length:
        raise ValueError("noncanonical v1 value or memo length")
    return value, rho, randomness, data[140:]


def encode_padded_proposal(value: int, rho: bytes, randomness: bytes, memo: bytes) -> bytes:
    """Unactivated fixed-size proposal; not valid experimental-v1 serialization."""
    _validate_note(value, rho, randomness, memo)
    return u64(value) + rho + randomness + u32(len(memo)) + memo + bytes(MEMO_MAX - len(memo))


def decode_padded_proposal(data: bytes) -> tuple[int, bytes, bytes, bytes]:
    if type(data) is not bytes or len(data) != FIXED_PLAINTEXT_LENGTH:
        raise ValueError("padded proposal plaintext must be exactly 652 bytes")
    value = int.from_bytes(data[:8], "little")
    rho, randomness = data[8:72], data[72:136]
    memo_length = int.from_bytes(data[136:140], "little")
    if value == 0 or memo_length > MEMO_MAX:
        raise ValueError("noncanonical value or memo length")
    memo_end = 140 + memo_length
    memo = data[140:memo_end]
    if any(data[memo_end:]):
        raise ValueError("nonzero memo padding")
    return value, rho, randomness, memo
