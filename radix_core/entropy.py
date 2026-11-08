"""Small CSPRNG boundary for experimental note and wallet material.

The system source delegates to Python's ``secrets`` module. The concrete
cryptography ML-KEM adapter uses OpenSSL's CSPRNG for key generation and
encapsulation. Neither path independently attests the host OS/runtime entropy
or protects key memory. Durable encrypted wallet files and a persistent nonce
registry exist as explicit helpers, but do not provide deterministic seed
recovery, zeroization, or protection from file/database rollback.
"""
from __future__ import annotations

import secrets
from typing import Protocol


class EntropyError(RuntimeError):
    """An entropy source failed or violated its byte-count contract."""


class EntropySource(Protocol):
    def token_bytes(self, length: int) -> bytes:
        """Return exactly ``length`` unpredictable bytes."""
        ...


class SystemEntropySource:
    """Use Python's operating-system-backed ``secrets.token_bytes`` source."""

    def token_bytes(self, length: int) -> bytes:
        return secrets.token_bytes(length)


SYSTEM_ENTROPY = SystemEntropySource()


def draw_random_bytes(length: int, source: EntropySource = SYSTEM_ENTROPY) -> bytes:
    if type(length) is not int or length <= 0:
        raise ValueError("entropy byte count must be a positive integer")
    try:
        method = getattr(source, "token_bytes")
    except Exception as exc:
        raise EntropyError("entropy source has no usable token_bytes method") from exc
    if not callable(method):
        raise EntropyError("entropy source has no usable token_bytes method")
    try:
        result = method(length)
    except Exception as exc:
        raise EntropyError(f"entropy source failed ({type(exc).__name__})") from exc
    if type(result) is not bytes or len(result) != length:
        raise EntropyError("entropy source returned a noncanonical byte count")
    return result


def draw_spend_secret(source: EntropySource = SYSTEM_ENTROPY) -> bytes:
    """Draw the 64-byte spend secret required by the experimental formulas."""
    return draw_random_bytes(64, source)


def draw_note_blinding(source: EntropySource = SYSTEM_ENTROPY) -> tuple[bytes, bytes]:
    """Draw 64-byte candidates for ``rho`` and commitment blinding."""
    return draw_random_bytes(64, source), draw_random_bytes(64, source)


def draw_aead_nonce_v1(source: EntropySource = SYSTEM_ENTROPY) -> bytes:
    """Draw a 96-bit candidate; the AEAD boundary must reserve its key/nonce pair."""
    return draw_random_bytes(12, source)
