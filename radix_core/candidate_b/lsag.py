"""Linkable ring signature (LSAG), the engine of a Monero-style spend.

The construction is the Abe-Ohkubo-Suzuki / Liu-Wei-Wong linkable ring signature,
instantiated over the prototype Schnorr group. It provides:

* **Signer ambiguity**: an adversary without any ring member's secret cannot tell
  which index signed.
* **Linkability**: for a given verification key the tag is deterministic, so a
  second spend of the same note reveals the same tag and consensus rejects it.
* **Unforgeability**: without a ring member's secret the challenge chain cannot be
  closed (standard Fiat-Shamir/Schnorr argument in the random-oracle model).

It is **not post-quantum**: the group is discrete-log based. It is the classical
stand-in for a lattice linkable ring signature (SMILE-class); the protocol layer
only depends on the `LinkableRingSignature` interface, so the backend is swappable.

Security limitations of this reference implementation: pure-Python big integers
(no constant-time guarantees), no transcript framing beyond the domain-separated
hash, and no batch verification. Do not use it to protect value.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .group import (
    G,
    P,
    Q,
    decode_point,
    decode_scalar,
    encode_point,
    encode_scalar,
    hash_to_point,
    hash_to_scalar,
    is_valid_point,
    point_mul,
    point_pow,
    scalar_mul,
)

RING_SIGNATURE_TAG = b"radix/b/lsag/v1"
MIN_RING_SIZE = 1
MAX_RING_SIZE = 64


class RingSignatureError(ValueError):
    """A ring signature is malformed or does not verify."""


@dataclass(frozen=True)
class LinkableRingSignature:
    """`tag` is the deterministic linkability marker; `c0` seeds the chain."""

    tag: int
    c0: int
    responses: tuple[int, ...]

    def encode(self) -> bytes:
        return (
            encode_point(self.tag)
            + encode_scalar(self.c0)
            + b"".join(encode_scalar(response) for response in self.responses)
        )

    @classmethod
    def decode(cls, data: bytes, ring_size: int) -> LinkableRingSignature:
        if type(ring_size) is not int or not MIN_RING_SIZE <= ring_size <= MAX_RING_SIZE:
            raise RingSignatureError("ring size out of range")
        expected = 64 + 32 * ring_size
        if type(data) is not bytes or len(data) != expected:
            raise RingSignatureError("ring signature encoding has the wrong length")
        try:
            tag = decode_point(data[:32])
            c0 = decode_scalar(data[32:64])
            responses = tuple(
                decode_scalar(data[64 + 32 * index : 96 + 32 * index])
                for index in range(ring_size)
            )
        except ValueError as exc:
            raise RingSignatureError(f"malformed ring signature: {exc}") from exc
        return cls(tag=tag, c0=c0, responses=responses)


def _challenge(message: bytes, tag: int, left: int, right: int) -> int:
    return hash_to_scalar(
        RING_SIGNATURE_TAG,
        message,
        tag.to_bytes(32, "big"),
        left.to_bytes(32, "big"),
        right.to_bytes(32, "big"),
    )


def _ring_points(ring: tuple[int, ...]) -> tuple[int, ...]:
    if type(ring) is not tuple or not MIN_RING_SIZE <= len(ring) <= MAX_RING_SIZE:
        raise RingSignatureError(
            f"ring must be a tuple of {MIN_RING_SIZE}..{MAX_RING_SIZE} members"
        )
    if any(not is_valid_point(point) for point in ring):
        raise RingSignatureError("ring contains an invalid group element")
    if len(set(ring)) != len(ring):
        raise RingSignatureError("ring members must be distinct")
    return ring


def tag_for(secret: int, verification_key: int) -> int:
    """Deterministic per-note tag: I = Hp(Y)^x. Only the note owner can compute it."""
    if type(secret) is not int or not 1 <= secret < Q:
        raise RingSignatureError("secret out of range")
    ring_point = _ring_points((verification_key,))[0]
    return point_pow(hash_to_point(ring_point.to_bytes(32, "big")), secret)


def sign(
    message: bytes,
    ring: tuple[int, ...],
    signer_index: int,
    secret: int,
) -> LinkableRingSignature:
    """Sign `message` proving knowledge of a secret for one ring member."""
    if type(message) is not bytes:
        raise RingSignatureError("message must be bytes")
    ring = _ring_points(ring)
    if type(signer_index) is not int or not 0 <= signer_index < len(ring):
        raise RingSignatureError("signer index out of range")
    if type(secret) is not int or not 1 <= secret < Q:
        raise RingSignatureError("secret out of range")
    if scalar_mul(secret) != ring[signer_index]:
        raise RingSignatureError("secret does not match the signing ring member")

    size = len(ring)
    tag = tag_for(secret, ring[signer_index])
    nonce = secrets.randbelow(Q - 1) + 1

    challenges = [0] * size
    responses = [0] * size

    first = (signer_index + 1) % size
    challenges[first] = _challenge(
        message,
        tag,
        scalar_mul(nonce),
        point_pow(hash_to_point(ring[signer_index].to_bytes(32, "big")), nonce),
    )

    index = first
    while index != signer_index:
        response = secrets.randbelow(Q - 1) + 1
        responses[index] = response
        left = point_mul(scalar_mul(response), point_pow(ring[index], challenges[index]))
        right = point_mul(
            point_pow(hash_to_point(ring[index].to_bytes(32, "big")), response),
            point_pow(tag, challenges[index]),
        )
        index = (index + 1) % size
        challenges[index] = _challenge(message, tag, left, right)

    responses[signer_index] = (nonce - secret * challenges[signer_index]) % Q
    return LinkableRingSignature(
        tag=tag, c0=challenges[0], responses=tuple(responses)
    )


def verify(
    message: bytes, ring: tuple[int, ...], signature: LinkableRingSignature
) -> bool:
    """Return True iff the signature closes the challenge chain over `ring`."""
    try:
        ring = _ring_points(ring)
        if type(signature) is not LinkableRingSignature:
            return False
        if len(signature.responses) != len(ring):
            return False
        if not is_valid_point(signature.tag):
            return False
        if not 0 <= signature.c0 < Q:
            return False
        if any(not 0 <= response < Q for response in signature.responses):
            return False

        points = tuple(
            hash_to_point(point.to_bytes(32, "big")) for point in ring
        )
        challenge = signature.c0
        for index, response in enumerate(signature.responses):
            left = point_mul(scalar_mul(response), point_pow(ring[index], challenge))
            right = point_mul(
                point_pow(points[index], response), point_pow(signature.tag, challenge)
            )
            challenge = _challenge(message, signature.tag, left, right)
        return challenge == signature.c0
    except (ValueError, TypeError):
        return False
