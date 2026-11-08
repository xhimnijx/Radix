"""Domain-separated Fiat-Shamir transcript shared by the proof layers.

Every challenge in this package is derived by hashing a transcript, so the
soundness of the non-interactive form rests on the transcript being unambiguous:
nothing may be omitted, reordered, or made concatenation-ambiguous. This module
exists so that property is encoded once and tested, instead of being re-derived
(a little differently) in each proof module.

Rules enforced here:

* a domain tag is fixed at construction and absorbed first, so two protocols can
  never collide;
* every absorption is length-prefixed with its label, so ``("a", "bc")`` and
  ``("ab", "c")`` hash differently;
* squeezing is stateful: a second challenge differs from the first, so a prover
  cannot reuse a challenge value across sub-protocols;
* ``clone`` exists so a prover can recompute a verifier's challenges without
  disturbing its own stream.

This is a hash construction, not a proof system; it carries no security claim of
its own beyond collision resistance of SHAKE-256.
"""

from __future__ import annotations

from hashlib import shake_256

TAG = b"radix/b/lattice/transcript/v1"


class TranscriptError(ValueError):
    """A transcript was used with malformed labels, payloads, or sizes."""


class Transcript:
    """Absorb-then-squeeze transcript with length-prefixed framing."""

    __slots__ = ("_domain", "_parts")

    def __init__(self, domain: bytes) -> None:
        if type(domain) is not bytes or not domain:
            raise TranscriptError("domain must be a non-empty byte string")
        if len(domain) > 1 << 16:
            raise TranscriptError("domain is unreasonably long")
        self._domain = domain
        self._parts: tuple[bytes, ...] = (TAG, _frame(b"domain", domain))

    def absorb(self, label: bytes, payload: bytes) -> "Transcript":
        """Absorb `payload` under `label`; returns self so calls can chain."""
        if type(label) is not bytes or type(payload) is not bytes:
            raise TranscriptError("labels and payloads must be bytes")
        self._parts = self._parts + (_frame(label, payload),)
        return self

    def absorb_poly(self, label: bytes, poly: tuple[int, ...]) -> "Transcript":
        """Absorb a polynomial as fixed-width 4-byte coefficients."""
        if type(poly) is not tuple or not poly:
            raise TranscriptError("polynomial must be a non-empty tuple")
        if any(type(value) is not int or not 0 <= value < 1 << 32 for value in poly):
            raise TranscriptError("coefficients must be 32-bit residues")
        return self.absorb(label, b"".join(value.to_bytes(4, "little") for value in poly))

    def challenge(self, label: bytes, length: int) -> bytes:
        """Squeeze `length` bytes, absorbing the request so the stream advances."""
        if type(label) is not bytes or type(length) is not int or length < 1:
            raise TranscriptError("challenge needs a byte label and a positive length")
        if length > 1 << 16:
            raise TranscriptError("challenge is unreasonably long")
        digest = shake_256()
        for part in self._parts + (_squeeze(label, length),):
            digest.update(part)
        value = digest.digest(length)
        self._parts = self._parts + (_frame(b"squeeze", label + length.to_bytes(4, "little") + value),)
        return value

    def challenge_ternary(self, label: bytes, degree: int, weight: int) -> tuple[int, ...]:
        """A sparse ternary challenge with exactly `weight` non-zero coefficients."""
        if type(degree) is not int or degree < 1 or type(weight) is not int or not 1 <= weight <= degree:
            raise TranscriptError("ternary challenge needs 1 <= weight <= degree")
        stream = bytearray()
        while len(stream) < 8 * (2 * weight + 4):
            stream.extend(self.challenge(label, 64))
        positions = list(range(degree))
        coefficients = [0] * degree
        cursor = 0
        for _ in range(weight):
            index = int.from_bytes(stream[cursor : cursor + 4], "little") % len(positions)
            cursor += 4
            coefficients[positions.pop(index)] = 1 if stream[cursor] & 1 else -1
            cursor += 1
        return tuple(coefficients)

    def clone(self) -> "Transcript":
        other = Transcript.__new__(Transcript)
        other._domain = self._domain
        other._parts = self._parts
        return other

    @property
    def domain(self) -> bytes:
        return self._domain


def _frame(label: bytes, payload: bytes) -> bytes:
    if len(label) > 255:
        raise TranscriptError("labels are limited to 255 bytes")
    return bytes([len(label)]) + label + len(payload).to_bytes(4, "little") + payload


def _squeeze(label: bytes, length: int) -> bytes:
    return _frame(b"squeeze-request", label + length.to_bytes(4, "little"))
