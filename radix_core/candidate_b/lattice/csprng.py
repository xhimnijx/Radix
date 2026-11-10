"""A cryptographically secure drop-in for `random.Random`.

Why this exists: the wallet derived its keys and its proof masks from Python's `random.Random`,
which is Mersenne Twister. MT19937 is a fine generator for simulations and the wrong primitive for
anything secret -- 624 consecutive outputs recover its entire state, and it makes no claim to be
unpredictable. The independent review flagged it, correctly.

The lattice code only needs four methods, so this provides exactly those and nothing else:

    randrange(stop) / randrange(start, stop)
    randint(a, b)
    getrandbits(k)
    random()            a float in [0, 1)

The construction is SHAKE256 in counter mode: a keyed stream, rekeyed per block, which is a
standard expand-from-seed construction. It is deliberately not a class with `Random`'s whole
surface, so a caller cannot accidentally depend on behaviour this does not promise.

Argument convention matches `random.Random` where the lattice samplers rely on it: `randrange` is
half-open, `randint` is inclusive, and `getrandbits` returns a non-negative integer with exactly
`k` bits.
"""

from __future__ import annotations

import hashlib
import os


class CipherRng:
    """SHAKE256 in counter mode, with the four methods the samplers use."""

    __slots__ = ("_seed", "_counter", "_buffer", "_offset")

    def __init__(self, seed: bytes | None = None):
        if seed is None:
            seed = os.urandom(32)
        if not isinstance(seed, (bytes, bytearray)):
            raise TypeError("a CSPRNG seed must be bytes")
        self._seed = hashlib.sha3_256(b"radix/csprng/v1" + bytes(seed)).digest()
        self._counter = 0
        self._buffer = b""
        self._offset = 0

    def _refill(self) -> None:
        block = hashlib.shake_256(
            self._seed + self._counter.to_bytes(8, "little")
        ).digest(64)
        # Rekey, so recovering one block does not determine the next.
        self._seed = hashlib.sha3_256(b"radix/csprng/rekey" + self._seed + block).digest()
        self._counter += 1
        self._buffer = block
        self._offset = 0

    def _bytes(self, count: int) -> bytes:
        out = bytearray()
        while len(out) < count:
            if self._offset >= len(self._buffer):
                self._refill()
            take = min(count - len(out), len(self._buffer) - self._offset)
            out += self._buffer[self._offset : self._offset + take]
            self._offset += take
        return bytes(out)

    def getrandbits(self, k: int) -> int:
        if k < 0:
            raise ValueError("number of bits must be non-negative")
        if k == 0:
            return 0
        count = (k + 7) // 8
        return int.from_bytes(self._bytes(count), "big") >> (count * 8 - k)

    def randrange(self, start: int, stop: int | None = None) -> int:
        if stop is None:
            start, stop = 0, start
        span = stop - start
        if span <= 0:
            raise ValueError("empty range for randrange()")
        # Rejection sampling, so the distribution is exact rather than modulo-biased.
        bits = span.bit_length()
        while True:
            value = self.getrandbits(bits)
            if value < span:
                return start + value

    def randint(self, a: int, b: int) -> int:
        return self.randrange(a, b + 1)

    def random(self) -> float:
        """A float in [0, 1), with 53 bits of precision as `random.Random.random` has."""
        return self.getrandbits(53) / float(1 << 53)

    def sample_bytes(self, count: int) -> bytes:
        return self._bytes(count)


def from_seed(seed: bytes) -> CipherRng:
    return CipherRng(seed)


def fresh() -> CipherRng:
    return CipherRng()
