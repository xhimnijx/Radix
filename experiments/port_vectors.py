"""Reference vectors for the Rust port.

Mirrors `proof_rust/src/sample.rs` exactly: same domain, same length-prefixed label,
same little-endian bytes. If these two ever disagree, every cross-language vector
fails at once.
"""

from hashlib import shake_256

from radix_core.candidate_b.lattice import bdlop

Q = 4_294_966_337
DOMAIN = b"radix/port/v1"
D = 128


def uniform_from(label: bytes, counter: int) -> tuple[int, ...]:
    material = DOMAIN + len(label).to_bytes(4, "little") + label + counter.to_bytes(4, "little")
    stream = shake_256(material).digest(D * 4)
    return tuple(
        int.from_bytes(stream[4 * index : 4 * index + 4], "little") % Q for index in range(D)
    )


def vector_from(label: bytes, count: int, first: int) -> tuple[tuple[int, ...], ...]:
    return tuple(uniform_from(label, first + index) for index in range(count))


def digest(data: bytes, length: int = 16) -> str:
    return shake_256(data).hexdigest(length)


print("uniform('a',0)[:4] =", uniform_from(b"a", 0)[:4])

matrix = (vector_from(b"B-row", 3, 0), vector_from(b"B-row", 3, 8))
vector = vector_from(b"b-row", 3, 16)
key = bdlop.CommitmentKey(matrix=matrix, vector=vector, rows=2, cols=3)
randomness = vector_from(b"r", 3, 32)
message = vector_from(b"m", 1, 40)[0]

commitment = bdlop.commit(key, message, randomness)
print("commitment digest =", digest(commitment.encode()))
print("commitment u[:4]  =", commitment.u[:4])

