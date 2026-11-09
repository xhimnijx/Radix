"""Verify a Rust proof with the Python reference.

The strongest check available: the Rust prover's output, checked by the code the
whole project is modelled on. A Rust prover and Rust verifier can be wrong together;
this cannot.

The keys, the ring and the matrix are rebuilt from the same `uniform_from` generator
the Rust side uses, so only the proof and the honest public key need to be read.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from port_vectors import uniform_from

from radix_core.candidate_b.lattice import ring, setmembership as S
from radix_testnet.codec import decode_proof

FIXTURES = Path(__file__).resolve().parent.parent / "proof_rust" / "tests" / "fixtures"

DEPTH = 2
ROWS = 4
COLS = 13
HONEST = 7
MESSAGE = b"hello from rust"
WIDTH = S.masking_width(DEPTH, S.SMILE, ROWS)
PUBLIC_BYTES = ROWS * S.SMILE.ring_degree * 4


def stream(label: bytes, count: int) -> tuple[tuple[int, ...], ...]:
    return tuple(uniform_from(label, index) for index in range(count))


def rig(public: tuple[tuple[int, ...], ...]):
    rows0 = tuple(
        stream(b"K0", S.SMILE.challenge_dim * WIDTH)[row * WIDTH : (row + 1) * WIDTH]
        for row in range(S.SMILE.challenge_dim)
    )
    b_rows = tuple(
        stream(b"K1", (ROWS + 2 * DEPTH + 1) * WIDTH)[row * WIDTH : (row + 1) * WIDTH]
        for row in range(ROWS + 2 * DEPTH + 1)
    )
    keys = S.Keys(rows0=rows0, rows=b_rows, depth=DEPTH, row_count=ROWS)

    matrix = tuple(
        stream(b"A", ROWS * COLS)[row * COLS : (row + 1) * COLS] for row in range(ROWS)
    )
    pool = stream(b"pk", (32**DEPTH) * ROWS)
    ring_keys = [tuple(pool[key * ROWS : (key + 1) * ROWS]) for key in range(32**DEPTH)]
    ring_keys[HONEST] = public
    statement = S.Statement(matrix=matrix, keys=tuple(ring_keys), depth=DEPTH)
    return keys, statement


def main(name: str = "rust_proof.bin", message: bytes = MESSAGE) -> int:
    blob = (FIXTURES / name).read_bytes()
    proof_bytes = blob[: len(blob) - PUBLIC_BYTES]
    public_blob = blob[len(blob) - PUBLIC_BYTES :]
    size = S.SMILE.ring_degree * 4
    public = tuple(
        ring.decode(public_blob[i * size : (i + 1) * size], S.SMILE) for i in range(ROWS)
    )

    keys, statement = rig(public)
    proof = decode_proof(proof_bytes, depth=DEPTH, rows=ROWS)
    ok = S.verify(keys, statement, proof, message)
    print(f"{name}: {len(proof_bytes)} proof bytes, python verifier says {ok}")

    # A proof must also fail when the message changes.
    if ok:
        other = S.verify(keys, statement, proof, message + b"!")
        print(f"  with a different message: {other}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
