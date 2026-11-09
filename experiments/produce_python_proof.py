"""Produce a real Python proof and the material the Rust verifier needs.

The keys and the ring are built with the shared `uniform_from` generator rather than
with `setup(rng)`, so the Rust side can rebuild them identically without transferring
anything. Only two things cannot be regenerated: the proof (its masks come from
Mersenne Twister) and the honest public key (its secret is not shared). Both go in
the fixture.

Layout: proof bytes, then `k` public-key polynomials.
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from port_vectors import uniform_from

from radix_core.candidate_b.lattice import ring, setmembership as S

DEPTH = 2
ROWS = 4
COLS = 13
WIDTH = S.masking_width(DEPTH, S.SMILE, ROWS)
HONEST = 7
MESSAGE = b"hello from python"

OUT = Path(__file__).resolve().parent.parent / "proof_rust" / "tests" / "fixtures"


def poly_stream(label: bytes, count: int) -> tuple[tuple[int, ...], ...]:
    return tuple(uniform_from(label, index) for index in range(count))


def main() -> int:
    rows0 = tuple(
        poly_stream(b"K0", S.SMILE.challenge_dim * WIDTH)[row * WIDTH : (row + 1) * WIDTH]
        for row in range(S.SMILE.challenge_dim)
    )
    b_rows = tuple(
        poly_stream(b"K1", (ROWS + 2 * DEPTH + 1) * WIDTH)[row * WIDTH : (row + 1) * WIDTH]
        for row in range(ROWS + 2 * DEPTH + 1)
    )
    keys = S.Keys(rows0=rows0, rows=b_rows, depth=DEPTH, row_count=ROWS)

    matrix = tuple(
        tuple(poly_stream(b"A", ROWS * COLS)[row * COLS : (row + 1) * COLS])
        for row in range(ROWS)
    )

    # A small secret of our own choosing, so the public key is reproducible.
    secret = tuple(ring.constant((index % 7) - 3, S.SMILE) for index in range(COLS))
    public = tuple(ring.dot(row, secret, S.SMILE) for row in matrix)

    pool = poly_stream(b"pk", (32**DEPTH) * ROWS)
    ring_keys = [
        tuple(pool[key * ROWS : (key + 1) * ROWS]) for key in range(32**DEPTH)
    ]
    ring_keys[HONEST] = public
    statement = S.Statement(matrix=matrix, keys=tuple(ring_keys), depth=DEPTH)

    print(f"W = {WIDTH}, depth = {DEPTH}, ring = {32 ** DEPTH}")
    print("proving (this takes a minute or two)...")
    proof = S.prove(keys, statement, secret, HONEST, MESSAGE, random.Random(99))
    print("verified in python:", S.verify(keys, statement, proof, MESSAGE))
    assert S.verify(keys, statement, proof, MESSAGE)

    OUT.mkdir(parents=True, exist_ok=True)
    blob = proof.encode() + b"".join(ring.encode(poly, S.SMILE) for poly in public)
    path = OUT / "python_proof.bin"
    path.write_bytes(blob)
    print(f"wrote {path} ({len(blob)} bytes)")
    print(f"proof bytes = {len(blob) - ROWS * S.SMILE.ring_degree * 4}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
