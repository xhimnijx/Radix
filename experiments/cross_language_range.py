"""Cross-language check: a Python range proof verified by the Rust verifier.

The project's whole method is that two independent implementations must agree. The range
constraint added two beta challenges, a shifted commitment layout and a new term in the
verifier's equation -- exactly the kind of change where one side can be subtly wrong and
still pass its own tests.

This script produces a proof in Python that carries range messages and asks the Rust
verifier to accept it. If the two disagree, the disagreement is the bug report.

    python experiments/cross_language_range.py
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from radix_core.candidate_b.lattice import digits, ring, setmembership as S  # noqa: E402
from radix_core.candidate_b.lattice.params import SMILE  # noqa: E402
from radix_testnet import rust_backend  # noqa: E402


def build(range_count: int, seed: int = 11):
    rng = random.Random(seed)
    depth, rows = 2, 4
    keys = S.setup(rng, depth, None, rows, range_count=range_count)
    matrix = tuple(
        tuple(ring.sample_uniform(rng) for _ in range(SMILE.matrix_cols)) for _ in range(rows)
    )
    secret = ring.sample_vector(rng, SMILE.matrix_cols, small=True, parameters=SMILE)
    public = tuple(ring.dot(row, secret, SMILE) for row in matrix)
    ring_keys = [
        tuple(ring.sample_uniform(rng) for _ in range(rows)) for _ in range(1024)
    ]
    ring_keys[7] = public
    statement = S.Statement(matrix=matrix, keys=tuple(ring_keys), depth=depth)
    return keys, statement, secret


def main() -> int:
    if not rust_backend.available():
        print("the Rust verifier is not built; run cargo build --release --bin verify_request")
        return 2

    keys, statement, secret = build(2)
    packed = digits.pack_bits(digits.bits_of(12345, 32), SMILE)
    message = b"cross-language range"
    proof = S.prove(keys, statement, secret, 7, message, random.Random(5), None, None, packed)

    python_ok = S.verify(keys, statement, proof, message)
    rust_ok = rust_backend.verify(keys, statement, proof, message)
    rust_on_other = rust_backend.verify(keys, statement, proof, b"a different message")

    print(f"proof bytes        : {proof.size_bytes}")
    print(f"commitment entries : {len(proof.commitment)}")
    print(f"python accepts     : {python_ok}")
    print(f"rust accepts       : {rust_ok}")
    print(f"rust accepts other : {rust_on_other}  (must be False)")

    agree = python_ok and rust_ok and not rust_on_other
    print("verdict            :", "AGREE" if agree else "DISAGREE")
    return 0 if agree else 1


if __name__ == "__main__":
    raise SystemExit(main())
