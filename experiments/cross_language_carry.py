"""Cross-language check: a carry-and-relation proof made in Python, verified by Rust.

The carry work added two things that can silently disagree between implementations: a new
kind of committed row with no binaryness term, and a linear relation whose algebra depends on
the exact placement of `c` and the constant. A sign error or an off-by-one in the relation's
position space would pass one side's tests and fail the other's, which is precisely what the
two-implementation discipline exists to catch.

    python experiments/cross_language_carry.py
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from radix_core.candidate_b.lattice import ring, setmembership as S, subring  # noqa: E402
from radix_core.candidate_b.lattice.params import SMILE  # noqa: E402
from radix_testnet import rust_backend  # noqa: E402

POSITIONS = 32
BIT_COUNT = 3          # a carry for four inputs


def build(range_count: int, carry_count: int, seed: int = 77):
    rng = random.Random(seed)
    keys = S.setup(rng, 2, None, 4, range_count=range_count, carry_count=carry_count)
    matrix = tuple(
        tuple(ring.sample_uniform(rng) for _ in range(SMILE.matrix_cols)) for _ in range(4)
    )
    secret = ring.sample_vector(rng, SMILE.matrix_cols, small=True, parameters=SMILE)
    public = tuple(ring.dot(row, secret, SMILE) for row in matrix)
    ring_keys = [tuple(ring.sample_uniform(rng) for _ in range(4)) for _ in range(1024)]
    ring_keys[6] = public
    return keys, S.Statement(matrix=matrix, keys=tuple(ring_keys), depth=2), secret


def planes(values: list[int], bit_count: int) -> list[int]:
    return [(value >> bit) & 1 for bit in range(bit_count) for value in values]


def pack(flat: list[int]) -> tuple:
    padded = flat + [0] * (-len(flat) % POSITIONS)
    return tuple(
        subring.from_constants(tuple(padded[start : start + POSITIONS]), SMILE)
        for start in range(0, len(padded), POSITIONS)
    )


def main() -> int:
    if not rust_backend.available():
        print("the Rust verifier is not built; run cargo build --release --bin verify_request")
        return 2

    values = [index % 5 for index in range(POSITIONS)]
    bit_polys = pack(planes(values, BIT_COUNT))
    carry_poly = subring.from_constants(tuple(values), SMILE)
    relation = S.LinearRelation(
        weights=(ring.constant(1, SMILE),)
        + tuple(ring.constant(-(1 << bit), SMILE) for bit in range(BIT_COUNT)),
        positions=(-(len(bit_polys) + 1),)
        + tuple(-(index + 1) for index in range(len(bit_polys))),
        constant=ring.zero(SMILE),
    )

    keys, statement, secret = build(len(bit_polys), 1)
    message = b"cross-language carry"
    proof = S.prove(
        keys, statement, secret, 6, message, random.Random(11), None, None,
        bit_polys, (relation,), (carry_poly,),
    )

    python_ok = S.verify(keys, statement, proof, message, relations=(relation,))
    rust_ok = rust_backend.verify(keys, statement, proof, message, (relation,))
    rust_on_other = rust_backend.verify(keys, statement, proof, b"different", (relation,))
    # And without the relation, a proof whose carry is wrong must be refused by Rust too.
    wrong_carry = subring.from_constants(tuple(2 for _ in range(POSITIONS)), SMILE)
    bad = S.prove(
        keys, statement, secret, 6, message, random.Random(11), None, None,
        bit_polys, (relation,), (wrong_carry,),
    )
    rust_refuses_bad = rust_backend.verify(keys, statement, bad, message, (relation,))

    print(f"proof bytes        : {proof.size_bytes}")
    print(f"commitment entries : {len(proof.commitment)}")
    print(f"python accepts     : {python_ok}")
    print(f"rust accepts       : {rust_ok}")
    print(f"rust accepts other : {rust_on_other}   (must be False)")
    print(f"rust refuses a bad carry: {rust_refuses_bad}   (must be False)")

    agree = python_ok and rust_ok and not rust_on_other and not rust_refuses_bad
    print("verdict            :", "AGREE" if agree else "DISAGREE")
    return 0 if agree else 1


if __name__ == "__main__":
    raise SystemExit(main())
