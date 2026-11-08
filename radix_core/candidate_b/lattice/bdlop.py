"""BDLOP-style commitment, the base layer of SMILE.

SMILE (Fig. 5, p. 14 of the full version) commits with

    (t ; u) = (B ; b) . s + (0 ; m),      t in R_q^k, u in R_q,

where ``B`` is a public k x ell matrix over R_q, ``b`` is a public length-k
vector, ``s`` is a short secret vector and ``m`` is the committed message.
Opening reveals ``(s, m)``; binding rests on Module-SIS and hiding on
Module-LWE with a Gaussian/small ``s``. This module implements the commitment
and its additive homomorphism only. It does not implement the zero-knowledge
proof of knowledge, which is what SMILE adds on top and what B2 still owes.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .params import SMILE, SmileParameters
from . import ring
from .ring import Poly

COMMITMENT_TAG = b"radix/b/lattice/bdlop/v1"


@dataclass(frozen=True)
class CommitmentKey:
    matrix: tuple[tuple[Poly, ...], ...]
    vector: tuple[Poly, ...]

    def __post_init__(self) -> None:
        if len(self.matrix) != SMILE.matrix_rows:
            raise ValueError("commitment matrix must have k rows")
        if any(len(row) != SMILE.matrix_cols for row in self.matrix):
            raise ValueError("commitment matrix must have ell columns")
        # (B ; b) is (k+1) x ell: the b row is a single row of ell polynomials.
        if len(self.vector) != SMILE.matrix_cols:
            raise ValueError("commitment vector must have ell entries")


@dataclass(frozen=True)
class Commitment:
    t: tuple[Poly, ...]
    u: Poly

    def __post_init__(self) -> None:
        if len(self.t) != SMILE.matrix_rows:
            raise ValueError("commitment t must have k polynomials")

    def encode(self) -> bytes:
        return b"".join(ring.encode(poly) for poly in self.t) + ring.encode(self.u)


def setup(rng: random.Random, parameters: SmileParameters | None = None) -> CommitmentKey:
    p = SMILE if parameters is None else parameters
    matrix = tuple(
        tuple(ring.sample_uniform(rng, p) for _ in range(p.matrix_cols))
        for _ in range(p.matrix_rows)
    )
    vector = tuple(ring.sample_uniform(rng, p) for _ in range(p.matrix_cols))
    return CommitmentKey(matrix=matrix, vector=vector)


def opening(
    rng: random.Random, parameters: SmileParameters | None = None
) -> tuple[Poly, ...]:
    p = SMILE if parameters is None else parameters
    return ring.sample_vector(rng, p.matrix_cols, small=True, parameters=p)


def commit(
    key: CommitmentKey,
    message: Poly,
    randomness: tuple[Poly, ...],
    parameters: SmileParameters | None = None,
) -> Commitment:
    p = SMILE if parameters is None else parameters
    if len(randomness) != p.matrix_cols:
        raise ValueError("randomness must have ell polynomials")
    t = ring.mat_vec(key.matrix, randomness, p)
    u = ring.add(ring.dot(key.vector, randomness, p), message, p)
    return Commitment(t=t, u=u)


def verify(
    key: CommitmentKey,
    commitment: Commitment,
    message: Poly,
    randomness: tuple[Poly, ...],
    parameters: SmileParameters | None = None,
) -> bool:
    expected = commit(key, message, randomness, parameters)
    return expected == commitment


def add_commitments(
    left: Commitment, right: Commitment, parameters: SmileParameters | None = None
) -> Commitment:
    p = SMILE if parameters is None else parameters
    return Commitment(
        t=tuple(
            ring.add(a, b, p) for a, b in zip(left.t, right.t)
        ),
        u=ring.add(left.u, right.u, p),
    )


def add_openings(
    left: tuple[Poly, ...], right: tuple[Poly, ...], parameters: SmileParameters | None = None
) -> tuple[Poly, ...]:
    p = SMILE if parameters is None else parameters
    if len(left) != len(right):
        raise ValueError("openings must have the same length")
    return tuple(ring.add(a, b, p) for a, b in zip(left, right))
