"""Negacyclic ring arithmetic for the SMILE parameter manifest.

R_q = Z_q[X]/(X^d + 1). Polynomials are tuples of `d` integer coefficients,
always reduced into [0, q). Multiplication is exact integer arithmetic; the
public `mul` uses the negacyclic NTT when (q, d) admits one and falls back to the
O(d^2) convolution otherwise. `mul_naive` is kept as the auditable reference,
and the test suite asserts the two agree coefficient for coefficient.
""" 

from __future__ import annotations

import random
from typing import Iterable, Sequence

from . import ntt, subring
from .params import SMILE, SmileParameters

Poly = tuple[int, ...]


def _params(parameters: SmileParameters | None) -> SmileParameters:
    return SMILE if parameters is None else parameters


def zero(parameters: SmileParameters | None = None) -> Poly:
    return (0,) * _params(parameters).ring_degree


def constant(value: int, parameters: SmileParameters | None = None) -> Poly:
    p = _params(parameters)
    return (value % p.modulus,) + (0,) * (p.ring_degree - 1)


def normalize(values: Iterable[int], parameters: SmileParameters | None = None) -> Poly:
    p = _params(parameters)
    coefficients = tuple(int(value) % p.modulus for value in values)
    if len(coefficients) != p.ring_degree:
        raise ValueError(f"polynomial must have exactly {p.ring_degree} coefficients")
    return coefficients


def add(left: Poly, right: Poly, parameters: SmileParameters | None = None) -> Poly:
    p = _params(parameters)
    return tuple((a + b) % p.modulus for a, b in zip(left, right))


def sub(left: Poly, right: Poly, parameters: SmileParameters | None = None) -> Poly:
    p = _params(parameters)
    return tuple((a - b) % p.modulus for a, b in zip(left, right))


def neg(value: Poly, parameters: SmileParameters | None = None) -> Poly:
    p = _params(parameters)
    return tuple((-a) % p.modulus for a in value)


def scalar(value: int, poly: Poly, parameters: SmileParameters | None = None) -> Poly:
    p = _params(parameters)
    return tuple((value * a) % p.modulus for a in poly)


def mul_naive(left: Poly, right: Poly, parameters: SmileParameters | None = None) -> Poly:
    """O(d^2) negacyclic product: X^d == -1. Kept as the reference implementation."""
    p = _params(parameters)
    degree = p.ring_degree
    q = p.modulus
    out = [0] * degree
    for i, a in enumerate(left):
        if not a:
            continue
        for j, b in enumerate(right):
            if not b:
                continue
            index = i + j
            if index < degree:
                out[index] += a * b
            else:
                out[index - degree] -= a * b
    return tuple(value % q for value in out)


def mul(left: Poly, right: Poly, parameters: SmileParameters | None = None) -> Poly:
    """Negacyclic product: X^d == -1.

    Three paths, all equality-tested against each other: the NTT when a 256th root
    of unity exists, the quartic CRT when it does not, and the naive convolution as
    the reference both must match.
    """
    p = _params(parameters)
    if ntt.try_transform(p.modulus, p.ring_degree) is not None:
        return ntt.multiply(left, right, p)
    if (p.modulus - 1) % 64 == 0:
        return subring.multiply(left, right, p)
    return mul_naive(left, right, p)


def dot(left: Sequence[Poly], right: Sequence[Poly], parameters: SmileParameters | None = None) -> Poly:
    if len(left) != len(right):
        raise ValueError("dot product needs equally sized vectors")
    p = _params(parameters)
    out = zero(p)
    for a, b in zip(left, right):
        out = add(out, mul(a, b, p), p)
    return out


def mat_vec(
    matrix: Sequence[Sequence[Poly]], vector: Sequence[Poly], parameters: SmileParameters | None = None
) -> tuple[Poly, ...]:
    if any(len(row) != len(vector) for row in matrix):
        raise ValueError("matrix row length does not match the vector")
    p = _params(parameters)
    return tuple(dot(row, vector, p) for row in matrix)


def norm_inf(value: Poly) -> int:
    """Centered infinity norm: the honest measure for rejection sampling."""
    return max(centered(a) for a in value)


def l2_squared(value: Poly, parameters: SmileParameters | None = None) -> int:
    """Exact squared Euclidean norm over the signed representatives.

    Deliberately *not* reduced modulo q: the reviewers' beta and beta' are l2
    bounds, and a residue is meaningless for comparing against one.
    """
    p = _params(parameters)
    return sum(centered(a, p) ** 2 for a in value)


def centered(coefficient: int, parameters: SmileParameters | None = None) -> int:
    """Map a residue in [0, q) to the signed representative in (-q/2, q/2]."""
    if not isinstance(coefficient, int):
        raise TypeError("coefficient must be an integer")
    p = _params(parameters)
    residue = coefficient % p.modulus
    return residue if residue <= p.modulus // 2 else residue - p.modulus


def sample_uniform(rng: random.Random, parameters: SmileParameters | None = None) -> Poly:
    p = _params(parameters)
    return tuple(rng.randrange(p.modulus) for _ in range(p.ring_degree))


def sample_small(rng: random.Random, parameters: SmileParameters | None = None) -> Poly:
    """Uniform in [-mu, mu]; matches SMILE's secret distribution shape, not its analysis."""
    p = _params(parameters)
    bound = p.secret_bound
    return tuple((rng.randint(-bound, bound)) % p.modulus for _ in range(p.ring_degree))


def sample_vector(
    rng: random.Random, length: int, *, small: bool = False, parameters: SmileParameters | None = None
) -> tuple[Poly, ...]:
    sampler = sample_small if small else sample_uniform
    return tuple(sampler(rng, parameters) for _ in range(length))


def encode(poly: Poly, parameters: SmileParameters | None = None) -> bytes:
    """4-byte little-endian coefficients; canonical for q < 2^32."""
    p = _params(parameters)
    if len(poly) != p.ring_degree:
        raise ValueError("polynomial has the wrong degree")
    return b"".join(int(a).to_bytes(4, "little") for a in poly)


def decode(data: bytes, parameters: SmileParameters | None = None) -> Poly:
    p = _params(parameters)
    if type(data) is not bytes or len(data) != p.ring_degree * 4:
        raise ValueError("encoded polynomial has the wrong length")
    values = tuple(
        int.from_bytes(data[4 * index : 4 * index + 4], "little")
        for index in range(p.ring_degree)
    )
    if any(value >= p.modulus for value in values):
        raise ValueError("non-canonical coefficient encoding")
    return values
