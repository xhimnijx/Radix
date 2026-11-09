"""Negacyclic number-theoretic transform for R_q = Z_q[X]/(X^d + 1).

Why this exists: SMILE's set-membership recursion (Section 3.1, pp. 20-24) is
stated in the NTT domain - Lemmas 2.1 and 2.2 characterise a zero inner product
by the *NTT coefficients* of a committed polynomial being zero in the first
``d/l`` positions - and every honest value in that protocol is committed as
``NTT^-1(v)`` for a short vector ``v``. Building Fig. 6 without this transform
would mean building it twice.

It is also the performance fix the device budget needs: ``ring.mul`` was O(d^2)
(16,384 coefficient products per multiplication, and the BDLOP matrix product
does 52 of them), whereas this is O(d log d).

Math. ``X^d + 1`` has roots ``zeta^(2k+1)`` for ``k = 0..d-1``, where ``zeta``
is a primitive ``2d``-th root of unity. Evaluation at those roots is the map

    forward(a)_k = sum_j a_j * zeta^(j(2k+1)) = sum_j (a_j zeta^j) * omega^(jk)

with ``omega = zeta^2`` a primitive ``d``-th root, i.e. a twist by ``zeta^j``
followed by an ordinary radix-2 NTT. Products in the transform domain are
pointwise, because each coordinate is an evaluation at a fixed root.

Pure integer arithmetic: no floating point, no rounding, exact results.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from .params import SMILE, SmileParameters

MAX_ROOT_SEARCH = 64


class TransformError(ValueError):
    """A polynomial, vector, or parameter set cannot be transformed."""


@dataclass(frozen=True)
class Transform:
    """Twiddle tables for one (q, d) pair."""

    modulus: int
    degree: int
    root: int                      # zeta, primitive 2d-th root, zeta^d = -1
    twist: tuple[int, ...]         # zeta^j
    inverse_twist: tuple[int, ...] # zeta^-j
    bit_reversal: tuple[int, ...]
    forward_steps: tuple[int, ...]
    inverse_steps: tuple[int, ...]
    inverse_degree: int

    def __post_init__(self) -> None:
        if pow(self.root, 2 * self.degree, self.modulus) != 1:
            raise TransformError("root is not a 2d-th root of unity")
        if pow(self.root, self.degree, self.modulus) != self.modulus - 1:
            raise TransformError("root is not primitive: zeta^d must be -1")
        if len(self.twist) != self.degree or len(self.bit_reversal) != self.degree:
            raise TransformError("twiddle table has the wrong length")


def try_transform(modulus: int, degree: int) -> "Transform | None":
    """The transform for (modulus, degree), or None when no 2d-th root exists."""
    try:
        return _build(modulus, degree)
    except TransformError:
        return None


def transform(parameters: SmileParameters | None = None) -> Transform:
    """Build (and cache) the twiddle tables for a parameter set."""
    p = SMILE if parameters is None else parameters
    return _build(p.modulus, p.ring_degree)


@lru_cache(maxsize=8)
def _build(modulus: int, degree: int) -> Transform:
    root = _find_root(modulus, degree)
    omega = pow(root, 2, modulus)
    omega_inverse = pow(omega, -1, modulus)

    stages = degree.bit_length() - 1
    forward_steps = tuple(
        pow(omega, degree >> (stage + 1), modulus) for stage in range(stages)
    )
    inverse_steps = tuple(
        pow(omega_inverse, degree >> (stage + 1), modulus) for stage in range(stages)
    )
    return Transform(
        modulus=modulus,
        degree=degree,
        root=root,
        twist=tuple(pow(root, index, modulus) for index in range(degree)),
        inverse_twist=tuple(
            pow(pow(root, -1, modulus), index, modulus) for index in range(degree)
        ),
        bit_reversal=tuple(_reverse_bits(index, stages) for index in range(degree)),
        forward_steps=forward_steps,
        inverse_steps=inverse_steps,
        inverse_degree=pow(degree, -1, modulus),
    )


def _find_root(modulus: int, degree: int) -> int:
    """Smallest base whose (q-1)/(2d)-th power is a primitive 2d-th root."""
    order = 2 * degree
    if modulus < 3 or (modulus - 1) % order:
        raise TransformError("q-1 is not divisible by 2d: no transform exists")
    exponent = (modulus - 1) // order
    for base in range(2, 2 + MAX_ROOT_SEARCH):
        candidate = pow(base, exponent, modulus)
        if pow(candidate, degree, modulus) == modulus - 1:
            return candidate
    raise TransformError("no primitive 2d-th root of unity found")


def _reverse_bits(index: int, width: int) -> int:
    out = 0
    for _ in range(width):
        out = (out << 1) | (index & 1)
        index >>= 1
    return out


def _check(values: tuple[int, ...], table: Transform) -> None:
    if len(values) != table.degree:
        raise TransformError("polynomial has the wrong length")
    if any(type(value) is not int for value in values):
        raise TransformError("coefficients must be integers")


def _butterfly(
    values: list[int], table: Transform, steps: tuple[int, ...], order: tuple[int, ...]
) -> list[int]:
    modulus = table.modulus
    degree = table.degree
    out = [values[index] % modulus for index in order]
    length = 1
    for step in steps:
        jump = length << 1
        for start in range(0, degree, jump):
            factor = 1
            for offset in range(length):
                left = out[start + offset]
                right = out[start + offset + length] * factor % modulus
                out[start + offset] = (left + right) % modulus
                out[start + offset + length] = (left - right) % modulus
                factor = factor * step % modulus
        length = jump
    return out


def forward(poly: tuple[int, ...], parameters: SmileParameters | None = None) -> tuple[int, ...]:
    """Evaluations of `poly` at the d roots of X^d + 1."""
    table = transform(parameters)
    _check(poly, table)
    twisted = [value * table.twist[index] % table.modulus for index, value in enumerate(poly)]
    return tuple(_butterfly(twisted, table, table.forward_steps, table.bit_reversal))


def inverse(values: tuple[int, ...], parameters: SmileParameters | None = None) -> tuple[int, ...]:
    """The unique polynomial whose evaluations are `values`."""
    table = transform(parameters)
    _check(values, table)
    untwisted = _butterfly(list(values), table, table.inverse_steps, table.bit_reversal)
    return tuple(
        value * table.inverse_degree % table.modulus * table.inverse_twist[index] % table.modulus
        for index, value in enumerate(untwisted)
    )


def multiply(
    left: tuple[int, ...], right: tuple[int, ...], parameters: SmileParameters | None = None
) -> tuple[int, ...]:
    """Product in R_q: pointwise in the transform domain, then transform back."""
    table = transform(parameters)
    _check(left, table)
    _check(right, table)
    modulus = table.modulus
    product = [
        a * b % modulus
        for a, b in zip(forward(left, parameters), forward(right, parameters))
    ]
    return inverse(tuple(product), parameters)


def supports(parameters: SmileParameters | None = None) -> bool:
    """Whether a transform exists for this parameter set."""
    try:
        transform(parameters)
    except TransformError:
        return False
    return True
