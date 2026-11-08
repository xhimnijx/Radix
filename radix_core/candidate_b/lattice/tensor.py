"""Tensor / one-hot indexing for SMILE set membership (Fig. 6, p. 15).

SMILE hides *which* ring member is being shown by proving that a tensor product of
binary vectors is one-hot, without revealing the position. The set has
``n = l^m`` elements, indexed by ``m`` one-hot vectors of length ``l`` (the paper
uses ``l = 32``, ``m = 1..5``).

This module implements only the indexing arithmetic: one-hot construction, the
Kronecker product, and column selection from the public structured key. It does
not implement the commitment schedule or the proof. It exists so the layer above
can be written against tested index semantics rather than paper notation.
"""

from __future__ import annotations

from . import ring
from .params import SMILE, SmileParameters
from .ring import Poly


class TensorError(ValueError):
    """An index vector or tensor is malformed."""


def one_hot(dimension: int, index: int) -> tuple[int, ...]:
    """The length-`dimension` unit vector with a single 1 at `index`."""
    if type(dimension) is not int or dimension < 1:
        raise TensorError("dimension must be a positive integer")
    if type(index) is not int or not 0 <= index < dimension:
        raise TensorError("index is outside the vector")
    return tuple(1 if position == index else 0 for position in range(dimension))


def kron(left: tuple[int, ...], right: tuple[int, ...]) -> tuple[int, ...]:
    """Integer Kronecker product, right index varying fastest."""
    if not left or not right:
        raise TensorError("cannot take a tensor product with an empty vector")
    return tuple(a * b for a in left for b in right)


def tensor(vectors: tuple[tuple[int, ...], ...]) -> tuple[int, ...]:
    """Kronecker product of a non-empty list of vectors."""
    if not vectors:
        raise TensorError("tensor product needs at least one vector")
    result = vectors[0]
    for vector in vectors[1:]:
        result = kron(result, vector)
    return result


def set_size(m: int, l: int = SMILE.subring_dimension) -> int:
    """n = l^m: the number of set elements the shape can address."""
    if type(m) is not int or not 1 <= m <= 8:
        raise TensorError("tensor factor count must be in 1..8")
    if type(l) is not int or l < 2:
        raise TensorError("subring dimension must be at least 2")
    return l**m


def flat_index(indices: tuple[int, ...], l: int = SMILE.subring_dimension) -> int:
    """Position selected by a tuple of one-hot indices (base l, first fastest)."""
    if not indices:
        raise TensorError("at least one index is required")
    value = 0
    for index in indices:
        if type(index) is not int or not 0 <= index < l:
            raise TensorError("index is outside the subring dimension")
        value = value * l + index
    return value


def assert_one_hot(vector: tuple[int, ...]) -> int:
    """Return the 1-position, rejecting anything that is not a unit vector."""
    if type(vector) is not tuple or not vector:
        raise TensorError("vector must be a non-empty tuple")
    if any(type(value) is not int or value not in (0, 1) for value in vector):
        raise TensorError("vector entries must be 0 or 1")
    positions = [index for index, value in enumerate(vector) if value == 1]
    if len(positions) != 1:
        raise TensorError("vector must have exactly one 1")
    return positions[0]


def select_columns(
    columns: tuple[Poly, ...],
    weights: tuple[int, ...],
    parameters: SmileParameters | None = None,
) -> Poly:
    """sum_i weights[i] * columns[i], the T·(v1 (x) ... (x) vm) product.

    ``weights`` must be a one-hot vector, i.e. exactly one column is selected.
    That is what makes the position secret: the verifier only sees the result.
    """
    p = SMILE if parameters is None else parameters
    if len(columns) != len(weights):
        raise TensorError("column count does not match the weight vector")
    position = assert_one_hot(weights)
    return columns[position]
