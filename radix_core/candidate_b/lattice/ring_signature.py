"""Candidate B's post-quantum ring signature: SMILE set membership behind a 4-call API.

``RS.Setup`` / ``RS.KeyGen`` / ``RS.Sign`` / ``RS.Ver`` from Appendix C, with the
set-membership proof of Figs. 7-9 as the signing core. This is the "ring
transform" in the sense the objective uses it: the proof already hides *which*
public key is being opened (that is what the set matrix and the Fig. 8 recursion
do), so the transform is the API, the ring lookup, and the message binding --
not another layer of algebra.

What is and is not here:

* the signature is non-interactive Fiat-Shamir over the whole transcript, with
  the message absorbed into ``c'`` (p. 43);
* the ring is a tuple of public keys of size ``l^m``; a keygen output that is not
  in the ring is refused rather than silently signing;
* no rejection sampling and no bimodal Gaussian (see ``setmembership``), so the
  signatures are roughly twice the paper's 18.7 KB;
* research component: no security claim without independent review.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from . import ring, setmembership as S
from .params import SMILE, SmileParameters
from .ring import Poly


class RingSignatureError(ValueError):
    """The ring, the key, or the signature is malformed."""


@dataclass(frozen=True)
class Parameters:
    """The ring signature's public parameters."""

    keys: S.Keys
    matrix: tuple[tuple[Poly, ...], ...]
    depth: int

    def __post_init__(self) -> None:
        if self.depth != self.keys.depth:
            raise RingSignatureError("parameter depth disagree")
        if len(self.matrix) != SMILE.matrix_rows:
            raise RingSignatureError("A must have k rows")
        if any(len(row) != SMILE.matrix_cols for row in self.matrix):
            raise RingSignatureError("A must have ell columns")

    @property
    def ring_size(self) -> int:
        return S.SLOTS**self.depth


def setup(
    rng: random.Random, depth: int, parameters: SmileParameters | None = None
) -> Parameters:
    """RS.Setup: sample the proof keys and the matrix A."""
    sm = SMILE if parameters is None else parameters
    matrix = tuple(
        tuple(ring.sample_uniform(rng, sm) for _ in range(sm.matrix_cols))
        for _ in range(sm.matrix_rows)
    )
    return Parameters(keys=S.setup(rng, depth, sm), matrix=matrix, depth=depth)


def keygen(
    parameters: Parameters, rng: random.Random, params: SmileParameters | None = None
) -> tuple[tuple[Poly, ...], tuple[Poly, ...]]:
    """RS.KeyGen: a short secret and its public key A s."""
    return S.keygen(rng, parameters.matrix, params)


def sign(
    parameters: Parameters,
    secret: tuple[Poly, ...],
    public: tuple[Poly, ...],
    ring_keys: tuple[tuple[Poly, ...], ...],
    message: bytes,
    rng: random.Random,
    params: SmileParameters | None = None,
) -> S.Proof:
    """RS.Sign: prove knowledge of a preimage of one key in `ring_keys`."""
    if len(ring_keys) != parameters.ring_size:
        raise RingSignatureError("the ring must have l^m public keys")
    try:
        index = ring_keys.index(public)
    except ValueError:
        raise RingSignatureError("the public key is not in the ring") from None
    statement = S.Statement(matrix=parameters.matrix, keys=ring_keys, depth=parameters.depth)
    return S.prove(parameters.keys, statement, secret, index, message, rng, params)


def verify(
    parameters: Parameters,
    ring_keys: tuple[tuple[Poly, ...], ...],
    message: bytes,
    signature: S.Proof,
    params: SmileParameters | None = None,
) -> bool:
    """RS.Ver: check the signature against the ring."""
    if len(ring_keys) != parameters.ring_size:
        return False
    try:
        statement = S.Statement(
            matrix=parameters.matrix, keys=ring_keys, depth=parameters.depth
        )
    except (TypeError, ValueError):
        return False
    return S.verify(parameters.keys, statement, signature, message, params)


def size_bytes(depth: int) -> int:
    """Wire size of a ring signature at this depth (the proof, plus nothing)."""
    width = S.masking_width(depth)
    elements = (
        SMILE.challenge_dim
        + SMILE.matrix_rows
        + 2 * depth
        + 1  # commitments t_0 .. t_{k+2m+1}
        + 2  # h and omega
        + SMILE.matrix_cols  # z'
        + width  # z
    )
    return elements * SMILE.ring_degree * 4 + 2 * SMILE.ring_degree
