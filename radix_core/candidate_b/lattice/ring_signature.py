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
    """The ring signature's public parameters.

    ``tag_matrix`` holds the rows of ``A'``. When it is non-empty the proof runs
    over ``A_ext = [A; A']`` and the tag ``T = A' s`` is derived from the same
    witness, which is the construction a reviewer recommended after the separate
    tag proof was found forgeable.
    """

    keys: S.Keys
    matrix: tuple[tuple[Poly, ...], ...]
    depth: int
    tag_matrix: tuple[tuple[Poly, ...], ...] = ()
    #: The ring algebra this statement was built over. `SmileParameters` and
    #: `Parameters` are different objects -- the first carries modulus, ring degree and
    #: matrix width, the second carries the actual matrices -- and three separate modules
    #: broke by assuming one was the other. Exposing it here means a module that has a
    #: `Parameters` never has to guess which type it is holding.
    smile: SmileParameters = SMILE

    def __post_init__(self) -> None:
        if self.depth != self.keys.depth:
            raise RingSignatureError("parameter depth disagree")
        if not self.matrix:
            raise RingSignatureError("A must have at least one row")
        # Derive the width from the rows rather than from the default parameters:
        # a statement can be built at a different ell (the noise-aware statement needs
        # ell = 17), and pinning it to SMILE.matrix_cols made every such statement
        # impossible to construct.
        width = len(self.matrix[0])
        if width < 1:
            raise RingSignatureError("A must have at least one column")
        for row in self.matrix + self.tag_matrix:
            if len(row) != width:
                raise RingSignatureError("every row of A must have the same width")
        if self.keys.count != len(self.matrix) + len(self.tag_matrix):
            raise RingSignatureError("the key height must match A_ext")

    @property
    def ring_size(self) -> int:
        return S.SLOTS**self.depth

    @property
    def tag_rows(self) -> int:
        return len(self.tag_matrix)

    @property
    def extended(self) -> tuple[tuple[Poly, ...], ...]:
        return self.matrix + self.tag_matrix


def setup(
    rng: random.Random,
    depth: int,
    parameters: SmileParameters | None = None,
    tag_rows: int = 0,
) -> Parameters:
    """RS.Setup: sample the proof keys, the matrix A and (optionally) A'."""
    sm = SMILE if parameters is None else parameters
    if tag_rows < 0:
        raise RingSignatureError("tag_rows must not be negative")

    def row() -> tuple[Poly, ...]:
        return tuple(ring.sample_uniform(rng, sm) for _ in range(sm.matrix_cols))

    matrix = tuple(row() for _ in range(sm.matrix_rows))
    tag_matrix = tuple(row() for _ in range(tag_rows))
    keys = S.setup(rng, depth, sm, row_count=sm.matrix_rows + tag_rows)
    return Parameters(
        keys=keys, matrix=matrix, depth=depth, tag_matrix=tag_matrix, smile=sm
    )


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
    if parameters.tag_rows:
        raise RingSignatureError("these parameters carry tag rows; use sign_tagged")
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
    if parameters.tag_rows:
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




def tag_of(
    parameters: Parameters,
    secret: tuple[Poly, ...],
    params: SmileParameters | None = None,
) -> tuple[Poly, ...]:
    """T = A' s: one polynomial per tag row."""
    sm = SMILE if params is None else params
    if not parameters.tag_rows:
        raise RingSignatureError("these parameters have no tag rows")
    if len(secret) != sm.matrix_cols:
        raise RingSignatureError("the secret must have ell components")
    return tuple(ring.dot(row, secret, sm) for row in parameters.tag_matrix)


def sign_tagged(
    parameters: Parameters,
    secret: tuple[Poly, ...],
    public: tuple[Poly, ...],
    ring_keys: tuple[tuple[Poly, ...], ...],
    message: bytes,
    rng: random.Random,
    params: SmileParameters | None = None,
) -> tuple[S.Proof, tuple[Poly, ...]]:
    """Sign over the extended ring {(pk_j, T)}, where every member shares T.

    One witness, one proof. The tag rows are part of the proved relation, so a
    forger cannot choose T independently of the secret it opened.
    """
    sm = SMILE if params is None else params
    if not parameters.tag_rows:
        raise RingSignatureError("these parameters have no tag rows")
    if len(ring_keys) != parameters.ring_size:
        raise RingSignatureError("the ring must have l^m public keys")
    tag = tag_of(parameters, secret, sm)
    try:
        index = tuple(key + tag for key in ring_keys).index(public + tag)
    except ValueError:
        raise RingSignatureError("the public key is not in the ring") from None
    statement = S.Statement(
        matrix=parameters.extended,
        keys=tuple(key + tag for key in ring_keys),
        depth=parameters.depth,
    )
    proof = S.prove(parameters.keys, statement, secret, index, message, rng, sm)
    return proof, tag


def verify_tagged(
    parameters: Parameters,
    ring_keys: tuple[tuple[Poly, ...], ...],
    tag: tuple[Poly, ...],
    message: bytes,
    signature: S.Proof,
    params: SmileParameters | None = None,
) -> bool:
    """Check the proof against the extended ring built from the published tag."""
    sm = SMILE if params is None else params
    try:
        if not parameters.tag_rows or len(tag) != parameters.tag_rows:
            return False
        if len(ring_keys) != parameters.ring_size:
            return False
        statement = S.Statement(
            matrix=parameters.extended,
            keys=tuple(key + tag for key in ring_keys),
            depth=parameters.depth,
        )
    except (TypeError, ValueError):
        return False
    return S.verify(parameters.keys, statement, signature, message, sm)



