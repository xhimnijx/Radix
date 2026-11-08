"""Aggregation of k BDLOP commitments into one (SMILE Fig. 5, p. 14).

Fig. 5 takes ``k`` commitments

    (t_i ; u_i) = (B ; b).s_i + (0 ; m_i),      i = 1..k

under distinct randomnesses and outputs

    omega = (A ; a_1, ..., a_k ; a_w).r + (0 ; m_1, ..., m_k ; w~)

under one common randomness ``r``, together with a proof ``pi`` that the ``(t_i ; u_i)``
are valid and that ``omega`` commits to the same ``m_i``.

Why this layer first: Fig. 6 (set membership) keeps Fig. 5's omega, challenge, ``z``
and ``pi`` unchanged and only stops revealing which column of ``T`` was selected. The
missing piece there is the tensor/multiplication relation proved with the quadratic
constraints of p. 23; it is not a change to this protocol. Landing Fig. 5 gives the
transaction-aggregation primitive that Fig. 6 will reuse.

The identity that makes the verifier able to check ``pi`` without any secret is

    g* = sum_i c_i g_i - g_w + b.z
       = (sum_i c_i a_i - a_w).r + sum_i c_i m_i - w~ + b.z
       = a*.r + sum_i c_i u_i                                   (since b.z = w~ + sum c_i (u_i - m_i))

so ``(f ; g*)`` is a BDLOP commitment under ``(A ; a*)`` to the *public* message
``mu = sum_i c_i u_i``. ``pi`` is exactly the opening proof for that commitment, i.e.
``sigma.prove``. ``prove`` asserts this identity numerically rather than trusting it.

Caveats, stated rather than implied:
* ``z`` is masked without rejection sampling (the mask bound dwarfs ``k*kappa*mu``), so
  the proof is honest-verifier zero knowledge but the response is larger than SMILE's.
* Extraction of ``s_i`` from two accepting transcripts needs ``(c - c')`` invertible in
  ``R_q``; overwhelmingly likely, not checked here. Research component: this is not a
  reviewed proof system and carries no security claim.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from hashlib import shake_256

from . import bdlop, ring, sigma
from .params import SMILE, SmileParameters
from .ring import Poly

TAG = b"radix/b/lattice/aggregation/v1"
SUB_TAG = b"radix/b/lattice/aggregation/pi/v1"
CHALLENGE_BYTES = 512


class AggregationError(ValueError):
    """The aggregation key, transcript, or proof is malformed."""


@dataclass(frozen=True)
class AggregationKey:
    """Public data: the (B ; b) commitment key plus the omega key rows."""

    commitment: bdlop.CommitmentKey
    matrix: tuple[tuple[Poly, ...], ...]
    rows: tuple[tuple[Poly, ...], ...]
    row_w: tuple[Poly, ...]

    def __post_init__(self) -> None:
        if type(self.commitment) is not bdlop.CommitmentKey:
            raise AggregationError("commitment key has the wrong type")
        if len(self.matrix) != SMILE.matrix_rows:
            raise AggregationError("the omega matrix must have k rows")
        if not self.rows or len(self.rows) > len(self.matrix):
            raise AggregationError("row height must be in 1..k")
        for row in self.matrix + self.rows:
            if len(row) != SMILE.matrix_cols:
                raise AggregationError("key rows must have ell entries")
        if len(self.row_w) != SMILE.matrix_cols:
            raise AggregationError("the w row must have ell entries")

    @property
    def input_count(self) -> int:
        return len(self.rows)


@dataclass(frozen=True)
class Omega:
    """omega = (f ; g_1..g_k ; g_w), the aggregated BDLOP commitment."""

    f: tuple[Poly, ...]
    g: tuple[Poly, ...]
    g_w: Poly

    def __post_init__(self) -> None:
        if len(self.f) != SMILE.matrix_rows:
            raise AggregationError("omega f must have k entries")
        if not self.g or len(self.g) > len(self.f):
            raise AggregationError("omega g must have 1..k entries")

    def encode(self) -> bytes:
        return (
            b"".join(ring.encode(poly) for poly in self.f)
            + b"".join(ring.encode(poly) for poly in self.g)
            + ring.encode(self.g_w)
        )


@dataclass(frozen=True)
class AggregationProof:
    """(w, omega, z, pi); the challenges are derived, never transmitted."""

    w: tuple[Poly, ...]
    omega: Omega
    response: tuple[Poly, ...]
    pi: sigma.OpeningProof

    def encode(self) -> bytes:
        return (
            b"".join(ring.encode(poly) for poly in self.w)
            + self.omega.encode()
            + b"".join(ring.encode(poly) for poly in self.response)
            + self.pi.encode()
        )

    @classmethod
    def decode(
        cls, data: bytes, input_count: int, parameters: SmileParameters | None = None
    ) -> AggregationProof:
        p = SMILE if parameters is None else parameters
        if type(data) is not bytes or type(input_count) is not int or input_count < 1:
            raise AggregationError("malformed aggregation proof")
        stride = p.full_element_bytes
        expected = (
            (2 * p.matrix_rows + input_count + 1 + p.matrix_cols) * stride
            + p.ring_degree
            + p.matrix_cols * stride
        )
        if len(data) != expected:
            raise AggregationError("aggregation proof has the wrong length")

        offset = 0

        def take(count: int) -> tuple[Poly, ...]:
            nonlocal offset
            chunk = data[offset : offset + count * stride]
            offset += count * stride
            return tuple(
                ring.decode(chunk[index * stride : (index + 1) * stride], p)
                for index in range(count)
            )

        w = take(p.matrix_rows)
        f = take(p.matrix_rows)
        g = take(input_count)
        g_w = ring.decode(data[offset : offset + stride], p)
        offset += stride
        response = take(p.matrix_cols)
        pi = sigma.OpeningProof.decode(data[offset:], p)
        return cls(w=w, omega=Omega(f=f, g=g, g_w=g_w), response=response, pi=pi)


def setup(
    rng: random.Random,
    input_count: int | None = None,
    parameters: SmileParameters | None = None,
) -> AggregationKey:
    """Sample (B ; b) and the omega key rows (A ; a_1..a_k ; a_w)."""
    p = SMILE if parameters is None else parameters
    count = p.matrix_rows if input_count is None else input_count
    if type(count) is not int or not 1 <= count <= p.matrix_rows:
        raise AggregationError("input count must be in 1..k")
    commitment = bdlop.setup(rng, p)

    def row() -> tuple[Poly, ...]:
        return tuple(ring.sample_uniform(rng, p) for _ in range(p.matrix_cols))

    matrix = tuple(row() for _ in range(p.matrix_rows))
    rows = tuple(row() for _ in range(count))
    return AggregationKey(
        commitment=commitment, matrix=matrix, rows=rows, row_w=row()
    )


def _challenges(
    context: bytes,
    w: tuple[Poly, ...],
    omega: Omega,
    parameters: SmileParameters | None = None,
) -> tuple[Poly, ...]:
    """k sparse ternary challenges with exactly kappa non-zero coefficients each."""
    p = SMILE if parameters is None else parameters
    digest = shake_256()
    digest.update(TAG)
    digest.update(len(context).to_bytes(4, "little"))
    digest.update(context)
    for poly in w:
        digest.update(ring.encode(poly, p))
    digest.update(omega.encode())
    stream = digest.digest(CHALLENGE_BYTES)
    cursor = 0

    def draw(bound: int) -> int:
        nonlocal cursor
        if bound < 1:
            raise AggregationError("cannot draw from an empty range")
        if cursor + 4 > len(stream):
            raise AggregationError("challenge stream exhausted")
        value = int.from_bytes(stream[cursor : cursor + 4], "little")
        cursor += 4
        return value % bound

    challenges = []
    for _ in range(len(omega.g)):
        pool = list(range(p.ring_degree))
        coefficients = [0] * p.ring_degree
        for _ in range(p.challenge_dim):
            position = pool.pop(draw(len(pool)))
            coefficients[position] = 1 if draw(2) else -1
        challenges.append(tuple(coefficients))
    return tuple(challenges)


def _subcontext(
    context: bytes,
    w: tuple[Poly, ...],
    omega: Omega,
    response: tuple[Poly, ...],
    parameters: SmileParameters | None = None,
) -> bytes:
    """Bind the whole aggregation transcript into the inner opening proof."""
    p = SMILE if parameters is None else parameters
    digest = shake_256()
    digest.update(SUB_TAG)
    digest.update(len(context).to_bytes(4, "little"))
    digest.update(context)
    for poly in w:
        digest.update(ring.encode(poly, p))
    digest.update(omega.encode())
    for poly in response:
        digest.update(ring.encode(poly, p))
    return digest.digest(32)


def _omega(
    key: AggregationKey,
    messages: tuple[Poly, ...],
    randomness: tuple[Poly, ...],
    w_tilde: Poly,
    parameters: SmileParameters | None = None,
) -> Omega:
    p = SMILE if parameters is None else parameters
    return Omega(
        f=ring.mat_vec(key.matrix, randomness, p),
        g=tuple(
            ring.add(ring.dot(a, randomness, p), message, p)
            for a, message in zip(key.rows, messages)
        ),
        g_w=ring.add(ring.dot(key.row_w, randomness, p), w_tilde, p),
    )


def prove(
    key: AggregationKey,
    inputs: tuple[bdlop.Commitment, ...],
    messages: tuple[Poly, ...],
    secrets: tuple[tuple[Poly, ...], ...],
    context: bytes,
    rng: random.Random,
    parameters: SmileParameters | None = None,
) -> AggregationProof:
    p = SMILE if parameters is None else parameters
    if len(inputs) != key.input_count or len(messages) != key.input_count:
        raise AggregationError("input count does not match the aggregation key")
    if len(secrets) != key.input_count:
        raise AggregationError("every input needs an opening")
    for commitment, message, secret in zip(inputs, messages, secrets):
        if not bdlop.verify(key.commitment, commitment, message, secret, p):
            raise AggregationError("an input commitment does not match its opening")

    mask = sigma._mask_vector(rng, p)
    w = ring.mat_vec(key.commitment.matrix, mask, p)
    w_tilde = ring.dot(key.commitment.vector, mask, p)
    randomness = bdlop.opening(rng, p)
    omega = _omega(key, messages, randomness, w_tilde, p)

    challenges = _challenges(context, w, omega, p)
    response = tuple(
        ring.add(
            mask[column],
            _sum_scaled(challenges, tuple(secret[column] for secret in secrets), p),
            p,
        )
        for column in range(p.matrix_cols)
    )
    if not all(ring.norm_inf(poly) <= sigma.ACCEPT_BOUND for poly in response):
        raise AggregationError("masking bound produced an oversized response")

    a_star = _select_rows(key.rows, challenges, key.row_w, p)
    g_star = _g_star(key, omega, challenges, response, p)
    mu = _message_combination(inputs, challenges, p)
    if g_star != ring.add(ring.dot(a_star, randomness, p), mu, p):
        raise AggregationError("aggregation identity does not close")
    pi = sigma.prove(
        bdlop.CommitmentKey(matrix=key.matrix, vector=a_star),
        bdlop.Commitment(t=omega.f, u=g_star),
        mu,
        randomness,
        _subcontext(context, w, omega, response, p),
        rng,
        p,
    )
    return AggregationProof(w=w, omega=omega, response=response, pi=pi)


def _sum_scaled(
    challenges: tuple[Poly, ...], values: tuple[Poly, ...], parameters: SmileParameters
) -> Poly:
    if len(challenges) != len(values):
        raise AggregationError("challenge count does not match the value count")
    total = ring.zero(parameters)
    for challenge, value in zip(challenges, values):
        total = ring.add(total, ring.mul(challenge, value, parameters), parameters)
    return total


def _select_rows(
    rows: tuple[tuple[Poly, ...], ...],
    challenges: tuple[Poly, ...],
    row_w: tuple[Poly, ...],
    parameters: SmileParameters | None = None,
) -> tuple[Poly, ...]:
    """a* = sum_i c_i a_i - a_w."""
    p = SMILE if parameters is None else parameters
    if len(rows) != len(challenges):
        raise AggregationError("challenge count does not match the key rows")
    out = []
    for column in range(p.matrix_cols):
        total = ring.zero(p)
        for challenge, row in zip(challenges, rows):
            total = ring.add(total, ring.mul(challenge, row[column], p), p)
        out.append(ring.sub(total, row_w[column], p))
    return tuple(out)


def _g_star(
    key: AggregationKey,
    omega: Omega,
    challenges: tuple[Poly, ...],
    response: tuple[Poly, ...],
    parameters: SmileParameters | None = None,
) -> Poly:
    """g* = sum_i c_i g_i - g_w + b.z, computed from public data only."""
    p = SMILE if parameters is None else parameters
    total = _sum_scaled(challenges, omega.g, p)
    return ring.add(
        ring.sub(total, omega.g_w, p), ring.dot(key.commitment.vector, response, p), p
    )


def _message_combination(
    inputs: tuple[bdlop.Commitment, ...],
    challenges: tuple[Poly, ...],
    parameters: SmileParameters | None = None,
) -> Poly:
    """mu = sum_i c_i u_i, public because the inputs are public."""
    p = SMILE if parameters is None else parameters
    return _sum_scaled(challenges, tuple(item.u for item in inputs), p)


def verify(
    key: AggregationKey,
    inputs: tuple[bdlop.Commitment, ...],
    proof: AggregationProof,
    context: bytes,
    parameters: SmileParameters | None = None,
) -> bool:
    p = SMILE if parameters is None else parameters
    try:
        if type(proof) is not AggregationProof or type(key) is not AggregationKey:
            return False
        if len(inputs) != key.input_count or len(proof.w) != p.matrix_rows:
            return False
        if len(proof.response) != p.matrix_cols:
            return False
        if not all(ring.norm_inf(poly) <= sigma.ACCEPT_BOUND for poly in proof.response):
            return False
        challenges = _challenges(context, proof.w, proof.omega, p)
        if type(proof.pi) is not sigma.OpeningProof:
            return False
        expected_t = tuple(
            _sum_scaled(challenges, tuple(item.t[column] for item in inputs), p)
            for column in range(p.matrix_rows)
        )
        actual_t = tuple(
            ring.sub(product, masked, p)
            for product, masked in zip(
                ring.mat_vec(key.commitment.matrix, proof.response, p), proof.w
            )
        )
        if expected_t != actual_t:
            return False
        a_star = _select_rows(key.rows, challenges, key.row_w, p)
        g_star = _g_star(key, proof.omega, challenges, proof.response, p)
        mu = _message_combination(inputs, challenges, p)
        return sigma.verify(
            bdlop.CommitmentKey(matrix=key.matrix, vector=a_star),
            bdlop.Commitment(t=proof.omega.f, u=g_star),
            mu,
            proof.pi,
            _subcontext(context, proof.w, proof.omega, proof.response, p),
            p,
        )
    except (TypeError, ValueError):
        return False


def size_bytes(input_count: int, parameters: SmileParameters | None = None) -> int:
    """Wire size of an aggregation proof: w, omega, z and the inner sigma proof."""
    p = SMILE if parameters is None else parameters
    return (
        (2 * p.matrix_rows + input_count + 1 + p.matrix_cols) * p.full_element_bytes
        + p.ring_degree
        + p.matrix_cols * p.full_element_bytes
    )

