"""Proof of knowledge of a BDLOP opening (the inner Sigma-protocol of SMILE).

Given a commitment (t ; u) = (B ; b)·s + (0 ; m), prove knowledge of the short
opening vector `s` for a public message `m`. This is the `pi` in SMILE Fig. 5
(p. 14 of the full version) and the layer the set-membership proof builds on.

Protocol (Fiat-Shamir):
  prover:  y <- uniform in [-B, B]^ell
           w  = B·y,  w~ = <b, y>
           c  = H(context, w, w~)              (ternary challenge polynomial)
           z  = y + c·s  (componentwise)
  verifier: w' = B·z - c·t ;  w~' = <b, z> - c·(u - m)
           accept iff H(context, w', w~') == c and every ||z_j||_inf <= B + 1024

No rejection sampling: the masking bound B = 2^20 dwarfs ||c·s||_inf <= d·mu = 640,
so z is statistically close to uniform and the proof is honest-verifier zero
knowledge without aborting. The cost is a larger response (ell * 512 bytes); SMILE's
rejection-sampled variant shrinks it, which is future work.

Extraction caveat: two accepting transcripts give B·(z1-z2) = (c1-c2)·t, the
standard module-SIS witness relation. Making that an explicit `s` needs
(c1-c2) invertible in R_q, which is overwhelmingly likely but not checked here.
Research component; not a production proof system.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from hashlib import shake_256

from . import bdlop, ring
from .params import SMILE, SmileParameters
from .ring import Poly

MASK_BOUND = 1 << 20
CHALLENGE_COEFFICIENTS = (-1, 0, 1)
ACCEPT_BOUND = MASK_BOUND + 1024
PROOF_TAG = b"radix/b/lattice/sigma-opening/v1"


class SigmaError(ValueError):
    """A proof is malformed, out of bounds, or does not verify."""


@dataclass(frozen=True)
class OpeningProof:
    challenge: Poly
    response: tuple[Poly, ...]

    def encode(self) -> bytes:
        return (
            bytes(coefficient + 1 for coefficient in self.challenge)
            + b"".join(ring.encode(poly) for poly in self.response)
        )

    @classmethod
    def decode(cls, data: bytes, parameters: SmileParameters | None = None) -> OpeningProof:
        p = SMILE if parameters is None else parameters
        expected = p.ring_degree + p.matrix_cols * p.ring_degree * 4
        if type(data) is not bytes or len(data) != expected:
            raise SigmaError("opening proof has the wrong length")
        challenge = tuple(value - 1 for value in data[: p.ring_degree])
        if any(value not in CHALLENGE_COEFFICIENTS for value in challenge):
            raise SigmaError("challenge coefficient outside {-1,0,1}")
        payload = data[p.ring_degree :]
        stride = p.ring_degree * 4
        response = tuple(
            ring.decode(payload[index * stride : (index + 1) * stride], p)
            for index in range(p.matrix_cols)
        )
        return cls(challenge=challenge, response=response)


def _challenge(
    context: bytes,
    w: tuple[Poly, ...],
    w_tilde: Poly,
    parameters: SmileParameters | None = None,
) -> Poly:
    p = SMILE if parameters is None else parameters
    digest = shake_256()
    digest.update(PROOF_TAG)
    digest.update(len(context).to_bytes(4, "little"))
    digest.update(context)
    for poly in w:
        digest.update(ring.encode(poly, p))
    digest.update(ring.encode(w_tilde, p))
    # The paper's challenge distribution C: P(0) = 1/2, P(1) = P(-1) = 1/4.
    # sigma and setmembership must not draw from different spaces.
    return tuple(
        0 if byte < 128 else (1 if byte < 192 else -1)
        for byte in digest.digest(p.ring_degree)
    )


def _mask_vector(
    rng: random.Random, count: int, parameters: SmileParameters | None = None
) -> tuple[Poly, ...]:
    p = SMILE if parameters is None else parameters
    return tuple(
        tuple(
            rng.randint(-MASK_BOUND, MASK_BOUND) % p.modulus
            for _ in range(p.ring_degree)
        )
        for _ in range(count)
    )


def _response_norm_ok(response: tuple[Poly, ...]) -> bool:
    return all(ring.norm_inf(poly) <= ACCEPT_BOUND for poly in response)


def prove(
    key: bdlop.CommitmentKey,
    commitment: bdlop.Commitment,
    message: Poly,
    randomness: tuple[Poly, ...],
    context: bytes,
    rng: random.Random,
    parameters: SmileParameters | None = None,
) -> OpeningProof:
    p = SMILE if parameters is None else parameters
    if not bdlop.verify(key, commitment, message, randomness, p):
        raise SigmaError("opening does not match the commitment")
    mask = _mask_vector(rng, key.width, p)
    w = ring.mat_vec(key.matrix, mask, p)
    w_tilde = ring.dot(key.vector, mask, p)
    challenge = _challenge(context, w, w_tilde, p)
    response = tuple(
        ring.add(y, ring.mul(challenge, s, p), p)
        for y, s in zip(mask, randomness)
    )
    if not _response_norm_ok(response):
        raise SigmaError("masking bound produced an oversized response")
    return OpeningProof(challenge=challenge, response=response)


def verify(
    key: bdlop.CommitmentKey,
    commitment: bdlop.Commitment,
    message: Poly,
    proof: OpeningProof,
    context: bytes,
    parameters: SmileParameters | None = None,
) -> bool:
    p = SMILE if parameters is None else parameters
    try:
        if type(proof) is not OpeningProof:
            return False
        if len(proof.response) != key.width:
            return False
        if not _response_norm_ok(proof.response):
            return False
        expected_w = tuple(
            ring.sub(ring.dot(row, proof.response, p), ring.mul(proof.challenge, t, p), p)
            for row, t in zip(key.matrix, commitment.t)
        )
        expected_w_tilde = ring.add(
            ring.sub(
                ring.dot(key.vector, proof.response, p),
                ring.mul(proof.challenge, commitment.u, p),
                p,
            ),
            ring.mul(proof.challenge, message, p),
            p,
        )
        return _challenge(context, expected_w, expected_w_tilde, p) == proof.challenge
    except (TypeError, ValueError):
        return False
