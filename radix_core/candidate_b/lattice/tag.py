"""KNOWN BROKEN - DO NOT USE. Retained as a documented negative result.

Review finding (2026-11-08), reproduced in ``experiments/tag_forgery_repro.py``:
the proof below binds only the *derived* row ``u_der = <A', u> - message`` and
never the individual ``u_j``. A forger therefore picks any tag, any short
``r_m``, sets ``t = B_0^m r_m``, and chooses ``u`` so that
``<A', u> = <b', r_m> + message``. Then ``u_der = <b', r_m>``, and an honest
opening proof to zero -- which the forger can produce, because it chose ``r_m``
-- verifies. No secret is used, and the forgery succeeds against the real
verifier.

This is the same free-response failure as the crude construction it replaced,
one level down: it binds one derived row instead of the ell committed values.
A sound tag must commit the individual ``u_j`` and prove ``<A', u>`` against
them -- a linear-consistency argument over committed values, not a single
derived row. That is redesign work, not a patch.

Everything below is the original documentation of the attempt, kept because the
failed argument is part of the record.

A linkable tag for the SMILE ring signature: the committed-mask fix.

The naive construction (``experiments/linear_tag_soundness.py``) fails because
``tau = A' y'`` is uncommitted, so a prover can pick any tag and solve for
``tau`` afterwards. This module tried to close that hole by **committing to the
mask** and proving a relation against the derived key.

Construction, with a single public row ``A'`` (so the tag is one polynomial):

    commitment   t_m = B_0^m r_m,   u_j = <b^m_j, r_m> + y'_j        (j = 1..ell)
    mask         z' = y' + c' s
    tag          T  = <A', s>

The verifier forms, from public data only,

    m      = <A', z'> - c' T
    u_der  = <A', u> - m
           = <b', r_m> + c' (T - <A', s>)          with b' = sum_j A'_j * b^m_j

and verifies a BDLOP opening proof that ``(t_m ; u_der)`` opens to the message
``0`` under the derived key ``(B_0^m ; b')``. That proof forces
``c' (T - <A', s>) = 0``; since ``c'`` is invertible in `R_q` with overwhelming
probability -- and the verifier *checks* it -- the tag satisfies
``T = <A', s>``. Two spends of one note therefore carry the same tag, and a
different note carries a different one.

Assumptions, stated rather than implied:

* the tag is a Module-SIS-style collision problem: two distinct secrets with the
  same ``<A', .>`` would collide, so the tag's unforgeability rests on that
  hardness assumption, not on the ring signature alone;
* ``c'`` invertibility is checked by requiring every NTT coordinate to be
  non-zero. Every valid SMILE modulus forces the quartics to split, since the
  constant term ``r_i = (zeta^{2i+1})^4`` is an explicit fourth power, so that is
  exactly invertibility -- this is a property of the construction, not of the
  prototype ``q``;
* this is a second proof attached to the ring signature, not a single composed
  witness. Composition is milestone B5 and is not attempted here.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from . import bdlop, ntt, ring, sigma
from .params import SMILE, SmileParameters
from .ring import Poly

TAG_TAG = b"radix/b/lattice/tag/v1"


class TagError(ValueError):
    """The tag keys, mask, challenge, or proof are malformed."""


def _p(parameters: SmileParameters | None = None) -> SmileParameters:
    return SMILE if parameters is None else parameters


def invertible(poly: Poly, parameters: SmileParameters | None = None) -> bool:
    """Whether `poly` is a unit of R_q.

    Split quartic: all 128 NTT coordinates nonzero. Irreducible quartic: all 32
    residues nonzero, since each is an element of a field. See
    `setmembership._is_unit` for why the two conditions differ.
    """
    p = _p(parameters)
    if ntt.try_transform(p.modulus, p.ring_degree) is not None:
        return all(coefficient != 0 for coefficient in ntt.forward(poly, p))
    from . import subring

    return all(residue != (0, 0, 0, 0) for residue in subring.slots(poly, p))


@dataclass(frozen=True)
class TagKeys:
    """A mask-commitment key plus the public tag row A'."""

    mask_rows0: tuple[tuple[Poly, ...], ...]
    mask_rows: tuple[tuple[Poly, ...], ...]
    row: tuple[Poly, ...]

    def __post_init__(self) -> None:
        if len(self.mask_rows0) != SMILE.challenge_dim:
            raise TagError("the mask key needs kappa B_0 rows")
        if len(self.mask_rows) != SMILE.matrix_cols:
            raise TagError("the mask key needs ell b rows")
        if len(self.row) != SMILE.matrix_cols:
            raise TagError("A' must have ell entries")
        width = SMILE.matrix_cols
        for entry in self.mask_rows0 + self.mask_rows:
            if len(entry) != width:
                raise TagError("mask key rows must have ell entries")

    @property
    def commitment_key(self) -> bdlop.CommitmentKey:
        return bdlop.CommitmentKey(
            matrix=self.mask_rows0,
            vector=self.mask_rows[0],
            rows=SMILE.challenge_dim,
            cols=SMILE.matrix_cols,
        )

    def derived_row(self, p: SmileParameters | None = None) -> tuple[Poly, ...]:
        """b' = sum_j A'_j * b^m_j, the key row of the derived commitment."""
        sm = _p(p)
        width = sm.matrix_cols
        out = []
        for index in range(width):
            total = ring.zero(sm)
            for j in range(width):
                total = ring.add(
                    total, ring.mul(self.row[j], self.mask_rows[j][index], sm), sm
                )
            out.append(total)
        return tuple(out)

    def derived_key(self, p: SmileParameters | None = None) -> bdlop.CommitmentKey:
        return bdlop.CommitmentKey(
            matrix=self.mask_rows0,
            vector=self.derived_row(p),
            rows=SMILE.challenge_dim,
            cols=SMILE.matrix_cols,
        )


def setup(rng: random.Random, parameters: SmileParameters | None = None) -> TagKeys:
    sm = _p(parameters)
    width = sm.matrix_cols

    def row() -> tuple[Poly, ...]:
        return tuple(ring.sample_uniform(rng, sm) for _ in range(width))

    return TagKeys(
        mask_rows0=tuple(row() for _ in range(sm.challenge_dim)),
        mask_rows=tuple(row() for _ in range(width)),
        row=row(),
    )


def tag_of(keys: TagKeys, secret: tuple[Poly, ...], parameters: SmileParameters | None = None) -> Poly:
    """T = <A', s>."""
    sm = _p(parameters)
    if len(secret) != sm.matrix_cols:
        raise TagError("the secret must have ell components")
    return ring.dot(keys.row, secret, sm)


@dataclass(frozen=True)
class TagProof:
    """Mask commitment (t_m; u), the tag T, and the opening proof."""

    t: tuple[Poly, ...]
    u: tuple[Poly, ...]
    tag: Poly
    proof: sigma.OpeningProof

    def encode(self) -> bytes:
        return (
            b"".join(ring.encode(poly) for poly in self.t)
            + b"".join(ring.encode(poly) for poly in self.u)
            + ring.encode(self.tag)
            + self.proof.encode()
        )

    @property
    def size_bytes(self) -> int:
        return len(self.encode())


def prove_tag(
    keys: TagKeys,
    secret: tuple[Poly, ...],
    mask: tuple[Poly, ...],
    challenge_prime: Poly,
    response_prime: tuple[Poly, ...],
    context: bytes,
    rng: random.Random,
    parameters: SmileParameters | None = None,
) -> TagProof:
    """Commit to the mask and prove the tag relation against it.

    `mask` is the ``y'`` that produced ``response_prime = y' + c' s``, so the
    caller must pass the same mask it used in the ring signature.
    """
    sm = _p(parameters)
    width = sm.matrix_cols
    if len(mask) != width or len(response_prime) != width:
        raise TagError("the mask and response must have ell components")
    if not invertible(challenge_prime, sm):
        raise TagError("c' is not invertible; the tag proof would not bind")
    expected = tuple(
        ring.add(mask[i], ring.mul(challenge_prime, secret[i], sm), sm) for i in range(width)
    )
    if expected != tuple(response_prime):
        raise TagError("the response does not match y' + c' s")

    randomness = ring.sample_vector(rng, width, small=True, parameters=sm)
    t = tuple(ring.mat_vec(keys.mask_rows0, randomness, sm))
    u = tuple(
        ring.add(ring.dot(keys.mask_rows[j], randomness, sm), mask[j], sm)
        for j in range(width)
    )
    tag = tag_of(keys, secret, sm)
    message = ring.sub(
        ring.dot(keys.row, response_prime, sm), ring.mul(challenge_prime, tag, sm), sm
    )
    derived_u = ring.sub(ring.dot(keys.row, u, sm), message, sm)
    proof = sigma.prove(
        keys.derived_key(sm),
        bdlop.Commitment(t=t, u=derived_u),
        ring.zero(sm),
        randomness,
        context,
        rng,
        sm,
    )
    return TagProof(t=t, u=u, tag=tag, proof=proof)


def verify_tag(
    keys: TagKeys,
    proof: TagProof,
    challenge_prime: Poly,
    response_prime: tuple[Poly, ...],
    context: bytes,
    parameters: SmileParameters | None = None,
) -> bool:
    sm = _p(parameters)
    width = sm.matrix_cols
    try:
        if type(proof) is not TagProof:
            return False
        if len(proof.t) != sm.challenge_dim or len(proof.u) != width:
            return False
        if len(response_prime) != width:
            return False
        if not invertible(challenge_prime, sm):
            return False
        message = ring.sub(
            ring.dot(keys.row, response_prime, sm), ring.mul(challenge_prime, proof.tag, sm), sm
        )
        derived_u = ring.sub(ring.dot(keys.row, proof.u, sm), message, sm)
        return sigma.verify(
            keys.derived_key(sm),
            bdlop.Commitment(t=proof.t, u=derived_u),
            ring.zero(sm),
            proof.proof,
            context,
            sm,
        )
    except (TypeError, ValueError):
        return False
