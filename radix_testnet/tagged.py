"""Tagged spends: a spend the node can reject on the second attempt.

A ring signature deliberately hides *which* key it opens, so a plain UTXO set
cannot tell a first spend from a second one -- that is the anonymity working as
designed. The linkable tag is what restores double-spend detection, and the
same-witness extension from `ring_signature.sign_tagged` is the sound version of
it, so that is what the testnet uses. `k' = 4` per `REVIEW-FINDINGS.md`.

`radix_core.candidate_b.lattice.spend.build_spend` predates the extension and calls
the untagged signer, so this module supplies the tagged equivalent rather than
changing radix_core.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from radix_core.candidate_b.lattice import ring, ring_signature as RS
from radix_core.candidate_b.lattice import setmembership as S
from radix_core.candidate_b.lattice import spend as SP
from radix_core.candidate_b.lattice.params import SMILE, SmileParameters
from radix_core.candidate_b.lattice.spend import Output

Poly = tuple[int, ...]


class SpendError(ValueError):
    """A malformed or unbalanced spend."""


@dataclass(frozen=True)
class TaggedSpend:
    """Inputs (rings, signatures, tags, values), outputs, fee and anchor."""

    anchor: bytes
    input_values: tuple[int, ...]
    rings: tuple[tuple[Poly, ...], ...]
    outputs: tuple[Output, ...]
    fee: int
    signatures: tuple[S.Proof, ...]
    tags: tuple[tuple[Poly, ...], ...]

    def __post_init__(self) -> None:
        count = len(self.input_values)
        if not (len(self.rings) == len(self.signatures) == len(self.tags) == count):
            raise SpendError("one ring, signature, tag and value per input are required")
        if not count:
            raise SpendError("a spend needs at least one input")
        if len(self.anchor) != 32:
            raise SpendError("anchor must be 32 bytes")

    def message(self, p: SmileParameters | None = None) -> bytes:
        return SP._message(self.anchor, self.input_values, self.outputs, self.fee, p)

    def tag_bytes(self, p: SmileParameters | None = None) -> tuple[bytes, ...]:
        """Each tag as bytes: k' polynomials, the double-spend key."""
        sm = SMILE if p is None else p
        return tuple(b"".join(ring.encode(poly, sm) for poly in tag) for tag in self.tags)

    @property
    def total_in(self) -> int:
        return sum(self.input_values)

    @property
    def total_out(self) -> int:
        return sum(note.value for note in self.outputs) + self.fee

    @property
    def balanced(self) -> bool:
        return self.total_in == self.total_out


def _sign(parameters, secret, public, ring_keys, message, rng):
    """Sign one input, through whichever backend is selected.

    The Rust path cannot be a drop-in replacement for `RS.sign_tagged` at the call
    site because it returns the same pair from a subprocess; keeping the choice here
    means `build_tagged_spend` reads the same either way.
    """
    from . import prover

    if prover.BACKEND is prover.ProverBackend.RUST:
        from . import rust_backend

        return rust_backend.prove_tagged(parameters, secret, public, ring_keys, message)

    return RS.sign_tagged(parameters, secret, public, ring_keys, message, rng)


def build_tagged_spend(
    parameters: RS.Parameters,
    secrets: tuple[tuple[Poly, ...], ...],
    publics: tuple[tuple[Poly, ...], ...],
    rings: tuple[tuple[tuple[Poly, ...], ...], ...],
    input_values: tuple[int, ...],
    outputs: tuple[Output, ...],
    fee: int,
    anchor: bytes,
    rng: random.Random,
    params: SmileParameters | None = None,
) -> TaggedSpend:
    """Sign one tagged spend: one signature and one tag per input.

    Slow by construction -- a depth-2 proof is ~1-2 minutes in CPython -- which is
    why the node and the tests take a `verify` hook rather than always paying it.
    """
    if not (len(secrets) == len(publics) == len(rings) == len(input_values)):
        raise SpendError("one secret, ring and value per input are required")
    if len(anchor) != 32:
        raise SpendError("anchor must be 32 bytes")
    message = SP._message(anchor, input_values, outputs, fee, params)
    signed = tuple(
        _sign(parameters, secret, public, tuple(ring_keys), message, rng)
        for secret, public, ring_keys in zip(secrets, publics, rings)
    )
    return TaggedSpend(
        anchor=anchor,
        input_values=input_values,
        rings=rings,
        outputs=outputs,
        fee=fee,
        signatures=tuple(proof for proof, _tag in signed),
        tags=tuple(tag for _proof, tag in signed),
    )


def verify_tagged_spend(
    parameters: RS.Parameters, spend: TaggedSpend, params: SmileParameters | None = None
) -> bool:
    try:
        if not spend.balanced:
            return False
        message = spend.message(params)
        return all(
            RS.verify_tagged(parameters, tuple(ring_keys), tag, message, signature, params)
            for ring_keys, tag, signature in zip(spend.rings, spend.tags, spend.signatures)
        )
    except (TypeError, ValueError):
        return False
