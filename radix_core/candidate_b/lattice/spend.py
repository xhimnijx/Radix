"""Candidate-B spend authorisation: a lattice ring signature over a transaction message.

This is the integration point between the SMILE ring signature and a transaction.
It authorises a spend and checks value balance. It is deliberately *not* a
transaction layer yet, and the gap is specific:

**SMILE's ring signature is anonymous but not linkable.** Nothing in Figs. 7-9
produces a per-note tag, so this module cannot stop the same note being spent
twice: a spender who knows one key can sign any number of messages with it, and
each signature looks independent. Prevention needs a *nullifier proof* -- a
zero-knowledge proof that a revealed tag is ``PRF(secret, note)`` -- which is a
separate relation that this codebase does not yet implement. Until it exists,
`Ledger` below refuses every spend: the authorisation layer is complete, the
double-spend layer is absent, and pretending otherwise would be the exact kind of
fabrication this project avoids.

What *is* real here:

* canonical message encoding bound into the signature's ``c'`` challenge;
* equal-value rings, so no amount commitment or range proof is needed to keep the
  balance check sound (all ring members share the input's value);
* value balance ``sum(inputs) = sum(outputs) + fee``;
* the ring per input, checked to have exactly ``l^m`` members.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from hashlib import shake_256

from . import ring, ring_signature as RS, setmembership as S
from .params import SMILE, SmileParameters
from .ring import Poly

SPEND_TAG = b"radix/b/spend/v1"
MAX_VALUE = (1 << 64) - 1


class SpendError(ValueError):
    """A spend, its ring, or its balance is malformed."""


def _u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= MAX_VALUE:
        raise SpendError("value must be a 64-bit unsigned integer")
    return value.to_bytes(8, "big")


def _u16(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 1 << 16:
        raise SpendError("length must fit in 16 bits")
    return value.to_bytes(2, "big")


def _frame(parts) -> bytes:
    out = [SPEND_TAG]
    for part in parts:
        out.append(_u16(len(part)))
        out.append(part)
    return b"".join(out)


def key_bytes(key: tuple[Poly, ...], p: SmileParameters | None = None) -> bytes:
    sm = SMILE if p is None else p
    if len(key) != sm.matrix_rows:
        raise SpendError("a public key must have k components")
    return b"".join(ring.encode(poly, sm) for poly in key)


@dataclass(frozen=True)
class Output:
    """A one-time lattice public key and the value it holds."""

    key: tuple[Poly, ...]
    value: int

    def encode(self, p: SmileParameters | None = None) -> bytes:
        return _frame([key_bytes(self.key, p), _u64(self.value)])


@dataclass(frozen=True)
class Spend:
    """Inputs (ring + signature + value), outputs, fee and anchor."""

    anchor: bytes
    input_values: tuple[int, ...]
    rings: tuple[tuple[tuple[Poly, ...], ...], ...]
    outputs: tuple[Output, ...]
    fee: int
    signatures: tuple[S.Proof, ...]

    def __post_init__(self) -> None:
        if len(self.rings) != len(self.signatures) or len(self.rings) != len(self.input_values):
            raise SpendError("one ring, value and signature per input are required")
        if not self.rings:
            raise SpendError("a spend needs at least one input")
        if len(self.anchor) != 32:
            raise SpendError("anchor must be 32 bytes")

    def message(self, p: SmileParameters | None = None) -> bytes:
        """The canonical bytes each input signature commits to."""
        return _frame(
            [
                self.anchor,
                _u16(len(self.input_values)),
                b"".join(_u64(value) for value in self.input_values),
                _u16(len(self.outputs)),
                b"".join(note.encode(p) for note in self.outputs),
                _u64(self.fee),
            ]
        )

    @property
    def tags(self) -> tuple[bytes, ...] | None:
        """Always None: this type is untagged.

        It used to read `signature.tag_proof`, which the same-witness extension does
        not populate, so a tagged spend built the new way would have reported `None`
        here and a ledger would have silently skipped its tag checks. Tagged spends
        live in `radix_testnet.tagged.TaggedSpend`, where the tags are a real field.
        """
        return None

    @property
    def total_in(self) -> int:
        return sum(self.input_values)

    @property
    def total_out(self) -> int:
        return sum(note.value for note in self.outputs) + self.fee

    @property
    def balanced(self) -> bool:
        return self.total_in == self.total_out


def _message(anchor: bytes, input_values, outputs, fee: int, p) -> bytes:
    return _frame(
        [
            anchor,
            _u16(len(input_values)),
            b"".join(_u64(value) for value in input_values),
            _u16(len(outputs)),
            b"".join(note.encode(p) for note in outputs),
            _u64(fee),
        ]
    )


def build_spend(
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
) -> Spend:
    """Sign one spend: one ring signature per input over the shared message.

    This builds an **untagged** spend. Tagged spends have their own type:
    `radix_testnet.tagged.TaggedSpend`, built on `ring_signature.sign_tagged`, which
    proves the tag inside the same relation. The separate tag proof that used to live
    behind a `tag_keys` argument here was **forgeable** and has been removed rather
    than left reachable -- see `tag.py` and `REVIEW-FINDINGS.md`.
    """
    if not (len(secrets) == len(publics) == len(rings) == len(input_values)):
        raise SpendError("one secret, ring and value per input are required")
    if len(anchor) != 32:
        raise SpendError("anchor must be 32 bytes")
    message = _message(anchor, input_values, outputs, fee, params)
    signatures = tuple(
        RS.sign(parameters, secret, public, tuple(ring_keys), message, rng, params)
        for secret, public, ring_keys in zip(secrets, publics, rings)
    )
    return Spend(
        anchor=anchor,
        input_values=input_values,
        rings=rings,
        outputs=outputs,
        fee=fee,
        signatures=signatures,
    )


def verify_spend(
    parameters: RS.Parameters,
    spend: Spend,
    params: SmileParameters | None = None,
) -> bool:
    """Check the rings, the balance, and every signature against the message.

    Untagged only. A tagged spend is verified with `ring_signature.verify_tagged`.
    """
    try:
        if not spend.balanced:
            return False
        message = spend.message(params)
        return all(
            RS.verify(parameters, tuple(ring_keys), message, signature, params)
            for ring_keys, signature in zip(spend.rings, spend.signatures)
        )
    except (TypeError, ValueError):
        return False


class TagSet:
    """Spent tags. Immutable: ``accept`` returns a new set or raises.

    This is the double-spend check that SMILE's ring signature does not provide on
    its own. It only works on **tagged** spends: an untagged spend has no
    linkable handle, so it is refused rather than quietly accepted.
    """

    __slots__ = ("_tags",)

    def __init__(self, tags: frozenset[bytes] = frozenset()) -> None:
        self._tags = tags

    @property
    def tags(self) -> frozenset[bytes]:
        return self._tags

    def contains(self, tag: bytes) -> bool:
        return tag in self._tags

    def accept(self, spend: Spend, params: SmileParameters | None = None) -> "TagSet":
        """Add a spend's tags, refusing a replay or a duplicate within the spend."""
        if not verify_spend_or_shape(spend):
            raise SpendError("the spend is malformed")
        tags = spend.tags
        if tags is None:
            raise SpendError("an untagged spend cannot be checked for double spending")
        fresh = tuple(tags)
        if len(set(fresh)) != len(fresh):
            raise SpendError("the spend reuses a tag within itself")
        for tag in fresh:
            if tag in self._tags:
                raise SpendError("this note has already been spent")
        return TagSet(self._tags | frozenset(fresh))


def verify_spend_or_shape(spend: Spend) -> bool:
    """Cheap structural check used before touching a tag set."""
    try:
        return bool(spend.rings) and spend.balanced and len(spend.signatures) == len(spend.rings)
    except (TypeError, ValueError):
        return False
