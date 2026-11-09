"""One-time addressing: the lattice derivation, without the KEM.

ePrint 2025/112 §5.3 derives a stealth key from a KEM shared secret `S`:

    p = k + XOF(S)          the stealth secret
    P = A·p                 the stealth public key
    T = A'·p = T_K + A'·XOF(S)

C1 and C2 resolved the two things that make it work. `XOF(S)` must be **short** -- with a
uniform shift `p` is uniform and the key does not decrypt, which C2 showed is a correctness
failure rather than a style preference. And the tag needs a **public image** `T_K = A'·k` in
the meta-address, so the sender can compute `T` without ever holding `p`.

The KEM itself is not here: `S` is caller-supplied and the shift is derived from it into a
short distribution, which is the one-line fix C2 described for the paper.

Every ring operation goes through `_ring(parameters)`. That helper exists because three
previous attempts at this module failed by confusing `Parameters` (matrices) with
`SmileParameters` (modulus and degree) -- each fix revealing the next call site. One
resolution point, used everywhere, is the fix for that class of error rather than for one
instance of it.
"""

from __future__ import annotations

import hashlib
import operator

from radix_core.candidate_b.lattice import ring
from radix_core.candidate_b.lattice.params import SMILE, SmileParameters


class StealthError(ValueError):
    """A meta-address, a secret or a derivation is malformed."""


#: Shift width. Two, matching Kyber-768/1024's CBD parameter, so that `p = k + delta`
#: stays inside 4 and the proof's `mu = 5` holds with room.
SHIFT_ETA = 2


def _ring(parameters) -> SmileParameters:
    """The ring algebra for whatever parameter object a caller holds.

    Accepts a `SmileParameters`, an `RS.Parameters` (which now carries `.smile`), or None.
    """
    if parameters is None:
        return SMILE
    if isinstance(parameters, SmileParameters):
        return parameters
    smile = getattr(parameters, "smile", None)
    return smile if isinstance(smile, SmileParameters) else SMILE


def _columns(parameters) -> int:
    """The matrix width, from whichever object actually knows it."""
    matrix = getattr(parameters, "matrix", None)
    if matrix:
        return len(matrix[0])
    return _ring(parameters).matrix_cols


def _rows(parameters) -> tuple:
    return tuple(getattr(parameters, "matrix", ()) or ())


def _tag_rows(parameters) -> tuple:
    return tuple(getattr(parameters, "tag_matrix", ()) or ())


def _centred(value: int, sm: SmileParameters) -> int:
    return value - sm.modulus if value > sm.modulus // 2 else value


def short_shift(shared_secret: bytes, parameters=None) -> tuple:
    """`XOF(S)` as a short polynomial vector, centred binomial of width `SHIFT_ETA`."""
    if not shared_secret:
        raise StealthError("a shared secret is required")
    sm = _ring(parameters)
    out = []
    for index in range(_columns(parameters)):
        digest = hashlib.shake_256(
            b"radix/stealth/shift/v1" + shared_secret + index.to_bytes(4, "little")
        ).digest(sm.ring_degree * 2)
        coefficients = []
        for position in range(sm.ring_degree):
            # Two-bit chunks: a binomial count of at most SHIFT_ETA, so the difference
            # lies in [-SHIFT_ETA, SHIFT_ETA]. The first version used four-bit chunks,
            # which gives a range of four and makes the shift wider than the parameter
            # it is named after.
            low = digest[2 * position] & 0x03
            high = digest[2 * position + 1] & 0x03
            value = bin(low).count("1") - bin(high).count("1")
            coefficients.append(value % sm.modulus)
        out.append(tuple(coefficients))
    return tuple(out)


def public_of(secret: tuple, parameters=None) -> tuple:
    sm = _ring(parameters)
    return tuple(ring.dot(row, secret, sm) for row in _rows(parameters))


def tag_of(secret: tuple, parameters=None) -> tuple:
    sm = _ring(parameters)
    return tuple(ring.dot(row, secret, sm) for row in _tag_rows(parameters))


def meta_address(spend_key: tuple, parameters=None) -> dict:
    """What a recipient publishes: the spend key and its tag image `T_K = A'·k`."""
    if not _tag_rows(parameters):
        raise StealthError("the parameters have no tag matrix")
    return {"spend": tuple(spend_key), "tag": tag_of(spend_key, parameters)}


def sender_derive(meta: dict, shared_secret: bytes, parameters=None) -> dict:
    """The sender's side: `P` and `T` from public data plus the shared secret."""
    sm = _ring(parameters)
    shift = short_shift(shared_secret, parameters)
    spend_public = public_of(meta["spend"], parameters)
    shift_public = public_of(shift, parameters)
    stealth_public = tuple(
        ring.add(a, b, sm) for a, b in zip(spend_public, shift_public)
    )
    shift_tag = tag_of(shift, parameters)
    stealth_tag = tuple(ring.add(a, b, sm) for a, b in zip(meta["tag"], shift_tag))
    return {"public": stealth_public, "tag": stealth_tag, "shift": shift}


def recipient_derive(spend_key: tuple, shared_secret: bytes, parameters=None) -> tuple:
    """The recipient's side: `p = k + delta`, which the sender cannot compute."""
    sm = _ring(parameters)
    shift = short_shift(shared_secret, parameters)
    return tuple(ring.add(a, b, sm) for a, b in zip(spend_key, shift))


def norm_inf(vector: tuple, parameters=None) -> int:
    sm = _ring(parameters)
    worst = 0
    for poly in vector:
        for value in poly:
            worst = max(worst, abs(_centred(value, sm)))
    return worst
