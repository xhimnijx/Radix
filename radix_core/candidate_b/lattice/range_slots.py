"""The range proof's α-slot terms, as functions.

Steps 3 and 4 of `docs/ALPHA-SLOTS.md`, factored out so they can be tested before the proof's
arity changes. Nothing here touches the wire format: these are the two algebraic objects the
prover will add to `psi` and `omega`, built to mirror `psi_bin`/`omega_bin` exactly with the
ring selector's `v` replaced by the bit polynomial `b`.

The construction, per C1 and C2:

    psi_range   = sum_b eta_b * a_b * (1 - 2 b)
    omega_range = sum_b eta_b * a_b^2

where `a_b = <row_b, mask>` is the masked value of the committed bit polynomial and `eta_b`
is its challenge. The verifier recomputes both from the transmitted polynomials; when `b` is
binary the `c^2` coefficient cancels, and when it is not it does not.

Why the challenges must be separate from the ring selector's (C2's argument, which is the
reason this is two per amount rather than folded in): combining them gives
`eta (v^2 - v + b^2 - b) = 0`, which a prover satisfies with `v^2 - v = -(b^2 - b) != 0` and
thereby breaks the selector. The pairing is the mechanism.
"""

from __future__ import annotations

from radix_core.candidate_b.lattice import params as P
from radix_core.candidate_b.lattice import ring
from radix_core.candidate_b.lattice.params import SMILE, SmileParameters

Poly = tuple


class RangeSlotError(ValueError):
    """The term data does not have the shape the construction requires."""


def psi_terms(masked_values: tuple, bit_polys: tuple, challenges: tuple,
              parameters: SmileParameters = SMILE) -> Poly:
    """`sum eta_b * a_b * (1 - 2 b)` over the committed bit polynomials.

    `masked_values` are `a_b = <row_b, mask>`, one per bit polynomial; `challenges` are the
    freshly drawn `eta_b`. The sum is over the same number of terms, checked rather than
    assumed because a silent length mismatch would drop a constraint.
    """
    if not (len(masked_values) == len(bit_polys) == len(challenges)):
        raise RangeSlotError(
            f"shape mismatch: {len(masked_values)} values, {len(bit_polys)} polynomials, "
            f"{len(challenges)} challenges"
        )
    total = ring.zero(parameters)
    for a_value, bit_poly, challenge in zip(masked_values, bit_polys, challenges):
        factor = ring.sub(
            ring.constant(1, parameters), ring.scalar(2, bit_poly, parameters), parameters
        )
        total = ring.add(
            total, ring.mul(challenge, ring.mul(a_value, factor, parameters), parameters),
            parameters,
        )
    return total


def omega_terms(masked_values: tuple, challenges: tuple,
                parameters: SmileParameters = SMILE) -> Poly:
    """`sum eta_b * a_b^2` over the same terms."""
    if len(masked_values) != len(challenges):
        raise RangeSlotError(
            f"shape mismatch: {len(masked_values)} values, {len(challenges)} challenges"
        )
    total = ring.zero(parameters)
    for a_value, challenge in zip(masked_values, challenges):
        total = ring.add(
            total, ring.mul(challenge, ring.mul(a_value, a_value, parameters), parameters),
            parameters,
        )
    return total


# NOTE: the cancellation condition is deliberately NOT encoded here.
#
# The verifier's check is `omega - c * psi == 0`, not `psi + c * omega`, because the
# commitment's square expands to `c^2 v(v-1) + c a(2v-1) + a^2`, and with `b` binary the
# c^2 term dies leaving `a^2 - c * a(1-2v)`. Writing that out as a helper here would be
# writing the verifier's equation twice, in two places, where a disagreement between them
# is exactly the class of bug this project has already paid for four times. The terms are
# constructed here; the equation is checked in the verifier, once.


def challenge_from(seed: bytes, count: int, parameters: SmileParameters = SMILE) -> tuple:
    """`count` independent range challenges, drawn from the transcript.

    A separate entry point so both implementations draw them the same way and in the same
    order relative to `h` and `c`: after `h`, before `c`.
    """
    from radix_core.candidate_b.lattice import transcript

    if count < 1:
        raise RangeSlotError("at least one challenge is required")
    tx = transcript.Transcript(b"radix/range/v1")
    tx.absorb(b"seed", seed)
    return tuple(
        _poly_from_challenge(tx.challenge(b"eta", parameters.ring_degree), parameters)
        for _ in range(count)
    )


def _poly_from_challenge(raw: bytes, parameters: SmileParameters) -> Poly:
    return tuple(byte % 3 - 1 for byte in raw)
