"""The noise-aware statement: `A·p + e = P`, not `A·p = P`.

C1's finding, seventh pass. The stealth-address public key from ePrint 2025/112 is

    P = A·p + e1

an **MLWE sample**, not an exact linear image. SMILE proves `A·s = pk` exactly, so a
stealth key is not a SMILE key at all — the noise is the blocker, not the norm. C1 called
this the part the earlier discussion had missed, and he was right: I had spent a round
arguing about whether `p` was short enough when the actual obstruction was `e1`.

The fix is structural and fits the same-witness extension this codebase already uses:

    matrix   A_noise = [A | I_k]        k extra columns, the identity
    witness          (p, e1)            one short vector of length ell + k
    relation         A·p + e1 = P

and the tag rows are `[A' | 0]`, because the tag is `A'·p` and the noise does not enter it.
That keeps the tag a function of the secret alone, which is what the linkability argument
needs.

`e1` is short — it is the KEM's own error — so the norm side is manageable; what this
costs is `k` extra witness components and their commitment and response elements, plus a
new extraction argument. This module implements the *linear algebra* of that statement so
the shape is testable before the proof is touched.
"""

from __future__ import annotations

from radix_core.candidate_b.lattice import ring
from radix_core.candidate_b.lattice.params import SMILE, SmileParameters


class NoisyStatementError(ValueError):
    """A witness does not satisfy the noisy relation, or has the wrong shape."""


def augment(matrix: tuple, rows: int, parameters: SmileParameters = SMILE) -> tuple:
    """`[A | I_k]`, with identity blocks appended to the first `rows` rows.

    The witness gains `rows` components, one per noise coefficient, and the identity
    makes column `ell + i` select the `i`-th noise component exactly.
    """
    if len(matrix) != rows:
        raise NoisyStatementError(f"expected {rows} rows, got {len(matrix)}")
    augmented = []
    for index, row in enumerate(matrix):
        identity = tuple(
            ring.constant(1 if index == other else 0, parameters) for other in range(rows)
        )
        augmented.append(tuple(row) + identity)
    return tuple(augmented)


def tag_matrix(tag_rows: tuple, ell: int, parameters: SmileParameters = SMILE) -> tuple:
    """`[A' | 0]`: the tag is `A'·p`, and the noise must not enter it.

    Padding with zero columns keeps the tag matrix the same width as the augmented
    matrix, so one witness can serve both relations while the tag stays a function of the
    secret alone.
    """
    zeros = tuple(ring.zero(parameters) for _ in range(ell))
    return tuple(tuple(row) + zeros for row in tag_rows)


def noisy_public_key(matrix: tuple, secret: tuple, noise: tuple,
                     parameters: SmileParameters = SMILE) -> tuple:
    """`A·p + e1`."""
    if len(secret) != len(matrix[0]):
        raise NoisyStatementError("the secret does not match the matrix width")
    if len(noise) != len(matrix):
        raise NoisyStatementError("the noise must have one component per row")
    return tuple(
        ring.add(ring.dot(row, secret, parameters), error, parameters)
        for row, error in zip(matrix, noise)
    )


def exact_public_key(matrix: tuple, secret: tuple, parameters: SmileParameters = SMILE) -> tuple:
    """`A·p`, the relation SMILE actually proves."""
    return tuple(ring.dot(row, secret, parameters) for row in matrix)


def holds(matrix: tuple, secret: tuple, noise: tuple, public: tuple,
          parameters: SmileParameters = SMILE) -> bool:
    """Does `A·p + e1 = P` for the *augmented* matrix?"""
    try:
        return noisy_public_key(matrix, secret, noise, parameters) == tuple(public)
    except NoisyStatementError:
        return False


def norm_inf(vector: tuple, parameters: SmileParameters = SMILE) -> int:
    """The largest centred coefficient across a vector of polynomials."""
    worst = 0
    for poly in vector:
        for value in poly:
            centred = value - parameters.modulus if value > parameters.modulus // 2 else value
            worst = max(worst, abs(centred))
    return worst


def is_short(vector: tuple, bound: int, parameters: SmileParameters = SMILE) -> bool:
    return norm_inf(vector, parameters) <= bound
