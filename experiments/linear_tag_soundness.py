"""Is the naive linear tag sound? A direct test, with the answer it gives.

The natural way to add a Monero-style key image to SMILE's ring signature is a
second public matrix ``A'`` and the tag ``T = A' s``, revealed through the same
masking as ``z'``:

    prover    sends tau = A' y'      (y' is the mask, z' = y' + c' s)
    verifier  checks c' T = A' z' - tau,  or recovers T = c'^-1 (A' z' - tau)

The algebra is right -- for an honest prover both routes give ``T = A' s``. The
question this script answers is whether the *check* constrains anything. It does
not: ``tau`` is not committed to anything, so for any ``T`` the prover likes there
is a ``tau`` that satisfies the equation. Two spends of the same note can then
carry unrelated tags, which is exactly the linkability the tag was supposed to
provide.

Conclusion, recorded so that nobody ships the naive version: the tag must be
bound to the mask by a proof, not merely checked against a free response. That is
the open B3 problem, and this script is the evidence that the shortcut fails.
"""

import random

from radix_core.candidate_b.lattice import params, ring

P_ = params.SMILE
Q = P_.modulus
ROWS = P_.matrix_rows
COLS = P_.matrix_cols


def matrix(rng):
    return tuple(tuple(ring.sample_uniform(rng) for _ in range(COLS)) for _ in range(ROWS))


def mat_vec(matrix_, vector):
    return tuple(ring.dot(row, vector, P_) for row in matrix_)


rng = random.Random(42)
A = matrix(rng)
A_tag = matrix(rng)
secret = ring.sample_vector(rng, COLS, small=True)
public = mat_vec(A, secret)
tag = mat_vec(A_tag, secret)

c_prime = ring.sample_small(rng)
mask = ring.sample_vector(rng, COLS, small=True)
response = tuple(ring.add(mask[i], ring.mul(c_prime, secret[i], P_), P_) for i in range(COLS))

# honest prover
tau = mat_vec(A_tag, mask)
left = tuple(ring.mul(c_prime, poly, P_) for poly in tag)
right = tuple(ring.sub(a, b, P_) for a, b in zip(mat_vec(A_tag, response), tau))
print("honest: c' * T == A' z' - tau        :", left == right)

# attacker: pick any tag it likes, then solve for tau
forged_tag = tuple(ring.sample_uniform(rng) for _ in range(ROWS))
forged_tau = tuple(
    ring.sub(a, b, P_)
    for a, b in zip(mat_vec(A_tag, response), (ring.mul(c_prime, poly, P_) for poly in forged_tag))
)
check = tuple(
    ring.sub(a, b, P_) for a, b in zip(mat_vec(A_tag, response), forged_tau)
)
print("forged: same equation still passes  :", check == tuple(ring.mul(c_prime, p, P_) for p in forged_tag))
print("forged tag differs from the real one:", forged_tag != tag)

# and a second spend of the *same* note can carry a different forged tag again
another = tuple(ring.sample_uniform(rng) for _ in range(ROWS))
print("two spends, two different tags      :", another != forged_tag)
print()
print("=> the equation alone constrains nothing; tau is free. Linkability")
print("   requires proving tau = A' y' against a commitment to y', which is")
print("   the open B3 problem, not a missing check.")
