"""Reproduce the review's tag forgery.

Cryptographer 1's claim: `verify_tag` never binds the individual `u_j`, only the
derived row `u_der = <A', u> - message`. So a forger can pick any tag, any short
`r_m`, set `t = B_0^m r_m`, and choose `u` so that `<A', u> = <b', r_m> + message`.
Then `u_der = <b', r_m>`, which is exactly what an honest opening proof to zero
under `(B_0^m; b')` expects -- and the forger knows `r_m`, so it can produce that
proof without ever knowing a secret.

If this prints `forged: True`, the tag is unsound and must be retired.
"""

import random

from radix_core.candidate_b.lattice import ntt, params, ring, tag as T

P_ = params.SMILE
CONTEXT = b"tag-context"


def inverse(poly):
    """Inverse in R_q, via the NTT: the modulus splits completely, so pointwise."""
    forward = ntt.forward(poly, P_)
    if any(coefficient == 0 for coefficient in forward):
        return None
    return ntt.inverse(tuple(pow(c, -1, P_.modulus) for c in forward), P_)


def unit_challenge(rng):
    while True:
        candidate = ring.sample_small(rng, P_)
        if T.invertible(candidate, P_):
            return candidate


def main() -> int:
    rng = random.Random(1234)
    keys = T.setup(rng, P_)

    # An honest transcript, only to supply public c' and z' for the forgery.
    secret = ring.sample_vector(rng, P_.matrix_cols, small=True)
    c_prime = unit_challenge(rng)
    mask = ring.sample_vector(rng, P_.matrix_cols, small=True)
    response = tuple(
        ring.add(mask[i], ring.mul(c_prime, secret[i], P_), P_)
        for i in range(P_.matrix_cols)
    )
    honest = T.prove_tag(keys, secret, mask, c_prime, response, CONTEXT, rng, P_)
    print("honest verifies:", T.verify_tag(keys, honest, c_prime, response, CONTEXT, P_))

    # ---- the forgery: no secret involved from here on
    forged_tag = ring.sample_small(rng, P_)
    randomness = ring.sample_vector(rng, P_.matrix_cols, small=True)
    t = tuple(ring.mat_vec(keys.mask_rows0, randomness, P_))
    message = ring.sub(
        ring.dot(keys.row, response, P_), ring.mul(c_prime, forged_tag, P_), P_
    )
    derived = keys.derived_row(P_)
    target = ring.add(ring.dot(derived, randomness, P_), message, P_)

    # u = (target / A'_1, 0, ..., 0); the verifier does not bound u
    first = inverse(keys.row[0])
    if first is None:
        print("A'_1 not invertible; retry with another key")
        return 1
    u = (ring.mul(target, first, P_),) + tuple(ring.zero(P_) for _ in range(P_.matrix_cols - 1))

    u_der = ring.sub(ring.dot(keys.row, u, P_), message, P_)
    expected = ring.dot(derived, randomness, P_)
    print("u_der == <b', r_m>:", u_der == expected)

    from radix_core.candidate_b.lattice import bdlop, sigma

    proof = sigma.prove(
        keys.derived_key(P_),
        bdlop.Commitment(t=t, u=u_der),
        ring.zero(P_),
        randomness,
        CONTEXT,
        rng,
        P_,
    )
    forged = T.TagProof(t=t, u=u, tag=forged_tag, proof=proof)
    ok = T.verify_tag(keys, forged, c_prime, response, CONTEXT, P_)
    print("forged tagged proof verifies:", ok)
    print("forged tag differs from the real one:", forged_tag != honest.tag)
    print("forger used the secret:", False)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
