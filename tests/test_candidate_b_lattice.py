"""Tests for the SMILE parameter manifest, ring arithmetic, and BDLOP commitment."""

import random

import pytest

from radix_core.candidate_b.lattice import bdlop, ntt, params, ring


def _rng(seed: int = 7) -> random.Random:
    return random.Random(seed)


def _is_probable_prime(n: int, rounds: int = 24) -> bool:
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small
    odd, exponent = n - 1, 0
    while odd % 2 == 0:
        odd //= 2
        exponent += 1
    rng = random.Random(11)
    for _ in range(rounds):
        base = rng.randrange(2, n - 1)
        value = pow(base, odd, n)
        if value in (1, n - 1):
            continue
        for _ in range(exponent - 1):
            value = pow(value, 2, n)
            if value == n - 1:
                break
        else:
            return False
    return True


# --------------------------------------------------------------------------
# B1: the transcribed parameter manifest
# --------------------------------------------------------------------------


def test_paper_values_are_pinned():
    assert params.SMILE.ring_degree == 128          # Fig. 11: (q,d,l) = (~2^32,128,32)
    assert params.SMILE.subring_dimension == 32
    assert params.SMILE.matrix_rows == 4            # k
    assert params.SMILE.matrix_cols == 13           # ell
    assert params.SMILE.challenge_dim == 10         # kappa
    assert params.SMILE.masking_dim == 10           # lambda
    assert params.SMILE.secret_bound == 5           # mu


def test_modulus_is_irreducible_quartic_and_flagged_as_not_from_the_paper():
    """The adopted criterion: `ord_256(q) = 4`, so X^128+1 has 32 irreducible quartics.

    That is what makes the quartic slots fields -- a nonzero residue is a unit, and
    `v(v-1) = 0` forces a 32-entry binary vector rather than a 128-coordinate
    idempotent. See REVIEW-FINDINGS.md. The cost is that no 256th root of unity
    exists, so `ntt_capacity` is 64 rather than 256.
    """
    q = params.PROTOTYPE_MODULUS
    assert q.bit_length() == 32
    assert q % 64 == 1 and q % 128 != 1
    assert _is_probable_prime(q)
    assert params.SMILE.ntt_capacity == 64            # 64 | q-1, 128 does not
    assert ntt.try_transform(q, params.RING_DEGREE) is None
    assert params.MODULUS_FROM_PAPER is False         # honest flag


def test_the_split_reference_modulus_still_admits_the_ntt():
    """Kept because the quartic-CRT path is tested against the NTT path."""
    split = params.SMILE_SPLIT
    assert split.modulus % 256 == 1
    assert split.ntt_capacity >= 256
    assert ntt.try_transform(split.modulus, split.ring_degree) is not None


def test_paper_size_table_is_transcribed():
    assert params.PAPER_RING_SIGNATURE_KB[1 << 5] == 15.96
    assert params.PAPER_RING_SIGNATURE_KB[1 << 15] == 18.73
    assert params.PAPER_TRANSACTION_KB[(2, 2)][1 << 15] == 30
    assert params.PAPER_TRANSACTION_KB[(1, 2)][1 << 5] == 22


def test_size_estimate_is_monotone_and_matches_the_table_at_pinned_points():
    assert params.estimate_ring_signature_kb(1 << 5) == pytest.approx(15.96)
    assert params.estimate_ring_signature_kb(1 << 15) == pytest.approx(18.73)
    sizes = [params.estimate_ring_signature_kb(1 << exponent) for exponent in range(5, 26)]
    assert sizes == sorted(sizes)


def test_ring_signature_size_formula_matches_the_paper_order_of_magnitude():
    # (kappa + k + 2m + 2) full R_q elements, 4 bytes per coefficient.
    estimated = params.SMILE.ring_signature_size_bytes(1 << 5, m=1)
    assert estimated == (10 + 4 + 2 + 2) * 128 * 4
    assert estimated / 1024 < params.PAPER_RING_SIGNATURE_KB[1 << 5] * 1.2


# --------------------------------------------------------------------------
# Ring arithmetic
# --------------------------------------------------------------------------


def test_ring_identities():
    rng = _rng()
    a = ring.sample_small(rng)
    b = ring.sample_small(rng)
    c = ring.sample_small(rng)

    assert ring.add(a, ring.zero()) == a
    assert ring.mul(a, ring.constant(1)) == a
    assert ring.mul(a, ring.constant(0)) == ring.zero()
    # Distributivity and commutativity on small representatives.
    assert ring.mul(a, ring.add(b, c)) == ring.add(ring.mul(a, b), ring.mul(a, c))
    assert ring.mul(a, b) == ring.mul(b, a)


def test_negacyclic_wraparound_is_x_to_the_d_equals_minus_one():
    degree = params.SMILE.ring_degree
    x = (0, 1) + (0,) * (degree - 2)            # X
    x_pow_d_minus_1 = (0,) * (degree - 1) + (1,)  # X^(d-1)
    product = ring.mul(x, x_pow_d_minus_1)       # X^d == -1
    assert product == ring.neg(ring.constant(1))


def test_encoding_roundtrip_and_canonicality():
    rng = _rng()
    for _ in range(3):
        poly = ring.sample_uniform(rng)
        assert ring.decode(ring.encode(poly)) == poly
    with pytest.raises(ValueError):
        ring.decode(ring.encode(ring.zero())[:-1])
    bad = params.SMILE.modulus.to_bytes(4, "little") + ring.encode(ring.zero())[4:]
    with pytest.raises(ValueError):
        ring.decode(bad)


def test_norm_measurement_uses_centered_representatives():
    assert ring.centered(0) == 0
    assert ring.centered(1) == 1
    assert ring.centered(params.SMILE.modulus - 1) == -1
    assert ring.centered(params.SMILE.modulus // 2 + 1) < 0
    small = ring.sample_small(_rng())
    assert ring.norm_inf(small) <= params.SMILE.secret_bound


def test_matrix_vector_product_matches_manual_dot_products():
    rng = _rng()
    key = bdlop.setup(rng)
    vector = ring.sample_vector(rng, params.SMILE.matrix_cols, small=True)
    result = ring.mat_vec(key.matrix, vector)
    manual = tuple(ring.dot(row, vector) for row in key.matrix)
    assert result == manual


# --------------------------------------------------------------------------
# BDLOP commitment
# --------------------------------------------------------------------------


def test_commit_and_open():
    rng = _rng()
    key = bdlop.setup(rng)
    message = ring.sample_small(rng)
    randomness = bdlop.opening(rng)

    commitment = bdlop.commit(key, message, randomness)
    assert bdlop.verify(key, commitment, message, randomness)
    assert len(commitment.t) == params.SMILE.matrix_rows
    assert len(commitment.encode()) == (params.SMILE.matrix_rows + 1) * 512


def test_wrong_message_or_randomness_does_not_verify():
    rng = _rng()
    key = bdlop.setup(rng)
    message = ring.sample_small(rng)
    randomness = bdlop.opening(rng)
    commitment = bdlop.commit(key, message, randomness)

    other_message = ring.add(message, ring.constant(1))
    assert not bdlop.verify(key, commitment, other_message, randomness)
    other_randomness = list(randomness)
    other_randomness[0] = ring.add(other_randomness[0], ring.constant(1))
    assert not bdlop.verify(key, commitment, message, tuple(other_randomness))


def test_commitment_is_additively_homomorphic():
    rng = _rng()
    key = bdlop.setup(rng)
    first_message, second_message = ring.sample_small(rng), ring.sample_small(rng)
    first_opening, second_opening = bdlop.opening(rng), bdlop.opening(rng)

    summed = bdlop.add_commitments(
        bdlop.commit(key, first_message, first_opening),
        bdlop.commit(key, second_message, second_opening),
    )
    combined_message = ring.add(first_message, second_message)
    combined_opening = bdlop.add_openings(first_opening, second_opening)
    assert bdlop.verify(key, summed, combined_message, combined_opening)


def test_commitment_key_shape_is_enforced():
    rng = _rng()
    good = bdlop.setup(rng)
    with pytest.raises(ValueError):
        bdlop.CommitmentKey(matrix=good.matrix[:3], vector=good.vector)
    with pytest.raises(ValueError):
        bdlop.CommitmentKey(matrix=good.matrix, vector=good.vector[:3])
    with pytest.raises(ValueError):
        bdlop.commit(good, ring.zero(), good.vector[:2])

def test_calibrated_size_reproduces_every_published_point():
    for m in range(1, 6):
        size = params.ring_signature_size_bytes_calibrated(32**m)
        assert size / 1024 == pytest.approx(params.PAPER_RING_SIGNATURE_KB[32**m], abs=0.1)


def test_structural_formula_is_a_lower_bound_not_an_estimate():
    """The (kappa + k + 2m + 2) count is 40-60% BELOW the paper's sizes.

    Recording the ratio stops anyone reading the structural count as a size
    prediction; `ring_signature_size_bytes_calibrated` is the planning model.
    """
    for m in range(1, 6):
        structural = params.SMILE.ring_signature_size_bytes(32**m, m=m) / 1024
        paper = params.PAPER_RING_SIGNATURE_KB[32**m]
        assert 0.5 <= structural / paper <= 0.7


def test_tensor_depth_requires_a_power_of_the_subring_dimension():
    assert params.tensor_depth(32) == 1
    assert params.tensor_depth(32**3) == 3
    for bad in (0, -1, 33, 1000):
        with pytest.raises(ValueError):
            params.tensor_depth(bad)

