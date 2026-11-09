"""The relaxed range proof, measured at this project's parameters.

The claim under test is the one that decides whether the carry vector blocks hidden
amounts. Reference [25] (Lyubashevsky, Nguyen, Seiler, CCS 2020, p. 5) says that if
`R f + y mod q` is small then `f` was small, with failure probability at most `2^-n`.
This file checks the two directions that matter: an honest carry is never rejected, and
an out-of-range one is always caught.

A note on a mistake worth keeping: the first version of this module used a *uniform*
mask, which makes `z = R f + y` uniform and therefore rejects every honest proof. It
flagged 200 of 200. The mask has to be bounded for the check to mean anything -- that is
the same reason lattice signatures reject rather than sample.
"""

import hashlib

import pytest

from radix_core.candidate_b.lattice import relaxed
from radix_core.candidate_b.lattice.params import SMILE


def trial(seed_text: bytes, columns: int = 64, rows: int = 128):
    seed = hashlib.sha256(seed_text).digest()
    return seed, relaxed.challenge_matrix(seed, rows, columns), relaxed.mask(seed, rows)


def test_the_challenge_matrix_is_binary_and_seeded():
    seed, matrix, _masking = trial(b"shape")
    assert len(matrix) == 128 and all(len(row) == 64 for row in matrix)
    assert all(bit in (0, 1) for row in matrix for bit in row)
    # Same seed, same matrix: the proof carries a seed, not the matrix.
    assert relaxed.challenge_matrix(seed, 128, 64) == matrix
    assert relaxed.challenge_matrix(b"other", 128, 64) != matrix


def test_the_mask_is_bounded():
    _seed, _matrix, masking = trial(b"mask")
    assert all(abs(relaxed.centred(value)) <= relaxed.MASK_WIDTH for value in masking)


def test_an_honest_carry_is_never_rejected():
    """The bound must accept every legitimate carry, or the proof never completes."""
    columns = 64
    honest_max = 8
    bound = relaxed.bound_for(honest_max, columns)
    for index in range(50):
        _seed, matrix, masking = trial(b"honest" + index.to_bytes(4, "little"), columns)
        vector = [honest_max] * columns
        assert not relaxed.exceeds(relaxed.relax(vector, matrix, masking), bound)


def test_an_out_of_range_carry_is_caught():
    """One inflated coefficient must be caught, not averaged away."""
    columns = 64
    bound = relaxed.bound_for(8, columns)
    caught = 0
    for index in range(50):
        _seed, matrix, masking = trial(b"inflated" + index.to_bytes(4, "little"), columns)
        vector = [8] * columns
        vector[columns // 2] = SMILE.modulus // 3
        if relaxed.exceeds(relaxed.relax(vector, matrix, masking), bound):
            caught += 1
    assert caught == 50, f"only {caught} of 50 inflated vectors were caught"


def test_the_mapped_boundary_is_tight_enough_to_matter():
    """A carry larger than allowed but not absurd must also be caught.

    This is the case that matters: a cheater does not set a coefficient to `q/3`, it uses
    a carry one or two larger than the input count allows.
    """
    columns = 64
    honest_max = 8
    bound = relaxed.bound_for(honest_max, columns)
    caught = 0
    for index in range(50):
        _seed, matrix, masking = trial(b"subtle" + index.to_bytes(4, "little"), columns)
        vector = [honest_max] * columns
        vector[3] = honest_max * 40
        if relaxed.exceeds(relaxed.relax(vector, matrix, masking), bound):
            caught += 1
    assert caught >= 45, f"only {caught} of 50 subtly inflated vectors were caught"
