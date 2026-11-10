"""The balance witness: computing the carry and refusing an unbalanced spend.

The carry for a spend is the quotient of the digit-polynomial difference by `(X - 4)`, and
this module computes it and refuses a spend whose amounts do not add up.

What is NOT here: the proof of that relation. `balance.relations` was removed because the
binaryness check and the carrying identity live in different subspaces -- slot-constant
messages for the first, coefficient-domain multiplication by `(X - 4)` for the second -- and a
relation written across the two would verify while meaning nothing. See the note at the end of
`balance.py` for the exact question and why it needs a reviewer's decision rather than a guess.
"""

import pytest

from radix_core.candidate_b.lattice import balance


def _unused_build_keys(range_count: int, carry_count: int, seed: int = 91):
    rng = random.Random(seed)
    keys = S.setup(
        rng, DEPTH, None, ROWS, range_count=range_count, carry_count=carry_count
    )
    matrix = tuple(
        tuple(ring.sample_uniform(rng) for _ in range(SMILE.matrix_cols)) for _ in range(ROWS)
    )
    secret = ring.sample_vector(rng, SMILE.matrix_cols, small=True, parameters=SMILE)
    public = tuple(ring.dot(row, secret, SMILE) for row in matrix)
    ring_keys = [
        tuple(ring.sample_uniform(rng) for _ in range(ROWS)) for _ in range(1024)
    ]
    ring_keys[4] = public
    statement = S.Statement(matrix=matrix, keys=tuple(ring_keys), depth=DEPTH)
    return keys, statement, secret


def test_a_spend_that_does_not_balance_is_refused_before_proving():
    """The witness builder refuses rather than producing a proof of a false statement."""
    with pytest.raises(balance.BalanceError, match="does not divide"):
        balance.build([500], [500], 100)


def test_a_negative_amount_is_refused():
    with pytest.raises(balance.BalanceError, match="not be negative"):
        balance.build([-1], [], 0)


def test_a_spend_with_no_inputs_is_refused():
    with pytest.raises(balance.BalanceError, match="at least one input"):
        balance.build([], [100], 0)


def test_the_bit_width_helper_is_honest_about_small_bounds():
    assert balance.bit_width(0) == 1
    assert balance.bit_width(1) == 1
    assert balance.bit_width(2) == 2
    assert balance.bit_width(3) == 2
    assert balance.bit_width(4) == 3
