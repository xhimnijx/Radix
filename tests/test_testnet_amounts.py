"""Balance without revealing amounts.

The property under test is the one a ledger needs: a transaction whose inputs cover its
outputs and fee can be checked by someone who learns none of the numbers, and one that
does not cover them is rejected.

These tests deliberately do not test a range proof, because there is not one yet. The
honest consequence -- a commitment to `q - 5` is indistinguishable from a commitment to
`-5`, so a sender can mint money -- is asserted as a *known limitation* rather than left
for a reader to discover.
"""

import random

import pytest

from radix_core.candidate_b.lattice import ring
from radix_core.candidate_b.lattice.params import SMILE
from radix_testnet import amounts


@pytest.fixture(scope="module")
def parameters():
    return amounts.Parameters.derive(SMILE)


def blinded(rng):
    return tuple(ring.sample_uniform(rng) for _ in range(SMILE.challenge_dim))


def zero_randomness():
    return tuple(ring.zero(SMILE) for _ in range(SMILE.challenge_dim))


def add_randomness(left, right):
    return tuple(ring.add(a, b, SMILE) for a, b in zip(left, right))


def test_a_commitment_opens_to_its_amount(parameters):
    rng = random.Random(1)
    randomness = blinded(rng)
    commitment = amounts.commit(1500, randomness, parameters)
    assert amounts.open_commitment(commitment, 1500, randomness, parameters) is True
    assert amounts.open_commitment(commitment, 1501, randomness, parameters) is False


def test_commitments_are_hiding(parameters):
    """Two commitments to the same amount must not be equal, or the amount leaks."""
    first = amounts.commit(1500, blinded(random.Random(2)), parameters)
    second = amounts.commit(1500, blinded(random.Random(3)), parameters)
    assert first != second
    assert len(first) == SMILE.challenge_dim


def test_the_commitment_is_additively_homomorphic(parameters):
    rng = random.Random(4)
    left_random = blinded(rng)
    right_random = blinded(rng)
    left = amounts.commit(600, left_random, parameters)
    right = amounts.commit(500, right_random, parameters)

    combined = amounts.combine([left, right], SMILE)
    total_random = add_randomness(left_random, right_random)
    assert amounts.open_commitment(combined, 1100, total_random, parameters)


def test_an_honest_balance_passes(parameters):
    """2 inputs of 600 and 500 covering one output of 1000 and a fee of 100."""
    rng = random.Random(5)
    input_random = [blinded(rng), blinded(rng)]
    inputs = [
        amounts.commit(600, input_random[0], parameters),
        amounts.commit(500, input_random[1], parameters),
    ]
    # The sender picks output randomness that sums to the input randomness, which is
    # what makes the difference vanish.
    output_random = add_randomness(input_random[0], input_random[1])
    outputs = [amounts.commit(1000, output_random, parameters)]

    assert amounts.balanced(inputs, outputs, 100, parameters) is True


def test_an_inflated_output_is_rejected(parameters):
    """The spend would mint 50 units, and the commitment difference is not zero."""
    rng = random.Random(6)
    input_random = [blinded(rng), blinded(rng)]
    inputs = [
        amounts.commit(600, input_random[0], parameters),
        amounts.commit(500, input_random[1], parameters),
    ]
    output_random = add_randomness(input_random[0], input_random[1])
    outputs = [amounts.commit(1050, output_random, parameters)]

    assert amounts.balanced(inputs, outputs, 100, parameters) is False


def test_a_wrong_fee_is_rejected(parameters):
    rng = random.Random(7)
    randomness = blinded(rng)
    inputs = [amounts.commit(1000, randomness, parameters)]
    outputs = [amounts.commit(900, randomness, parameters)]

    assert amounts.balanced(inputs, outputs, 100, parameters) is True
    assert amounts.balanced(inputs, outputs, 99, parameters) is False
    assert amounts.balanced(inputs, outputs, 101, parameters) is False


def test_mismatched_randomness_is_rejected(parameters):
    """Correct amounts with the wrong blinding would hide an unbalanced transaction."""
    rng = random.Random(8)
    input_random = blinded(rng)
    inputs = [amounts.commit(1000, input_random, parameters)]
    outputs = [amounts.commit(900, blinded(rng), parameters)]

    assert amounts.balanced(inputs, outputs, 100, parameters) is False


def test_an_amount_at_or_above_q_is_refused(parameters):
    with pytest.raises(amounts.AmountError, match="does not fit a single coefficient"):
        amounts.commit(SMILE.modulus, zero_randomness(), parameters)


def test_the_known_limitation_a_negative_amount_is_indistinguishable(parameters):
    """No range proof means a negative output can mint money. This asserts the gap.

    A commitment to `q - 100` is a perfectly valid commitment, and it balances against
    an input of 1000 with a fee of ... anything the sender likes. The defence is the
    digit-membership proof described in docs/CONFIDENTIAL-TRANSACTIONS.md, not this
    module. The test exists so the gap cannot be forgotten or silently closed by a
    comment.
    """
    negative = SMILE.modulus - 100
    commitment = amounts.commit(negative, zero_randomness(), parameters)
    assert amounts.open_commitment(commitment, negative, zero_randomness(), parameters)

    # And it is "in range" as far as the current hook can tell.
    assert amounts.value_in_range(negative) is True
