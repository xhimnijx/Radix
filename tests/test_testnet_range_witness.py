"""A spend can carry a range witness, and the node checks it before anything else.

This is the data-model step before the proof change. The witness is not proved -- it is
checked in the clear, so it proves nothing to a verifier that does not trust the prover.
What it does establish is that the encoding, the bit packing and the consistency checks run
on real traffic, and that a malformed witness is rejected for the right reason rather than
deep inside proof verification.

The limitation is named in `docs/PAPER.md` §8: the range proof is specified and its
primitives are tested, but it is not inside the proof.
"""

import pytest

from radix_testnet import codec
from radix_core.candidate_b.lattice import digits


def test_a_witness_for_an_amount_round_trips():
    witness = codec.range_witness([1000, 250])
    assert len(witness["digits"]) == 2
    assert len(witness["digits"][0]) == 32
    assert len(witness["bits"][0]) == 64
    # Every digit is in range and the bits reconstruct the digits.
    for digit_row, bit_row in zip(witness["digits"], witness["bits"]):
        assert all(0 <= digit <= 3 for digit in digit_row)
        for index in range(0, len(bit_row), 2):
            assert (bit_row[index + 1] << 1) | bit_row[index] == digit_row[index // 2]


def test_a_consistent_witness_is_accepted():
    payload = {"range": codec.range_witness([42])}
    codec.check_range_witness(payload)  # must not raise


def test_an_absent_witness_is_accepted():
    """A spend without a range witness is the current, visible-amount shape."""
    codec.check_range_witness({})


def test_a_witness_whose_bits_disagree_with_its_digits_is_refused():
    witness = codec.range_witness([42])
    witness["digits"][0][0] = 3
    witness["bits"][0][0] = 0  # now says the low digit is 0 while the digit says 3
    witness["bits"][0][1] = 0

    with pytest.raises(codec.CodecError, match="does not hold"):
        codec.check_range_witness({"range": witness})


def test_a_non_binary_bit_is_refused():
    witness = codec.range_witness([42])
    witness["bits"][0][0] = 2
    with pytest.raises(codec.CodecError, match="does not hold"):
        codec.check_range_witness({"range": witness})


def test_a_digit_out_of_range_is_refused():
    witness = codec.range_witness([42])
    witness["digits"][0][0] = 5
    witness["bits"][0][0] = 1  # 5 is 1 mod 2, so the bit still "agrees"
    witness["bits"][0][1] = 0
    with pytest.raises(codec.CodecError, match="does not hold"):
        codec.check_range_witness({"range": witness})


def test_a_malformed_witness_is_refused_with_a_clear_error():
    with pytest.raises(codec.CodecError, match="malformed range witness"):
        codec.check_range_witness({"range": {"digits": []}})
