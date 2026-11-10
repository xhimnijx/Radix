"""Digit membership inside the proof, not beside it.

This is the difference between "a spend carries a range witness that a node checks in the
clear" and "a spend proves its amounts are in range". Before this, the witness was checked
by the verifier reading it; now the constraint is a term in the proof's equation and the
bit polynomials are committed messages that are never sent.

What is tested, and why each matters:

- an honest range proof verifies, and rejects a different message;
- a bit polynomial whose slot value is not 0 or 1 is **refused by the proof**, which is the
  property the whole construction exists for;
- the packing property the proof consumes is `b*b = b` in the ring, which the earlier
  coefficient-block test did not check.

What is NOT tested here, because it is not built: the relaxed carry bound (`z = R f + y`),
and the wiring into the transaction envelope.
"""

import random

import pytest

from radix_core.candidate_b.lattice import digits, ring, setmembership as S, subring
from radix_core.candidate_b.lattice.params import SMILE

DEPTH = 2
ROWS = 4
KAPPA = SMILE.challenge_dim


def build(range_count: int, seed: int = 9):
    rng = random.Random(seed)
    keys = S.setup(rng, DEPTH, None, ROWS, range_count=range_count)
    matrix = tuple(
        tuple(ring.sample_uniform(rng) for _ in range(SMILE.matrix_cols)) for _ in range(ROWS)
    )
    secret = ring.sample_vector(rng, SMILE.matrix_cols, small=True, parameters=SMILE)
    public = tuple(ring.dot(row, secret, SMILE) for row in matrix)
    ring_keys = [
        tuple(ring.sample_uniform(rng) for _ in range(ROWS)) for _ in range(1024)
    ]
    ring_keys[5] = public
    statement = S.Statement(matrix=matrix, keys=tuple(ring_keys), depth=DEPTH)
    return keys, statement, secret


def prove(keys, statement, secret, bits, message=b"range", seed=3):
    return S.prove(
        keys, statement, secret, 5, message, random.Random(seed), None, None, bits
    )


def test_a_range_proof_verifies():
    keys, statement, secret = build(2)
    packed = digits.pack_bits(digits.bits_of(12345, 32), SMILE)
    proof = prove(keys, statement, secret, packed)

    assert S.verify(keys, statement, proof, b"range") is True


def test_a_range_proof_binds_the_message():
    keys, statement, secret = build(2)
    packed = digits.pack_bits(digits.bits_of(12345, 32), SMILE)
    proof = prove(keys, statement, secret, packed)

    assert S.verify(keys, statement, proof, b"a different message") is False


def test_a_non_binary_bit_is_refused_by_the_proof():
    """The soundness property, and the reason the packed polynomial must be CRT-lifted.

    A slot holding 2 satisfies `b(b-1) = 0` nowhere, so the equation fails and the proof is
    rejected. If this passed, "amounts in range" would mean nothing.
    """
    keys, statement, secret = build(2)
    good = digits.pack_bits(digits.bits_of(12345, 32), SMILE)
    slots = [1] * 32
    slots[0] = 2
    bad = (subring.from_constants(tuple(slots), SMILE), good[1])

    proof = prove(keys, statement, secret, bad)

    assert S.verify(keys, statement, proof, b"range") is False


def test_the_alpha_budget_matches_the_commitment_growth():
    """Two bit polynomials per amount, and one commitment component each."""
    plain, _s, _k = build(0)
    ranged, _s2, _k2 = build(2)

    assert len(ranged.range_rows) - len(plain.range_rows) == 2
    assert len(ranged.range_rows[0]) == len(plain.rows[0]), "a range row has the same width"

    keys, statement, secret = build(2)
    packed = digits.pack_bits(digits.bits_of(12345, 32), SMILE)
    proof = prove(keys, statement, secret, packed)
    plain_keys, plain_statement, plain_secret = build(0)
    baseline = prove(plain_keys, plain_statement, plain_secret, ())

    # Each range message costs exactly one commitment polynomial.
    assert len(proof.commitment) == len(baseline.commitment) + 2
    assert proof.size_bytes == baseline.size_bytes + 2 * 4 * SMILE.ring_degree


def test_the_bit_polynomials_are_never_sent():
    """They are committed, not transmitted: the verifier checks `f^2 + c f` without them."""
    keys, statement, secret = build(2)
    packed = digits.pack_bits(digits.bits_of(12345, 32), SMILE)
    proof = prove(keys, statement, secret, packed)

    encoded = proof.encode()
    for poly in packed:
        assert ring.encode(poly, SMILE) not in encoded, (
            "a bit polynomial appears verbatim in the proof"
        )


def test_a_wrong_number_of_bit_polynomials_is_refused():
    keys, statement, secret = build(2)
    one = digits.pack_bits(digits.bits_of(12345, 32), SMILE)[:1]
    with pytest.raises(S.SetMembershipError, match="expected 2 bit polynomials"):
        prove(keys, statement, secret, one)


def test_a_proof_from_a_plain_key_set_does_not_verify_against_a_ranged_one():
    """The keys are part of the statement: a 21-component commitment is not a 19 one."""
    plain_keys, statement, secret = build(0)
    ranged_keys, _, _ = build(2)
    packed = digits.pack_bits(digits.bits_of(12345, 32), SMILE)

    proof = prove(plain_keys, statement, secret, ())
    assert S.verify(ranged_keys, statement, proof, b"range") is False
