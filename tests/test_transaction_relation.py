from dataclasses import replace

import pytest

from radix_core.crypto import note_commitment, note_owner, nullifier, output_leaf, spend_public
from radix_core.merkle import DEPTH, OutputTree
from radix_core.transaction_relation import (
    NoteMembershipWitnessV1,
    check_note_membership_and_nullifier_witness_v1,
    check_statement_value_conservation_v1,
    check_value_conservation_v1,
)
from radix_core.wire import OutputRecord, TransactionStatementV1

CHAIN_ID = b"c" * 32


@pytest.mark.parametrize(
    ("input_value", "output_value", "fee", "expected"),
    [
        (0x0001_0000_0000_0020, 0x0001_0000_0000_0000, 0x20, True),
        (1, 1, 0, True),
        (2**64 - 1, 2**64 - 2, 1, True),
        (0, 0, 0, False),
        (1, 0, 1, False),
        (12, 10, 1, False),
        (2**64 - 1, 2**64 - 1, 1, False),
        (1, 1, True, False),
        (-1, 1, 0, False),
        (2**64, 1, 0, False),
    ],
)
def test_value_conservation_oracle_matches_nonzero_u64_no_overflow_rule(
    input_value, output_value, fee, expected
):
    assert check_value_conservation_v1(input_value, output_value, fee) is expected


def make_output(commitment: bytes, marker: int) -> OutputRecord:
    kem_ciphertext = bytes([marker]) * 1088
    nonce = bytes([marker + 1]) * 12
    ciphertext = bytes([marker + 2]) * 156
    leaf = output_leaf(commitment, kem_ciphertext, nonce, ciphertext)
    return OutputRecord(commitment, kem_ciphertext, nonce, ciphertext, leaf)


def test_statement_balance_oracle_uses_canonical_fee_and_strict_arity():
    output = make_output(b"o" * 64, 7)
    statement = TransactionStatementV1(
        chain_id=CHAIN_ID,
        anchor_height=3,
        root_out=b"r" * 64,
        fee=2,
        nullifiers=(b"n" * 64,),
        outputs=(output,),
    )
    encoded = statement.serialize()

    assert check_statement_value_conservation_v1(encoded, 100, 98)
    assert not check_statement_value_conservation_v1(encoded, 100, 97)
    assert not check_statement_value_conservation_v1(encoded + b"x", 100, 98)
    assert not check_statement_value_conservation_v1(bytearray(encoded), 100, 98)
    assert not check_statement_value_conservation_v1(
        replace(statement, nullifiers=(b"n" * 64, b"m" * 64)).serialize(), 100, 98
    )
    assert not check_statement_value_conservation_v1(
        replace(statement, outputs=(output, make_output(b"p" * 64, 8))).serialize(), 100, 98
    )


@pytest.fixture
def valid_case():
    spend_secret = bytes(range(64))
    shared_secret = bytes(range(32))
    rho = bytes([17]) * 64
    randomness = bytes([29]) * 64
    value = 123_456
    commitment = note_commitment(
        note_owner(spend_public(spend_secret), shared_secret), value, rho, randomness
    )
    source = make_output(commitment, 3)

    tree = OutputTree()
    for marker in (40, 41, 42, 43, 44, 45):
        tree.append(bytes([marker]) * 64)
    index = tree.append(source.leaf)
    tree.append(bytes([46]) * 64)
    statement = TransactionStatementV1(
        chain_id=CHAIN_ID,
        anchor_height=12,
        root_out=tree.root,
        fee=1,
        nullifiers=(nullifier(spend_secret, shared_secret, rho),),
        # This valid but unrelated output emphasizes that the oracle does not
        # validate output construction or transaction balance.
        outputs=(make_output(b"o" * 64, 7),),
    )
    witness = NoteMembershipWitnessV1(
        spend_secret=spend_secret,
        kem_shared_secret=shared_secret,
        value=value,
        rho=rho,
        randomness=randomness,
        source_output=source,
        leaf_index=index,
        siblings=tree.authentication_path(index),
    )
    return statement, witness


def test_reference_oracle_accepts_one_valid_opening_and_depth_64_path(valid_case):
    statement, witness = valid_case
    assert len(witness.siblings) == DEPTH
    assert witness.leaf_index == 6
    assert check_note_membership_and_nullifier_witness_v1(statement, witness)


def test_reference_oracle_rejects_opening_nullifier_leaf_and_path_mutations(valid_case):
    statement, witness = valid_case
    mutations = (
        replace(witness, spend_secret=b"x" * 64),
        replace(witness, kem_shared_secret=b"k" * 32),
        replace(witness, value=witness.value + 1),
        replace(witness, rho=b"r" * 64),
        replace(witness, randomness=b"z" * 64),
        replace(witness, source_output=replace(witness.source_output, commitment=b"m" * 64)),
        replace(witness, source_output=replace(witness.source_output, ciphertext=b"q" * 156)),
        replace(witness, leaf_index=witness.leaf_index ^ 1),
        replace(witness, leaf_index=True),
        replace(witness, leaf_index=6.0),
        replace(witness, leaf_index=1 << 64),
        replace(witness, siblings=(b"s" * 64,) + witness.siblings[1:]),
        replace(witness, siblings=witness.siblings[:-1]),
        replace(witness, siblings=list(witness.siblings)),
    )
    assert all(not check_note_membership_and_nullifier_witness_v1(statement, item) for item in mutations)

    wrong_nullifier = replace(statement, nullifiers=(b"n" * 64,))
    assert not check_note_membership_and_nullifier_witness_v1(wrong_nullifier, witness)
    wrong_root = replace(statement, root_out=b"r" * 64)
    assert not check_note_membership_and_nullifier_witness_v1(wrong_root, witness)


def test_reference_oracle_fails_closed_on_noncanonical_public_statement(valid_case):
    statement, witness = valid_case
    assert not check_note_membership_and_nullifier_witness_v1(object(), witness)
    assert not check_note_membership_and_nullifier_witness_v1(statement, object())
    assert not check_note_membership_and_nullifier_witness_v1(
        replace(statement, nullifiers=(statement.nullifiers[0], statement.nullifiers[0])), witness
    )
    assert not check_note_membership_and_nullifier_witness_v1(
        replace(statement, fee=True), witness
    )


def test_oracle_deliberately_checks_only_input_subrelation(valid_case):
    statement, witness = valid_case
    changed_output = make_output(b"p" * 64, 19)
    changed_public_fields = replace(
        statement,
        chain_id=b"d" * 32,
        anchor_height=0,
        fee=2**64 - 1,
        outputs=(changed_output,),
    )
    # The altered statement remains canonical; those fields are intentionally
    # outside this note-opening/membership/nullifier oracle's relation.
    assert check_note_membership_and_nullifier_witness_v1(changed_public_fields, witness)


def test_secret_opening_material_is_not_in_witness_repr(valid_case):
    _, witness = valid_case
    rendered = repr(witness)
    assert witness.spend_secret.hex() not in rendered
    assert witness.kem_shared_secret.hex() not in rendered
    assert witness.rho.hex() not in rendered
    assert witness.randomness.hex() not in rendered
