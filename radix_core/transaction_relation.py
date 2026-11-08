"""Reference checks for selected Candidate-A transaction relations.

This module is a host-language oracle, not a proof system. In particular, a
successful check discloses/uses the witness in ordinary Python and must never
be substituted for a zero-knowledge proof verifier in consensus.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import note_commitment, note_owner, nullifier, output_leaf, spend_public
from .encoding import U64_MAX
from .merkle import DEPTH, verify_membership
from .wire import (
    OutputRecord,
    TransactionStatementV1,
    parse_statement_v1,
    serialize_statement_v1,
    validate_output_record_v1,
)


def check_value_conservation_v1(input_value: int, output_value: int, fee: int) -> bool:
    """Host-side oracle for one-input/one-output nonzero U64 value conservation.

    Mirrors RDXL's intended arithmetic relation without overflow. This is not
    an AIR, proof verifier, fee-policy check, or consensus authorization.
    """

    for value in (input_value, output_value, fee):
        if type(value) is not int or not 0 <= value <= U64_MAX:
            return False
    if input_value == 0 or output_value == 0:
        return False
    if output_value > U64_MAX - fee:
        return False
    return output_value + fee == input_value


def check_statement_value_conservation_v1(
    statement_bytes: bytes,
    input_value: int,
    output_value: int,
) -> bool:
    """Check a canonical 1-in/1-out statement's fee against private values.

    The exact bounded statement bytes are parsed and re-encoded before the
    public fee is used. This host oracle does not prove the private output value
    opens the public commitment, bind bytes into a proof transcript, or perform
    consensus validation.
    """

    if type(statement_bytes) is not bytes:
        return False
    try:
        statement = parse_statement_v1(statement_bytes)
        if serialize_statement_v1(statement) != statement_bytes:
            return False
    except (TypeError, ValueError):
        return False
    if len(statement.nullifiers) != 1 or len(statement.outputs) != 1:
        return False
    return check_value_conservation_v1(input_value, output_value, statement.fee)


@dataclass(frozen=True)
class NoteMembershipWitnessV1:
    """Private opening material for one note and its output-tree path.

    ``kem_shared_secret`` is treated as a witness here; this oracle does not
    prove that it is the result of FIPS 203 decapsulation of the source
    output's KEM ciphertext. All secret/opening fields are excluded from repr.
    """

    spend_secret: bytes = field(repr=False)
    kem_shared_secret: bytes = field(repr=False)
    value: int = field(repr=False)
    rho: bytes = field(repr=False)
    randomness: bytes = field(repr=False)
    source_output: OutputRecord = field(repr=False)
    leaf_index: int
    siblings: tuple[bytes, ...] = field(repr=False)


def check_note_membership_and_nullifier_witness_v1(
    statement: TransactionStatementV1,
    witness: NoteMembershipWitnessV1,
) -> bool:
    """Check one note opening, its depth-64 membership, and statement nullifier.

    This verifies only the input-note subrelation. It does not check output
    construction, value conservation, fee semantics, anchor ancestry/age,
    nullifier-set uniqueness, KEM decapsulation, AEAD, or transaction
    transcript/proof binding. A ``True`` result is not consensus authorization.
    Invalid/noncanonical inputs fail closed with ``False``.
    """
    if type(statement) is not TransactionStatementV1:
        return False
    if type(witness) is not NoteMembershipWitnessV1:
        return False
    if type(statement.nullifiers) is not tuple or len(statement.nullifiers) != 1:
        return False
    if type(witness.siblings) is not tuple or len(witness.siblings) != DEPTH:
        return False
    if type(witness.source_output) is not OutputRecord:
        return False

    try:
        # This validates the entire canonical public statement, not only the
        # root/nullifier fields consumed by this subrelation.
        serialize_statement_v1(statement)
        validate_output_record_v1(witness.source_output)

        output = witness.source_output
        expected_commitment = note_commitment(
            note_owner(spend_public(witness.spend_secret), witness.kem_shared_secret),
            witness.value,
            witness.rho,
            witness.randomness,
        )
        if output.commitment != expected_commitment:
            return False

        expected_nullifier = nullifier(
            witness.spend_secret,
            witness.kem_shared_secret,
            witness.rho,
        )
        if statement.nullifiers[0] != expected_nullifier:
            return False

        # Recompute the leaf explicitly so this check is not dependent on a
        # previously cached or caller-supplied leaf interpretation.
        expected_leaf = output_leaf(
            output.commitment,
            output.kem_ciphertext,
            output.nonce,
            output.ciphertext,
        )
        if output.leaf != expected_leaf:
            return False
        return verify_membership(
            expected_leaf,
            witness.leaf_index,
            witness.siblings,
            statement.root_out,
        )
    except (AttributeError, TypeError, ValueError):
        return False
