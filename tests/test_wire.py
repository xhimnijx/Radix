import pytest

from radix_core.crypto import output_leaf
from radix_core.cryptography_backend import CryptographyMlKem768Provider
from radix_core.encoding import frame, u16, u64
from radix_core.wire import (
    MAX_STATEMENT_BYTES,
    OutputRecord,
    TransactionStatementV1,
    parse_address,
    parse_output_v1,
    parse_statement_v1,
    serialize_address,
)


def make_output(index: int = 0, ciphertext_length: int = 156) -> OutputRecord:
    commitment = bytes([index + 1]) * 64
    kem_ciphertext = bytes([index + 2]) * 1088
    nonce = bytes([index + 3]) * 12
    ciphertext = bytes([index + 4]) * ciphertext_length
    leaf = output_leaf(commitment, kem_ciphertext, nonce, ciphertext)
    return OutputRecord(commitment, kem_ciphertext, nonce, ciphertext, leaf)


def test_address_roundtrip_and_chain_binding():
    chain_id, spend_pk = b"c" * 32, b"s" * 64
    view_pk, _ = CryptographyMlKem768Provider().generate_keypair()
    encoded = serialize_address(chain_id, spend_pk, view_pk)
    assert parse_address(encoded, expected_chain_id=chain_id) == (chain_id, spend_pk, view_pk)
    with pytest.raises(ValueError, match="chain ID mismatch"):
        parse_address(encoded, expected_chain_id=b"x" * 32)
    with pytest.raises(ValueError):
        parse_address(encoded + b"\x00")

    malformed_key = bytearray(view_pk)
    malformed_key[0] = 0x01
    malformed_key[1] = (malformed_key[1] & 0xF0) | 0x0D
    malformed_address = frame("radix/address/v1", [chain_id, spend_pk, bytes(malformed_key)])
    with pytest.raises(ValueError, match="noncanonical polynomial coefficient"):
        parse_address(malformed_address)
    with pytest.raises(ValueError, match="noncanonical polynomial coefficient"):
        serialize_address(chain_id, spend_pk, bytes(malformed_key))


def test_output_leaf_matches_rust_reference_vector():
    leaf = output_leaf(b"o" * 64, b"k" * 1088, b"n" * 12, b"c" * 156)
    assert leaf.hex() == (
        "7b945ae5bd9e5cb7462849cf9b73c0b4e71f7f6c9c6f10c251de32e8c0939e3c"
        "184c2a1ac5686cb93e2f44295a6d191a84547eaae1c588317e4a6d28449fabba"
    )


def test_one_by_one_statement_matches_rust_reference_layout():
    output = OutputRecord(
        b"o" * 64,
        b"k" * 1088,
        b"n" * 12,
        b"c" * 156,
        output_leaf(b"o" * 64, b"k" * 1088, b"n" * 12, b"c" * 156),
    )
    statement = TransactionStatementV1(
        chain_id=b"x" * 32,
        anchor_height=12,
        root_out=b"r" * 64,
        fee=1,
        nullifiers=(b"z" * 64,),
        outputs=(output,),
    )
    encoded = statement.serialize()
    assert len(encoded) == 1678
    assert encoded[:48].hex() == (
        "524144495801150072616469782f74782d73746174656d656e742f763107002000000078787878787878787878787878"
    )
    assert encoded[157:165] == (1).to_bytes(8, "little")
    assert encoded[175:239] == b"z" * 64
    assert encoded[278:342] == b"o" * 64


def test_output_ciphertext_legacy_v1_endpoints_and_leaf_binding():
    for size in (156, 668):
        output = make_output(ciphertext_length=size)
        assert parse_output_v1(output.serialize()) == output
        assert output.leaf_matches_fields()
    wrong = make_output()
    tampered = OutputRecord(wrong.commitment, wrong.kem_ciphertext, wrong.nonce, wrong.ciphertext, b"z" * 64)
    assert not tampered.leaf_matches_fields()
    with pytest.raises(ValueError, match="output leaf"):
        tampered.serialize()
    malformed_wire = frame(
        "radix/output/v1",
        [tampered.commitment, tampered.kem_ciphertext, tampered.nonce, tampered.ciphertext, tampered.leaf],
    )
    with pytest.raises(ValueError, match="output leaf"):
        parse_output_v1(malformed_wire)
    for size in (155, 669):
        with pytest.raises(ValueError):
            make_output(ciphertext_length=size).serialize()


def test_output_ciphertext_length_domain_roundtrips_every_allowed_size():
    for size in range(156, 669):
        output = make_output(ciphertext_length=size)
        encoded = output.serialize()
        assert parse_output_v1(encoded) == output


def test_statement_roundtrip_and_strict_chain_version_and_trailing_bytes():
    statement = TransactionStatementV1(
        chain_id=b"c" * 32,
        anchor_height=60,
        root_out=b"r" * 64,
        fee=0,
        nullifiers=(b"n" * 64, b"m" * 64),
        outputs=(make_output(0, 156), make_output(1, 668)),
    )
    encoded = statement.serialize()
    assert parse_statement_v1(encoded, expected_chain_id=statement.chain_id) == statement
    with pytest.raises(ValueError, match="chain ID mismatch"):
        parse_statement_v1(encoded, expected_chain_id=b"x" * 32)
    with pytest.raises(ValueError):
        parse_statement_v1(encoded + b"\x00")

    # Replace only the fixed version field in the already framed statement.
    from radix_core.encoding import decode_frame
    parsed_fields = decode_frame(
        encoded,
        "radix/tx-statement/v1",
        [
            32,
            2,
            8,
            64,
            8,
            (2 + 4 + 64, 2 + 16 * 68),
            (2 + 4 + 1429, 2 + 16 * (4 + 1941)),
        ],
    )
    parsed_fields[1] = u16(2)
    bad_version = frame("radix/tx-statement/v1", parsed_fields)
    with pytest.raises(ValueError, match="unsupported transaction version"):
        parse_statement_v1(bad_version)


def test_statement_maximum_size_is_exact_and_oversize_rejected_early():
    statement = TransactionStatementV1(
        b"c" * 32,
        60,
        b"r" * 64,
        0,
        tuple(bytes([index + 1]) * 64 for index in range(16)),
        tuple(make_output(index, 668) for index in range(16)),
    )
    encoded = statement.serialize()

    assert len(encoded) == MAX_STATEMENT_BYTES == 32_385
    assert parse_statement_v1(encoded) == statement
    with pytest.raises(ValueError, match="exceeds size limit"):
        parse_statement_v1(bytes(MAX_STATEMENT_BYTES + 1))


def test_statement_rejects_duplicate_nullifiers_and_commitments():
    repeated_nf = TransactionStatementV1(
        b"c" * 32, 60, b"r" * 64, 0, (b"n" * 64, b"n" * 64), (make_output(),)
    )
    with pytest.raises(ValueError, match="duplicate nullifier"):
        repeated_nf.serialize()
    output = make_output()
    repeated_cm = OutputRecord(
        output.commitment,
        output.kem_ciphertext,
        output.nonce,
        output.ciphertext,
        output.leaf,
    )
    repeated_outputs = TransactionStatementV1(
        b"c" * 32, 60, b"r" * 64, 0, (b"n" * 64,), (output, repeated_cm)
    )
    with pytest.raises(ValueError, match="duplicate output commitment"):
        repeated_outputs.serialize()


def test_statement_requires_canonical_counts_and_integer_types():
    cases = [
        ((), (make_output(),)),
        ((b"n" * 64,), ()),
        ((b"n" * 64,) * 17, (make_output(),)),
    ]
    for nfs, outputs in cases:
        statement = TransactionStatementV1(b"c" * 32, 60, b"r" * 64, 0, nfs, outputs)
        with pytest.raises(ValueError):
            statement.serialize()
    with pytest.raises(ValueError):
        TransactionStatementV1(b"c" * 32, True, b"r" * 64, 0, (b"n" * 64,), (make_output(),)).serialize()


def test_statement_serialization_does_not_trust_shadowed_output_methods():
    output = make_output()
    object.__setattr__(output, "leaf", b"!" * 64)
    object.__setattr__(output, "leaf_matches_fields", lambda: True)
    object.__setattr__(output, "serialize", lambda: b"pretend canonical")
    statement = TransactionStatementV1(
        b"c" * 32, 60, b"r" * 64, 0, (b"n" * 64,), (output,)
    )
    with pytest.raises(ValueError, match="output leaf"):
        statement.serialize()


def test_statement_rejects_noncanonical_or_overridden_vector_containers():
    with pytest.raises(ValueError, match="nullifier vector"):
        TransactionStatementV1(
            b"c" * 32, 60, b"r" * 64, 0, [b"n" * 64], (make_output(),)
        ).serialize()
    with pytest.raises(ValueError, match="output vector"):
        TransactionStatementV1(
            b"c" * 32, 60, b"r" * 64, 0, (b"n" * 64,), [make_output()]
        ).serialize()

    class LyingTuple(tuple):
        def __len__(self):
            return 1

        def __iter__(self):
            return iter(())

    fake_nullifiers = LyingTuple((b"n" * 64,))
    with pytest.raises(ValueError, match="nullifier vector"):
        TransactionStatementV1(
            b"c" * 32, 60, b"r" * 64, 0, fake_nullifiers, (make_output(),)
        ).serialize()
    fake_outputs = LyingTuple((make_output(),))
    with pytest.raises(ValueError, match="output vector"):
        TransactionStatementV1(
            b"c" * 32, 60, b"r" * 64, 0, (b"n" * 64,), fake_outputs
        ).serialize()
