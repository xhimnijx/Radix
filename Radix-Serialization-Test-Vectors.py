"""Test-only encoder/reference decoder for the Radix experimental v1 byte grammar.

These tests check syntax, lengths, expected-chain matching, canonical counts, and selected test vectors.
They do not validate ML-KEM keys, AEAD ciphertexts, transactions, proofs, a
production parser, or the security of the protocol.
Run with: python Radix-Serialization-Test-Vectors.py
"""
import hashlib


def u16(value: int) -> bytes:
    return value.to_bytes(2, "little")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "little")


def bytes_field(value: bytes) -> bytes:
    return u32(len(value)) + value


def vec(values: list[bytes]) -> bytes:
    return u16(len(values)) + b"".join(bytes_field(value) for value in values)


def frame(tag: str, values: list[bytes]) -> bytes:
    encoded_tag = tag.encode("ascii")
    return (
        b"RADIX"
        + b"\x01"
        + u16(len(encoded_tag))
        + encoded_tag
        + u16(len(values))
        + b"".join(bytes_field(value) for value in values)
    )


def _take_uint(data: bytes, offset: int, width: int) -> tuple[int, int]:
    end = offset + width
    if end > len(data):
        raise ValueError("truncated integer")
    return int.from_bytes(data[offset:end], "little"), end


def _take_bytes(data: bytes, offset: int, max_length: int) -> tuple[bytes, int]:
    length, offset = _take_uint(data, offset, 4)
    if length > max_length:
        raise ValueError("field exceeds maximum length")
    end = offset + length
    if end > len(data):
        raise ValueError("truncated byte field")
    return data[offset:end], end


def parse_frame(data: bytes, expected_tag: str, field_max_lengths: list[int]) -> list[bytes]:
    tag = expected_tag.encode("ascii")
    if len(data) < 8 or data[:5] != b"RADIX":
        raise ValueError("bad frame magic or truncated header")
    if data[5] != 1:
        raise ValueError("unsupported frame version")
    tag_length, offset = _take_uint(data, 6, 2)
    if tag_length != len(tag):
        raise ValueError("unexpected tag length")
    end_tag = offset + tag_length
    if end_tag > len(data) or data[offset:end_tag] != tag:
        raise ValueError("unexpected tag")
    count, offset = _take_uint(data, end_tag, 2)
    if count != len(field_max_lengths):
        raise ValueError("unexpected frame argument count")
    fields = []
    for max_length in field_max_lengths:
        value, offset = _take_bytes(data, offset, max_length)
        fields.append(value)
    if offset != len(data):
        raise ValueError("trailing frame bytes")
    return fields


def parse_vec(
    data: bytes, max_count: int, max_item_length: int, exact_item_length: int | None = None
) -> list[bytes]:
    count, offset = _take_uint(data, 0, 2)
    if not 1 <= count <= max_count:
        raise ValueError("vector count out of range")
    items = []
    for _ in range(count):
        value, offset = _take_bytes(data, offset, max_item_length)
        if exact_item_length is not None and len(value) != exact_item_length:
            raise ValueError("noncanonical vector item length")
        items.append(value)
    if offset != len(data):
        raise ValueError("trailing vector bytes")
    return items


def parse_address(data: bytes, expected_chain_id: bytes) -> list[bytes]:
    if len(expected_chain_id) != 32:
        raise ValueError("expected chain id must be 32 bytes")
    fields = parse_frame(data, "radix/address/v1", [32, 64, 1184])
    if [len(field) for field in fields] != [32, 64, 1184]:
        raise ValueError("noncanonical address field length")
    if fields[0] != expected_chain_id:
        raise ValueError("chain id mismatch")
    return fields


def parse_output(data: bytes) -> list[bytes]:
    fields = parse_frame(data, "radix/output/v1", [64, 1088, 12, 668, 64])
    lengths = [len(field) for field in fields]
    if lengths[:3] != [64, 1088, 12] or lengths[3] not in range(156, 669) or lengths[4] != 64:
        raise ValueError("noncanonical output field length")
    return fields


def parse_statement(data: bytes) -> tuple[list[bytes], list[bytes], list[list[bytes]]]:
    max_output_frame = 5 + 1 + 2 + len("radix/output/v1") + 2 + 5 * 4 + 64 + 1088 + 12 + 668 + 64
    max_nullifier_vec = 2 + 16 * (4 + 64)
    max_output_vec = 2 + 16 * (4 + max_output_frame)
    fields = parse_frame(
        data,
        "radix/tx-statement/v1",
        [32, 2, 8, 64, 8, max_nullifier_vec, max_output_vec],
    )
    chain_id, version, anchor, root, fee, nf_vec, output_vec = fields
    if [len(chain_id), len(version), len(anchor), len(root), len(fee)] != [32, 2, 8, 64, 8]:
        raise ValueError("noncanonical statement field length")
    if version != u16(1):
        raise ValueError("unsupported transaction version")
    nullifiers = parse_vec(nf_vec, 16, 64, 64)
    encoded_outputs = parse_vec(output_vec, 16, max_output_frame)
    outputs = [parse_output(output) for output in encoded_outputs]
    return fields[:5], nullifiers, outputs


def seq(length: int) -> bytes:
    return bytes(index % 256 for index in range(length))


def fixture(c_length: int, input_count: int = 1, output_count: int = 1) -> tuple[bytes, bytes, bytes]:
    if c_length not in range(156, 669) or not 1 <= input_count <= 16 or not 1 <= output_count <= 16:
        raise ValueError("fixture dimensions out of range")
    chain_id, pk_s, pk_v = seq(32), seq(64), seq(1184)
    address = frame("radix/address/v1", [chain_id, pk_s, pk_v])

    outputs = []
    for index in range(output_count):
        cm = seq(64) if index == 0 else bytes([index]) * 64
        outputs.append(frame("radix/output/v1", [cm, seq(1088), seq(12), seq(c_length), seq(64)]))
    nullifiers = [bytes([0x5A]) * 64] + [bytes([0x5A + index]) * 64 for index in range(1, input_count)]
    statement = frame(
        "radix/tx-statement/v1",
        [
            chain_id,
            u16(1),
            u64(60),
            bytes([0xA5]) * 64,
            u64(0),
            vec(nullifiers),
            vec(outputs),
        ],
    )
    return address, outputs[0], statement


def test_primitive_known_answer() -> None:
    tag = b"radix/spend-pk/v1"
    secret = bytes(range(64))  # public test bytes, not a production secret
    encoded = frame("radix/spend-pk/v1", [secret])
    assert len(encoded) == 95
    assert encoded.hex() == (
        "524144495801110072616469782f7370656e642d706b2f763101004000000000"
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    )
    assert hashlib.shake_256(encoded).hexdigest(64) == (
        "6790c030ce689c30e5e0f77ecae4cafef32d1babf458e7b2e54d6c1485c8675"
        "76d2b5455f35507e1348e545f4c61f88b65979579d188008690b6e3659ef51559"
    )
    assert hashlib.shake_256(b"").hexdigest(64) == (
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
    )
    assert len(tag) == 17


def test_serialization_fingerprints() -> None:
    expected = {
        "address": (
            1318,
            "9cb50d69354c882cf746ef92e91666eb60bea30709917dafaeb4786e6f3fbac9",
        ),
        "output": (
            1429,
            "970b4e469795fef013696122d0391dfff566caa7d627f2169876032023a49aef",
        ),
        "statement": (
            1678,
            "845fc315a6ca599ea1046082521b9dd2ebf300d3a25148e8124dbf63d25c359f",
        ),
    }
    address, output, statement = fixture(156)
    for name, encoded in (
        ("address", address),
        ("output", output),
        ("statement", statement),
    ):
        expected_length, expected_sha256 = expected[name]
        assert len(encoded) == expected_length
        assert hashlib.sha256(encoded).hexdigest() == expected_sha256


def test_statement_length_boundaries_by_count_and_ciphertext_size() -> None:
    cases = (
        (1, 1, 156, 1678),
        (1, 1, 668, 2190),
        (16, 16, 156, 24193),
        (16, 16, 668, 32385),
    )
    for input_count, output_count, c_length, expected_length in cases:
        _, _, statement = fixture(c_length, input_count, output_count)
        assert len(statement) == expected_length


def _must_reject(operation) -> None:
    try:
        operation()
    except ValueError:
        return
    raise AssertionError("malformed encoding was accepted")


def test_reference_parser_acceptance_and_rejection() -> None:
    address, output, statement = fixture(156)
    assert parse_address(address, seq(32)) == [seq(32), seq(64), seq(1184)]
    _must_reject(lambda: parse_address(address, bytes([0xFF]) * 32))
    _must_reject(lambda: parse_address(address, seq(31)))
    assert [len(field) for field in parse_output(output)] == [64, 1088, 12, 156, 64]
    public, nullifiers, outputs = parse_statement(statement)
    assert [len(field) for field in public] == [32, 2, 8, 64, 8]
    assert len(nullifiers) == len(outputs) == 1

    _, _, max_count_statement = fixture(668, 16, 16)
    _, max_count_nullifiers, max_count_outputs = parse_statement(max_count_statement)
    assert len(max_count_nullifiers) == len(max_count_outputs) == 16

    for encoded, decoder in (
        (address, lambda value: parse_address(value, seq(32))),
        (output, parse_output),
        (statement, parse_statement),
    ):
        for end in range(len(encoded)):
            truncated = encoded[:end]
            _must_reject(lambda truncated=truncated, decoder=decoder: decoder(truncated))

    _must_reject(lambda: parse_address(b"X" + address[1:], seq(32)))
    _must_reject(lambda: parse_address(address[:5] + b"\x02" + address[6:], seq(32)))
    _must_reject(lambda: parse_address(address[:-1], seq(32)))
    _must_reject(lambda: parse_address(address + b"\x00", seq(32)))
    _must_reject(lambda: parse_output(address))

    tag_end = 5 + 1 + 2 + len(b"radix/address/v1")
    wrong_length = bytearray(address)
    first_field_length_offset = tag_end + 2
    wrong_length[first_field_length_offset:first_field_length_offset + 4] = u32(33)
    _must_reject(lambda: parse_address(bytes(wrong_length), seq(32)))

    short_ciphertext = frame(
        "radix/output/v1", [seq(64), seq(1088), seq(12), seq(155), seq(64)]
    )
    _must_reject(lambda: parse_output(short_ciphertext))
    _must_reject(lambda: parse_vec(u16(0), 16, 64, 64))
    _must_reject(lambda: parse_vec(u16(17), 16, 64, 64))
    _must_reject(lambda: parse_vec(u16(1) + bytes_field(seq(63)), 16, 64, 64))
    _must_reject(lambda: parse_vec(vec([seq(64)]) + b"\x00", 16, 64, 64))

    fields = parse_frame(statement, "radix/tx-statement/v1", [32, 2, 8, 64, 8, 1090, 31122])
    zero_input_statement = frame("radix/tx-statement/v1", fields[:5] + [u16(0), fields[6]])
    _must_reject(lambda: parse_statement(zero_input_statement))
    zero_output_statement = frame("radix/tx-statement/v1", fields[:6] + [u16(0)])
    _must_reject(lambda: parse_statement(zero_output_statement))
    encoded_outputs = parse_vec(fields[6], 16, 1941)
    seventeen_output_statement = frame(
        "radix/tx-statement/v1", fields[:6] + [vec(encoded_outputs * 17)]
    )
    _must_reject(lambda: parse_statement(seventeen_output_statement))
    wrong_version_statement = frame(
        "radix/tx-statement/v1", fields[:1] + [u16(2)] + fields[2:]
    )
    _must_reject(lambda: parse_statement(wrong_version_statement))
    _must_reject(lambda: parse_statement(frame("radix/tx-statement/v1", fields[:-1])))
    _must_reject(lambda: parse_statement(statement + b"\x00"))


if __name__ == "__main__":
    test_primitive_known_answer()
    test_serialization_fingerprints()
    test_statement_length_boundaries_by_count_and_ciphertext_size()
    test_reference_parser_acceptance_and_rejection()
    print("All Radix experimental-v1 encoding and reference-parser tests passed.")
