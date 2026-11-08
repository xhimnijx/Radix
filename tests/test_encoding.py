import pytest

from radix_core.crypto import SPEND_PK, shake_frame, spend_public
from radix_core.encoding import decode_frame, decode_vec, encode_vec, frame, u8, u16, u32, u64


def test_spend_public_known_answer_and_exact_frame_vector():
    secret = bytes(range(64))
    encoded = frame(SPEND_PK, [secret])
    assert len(encoded) == 95
    assert encoded.hex() == (
        "524144495801110072616469782f7370656e642d706b2f763101004000000000"
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    )
    assert spend_public(secret).hex() == (
        "6790c030ce689c30e5e0f77ecae4cafef32d1babf458e7b2e54d6c1485c8675"
        "76d2b5455f35507e1348e545f4c61f88b65979579d188008690b6e3659ef51559"
    )


def test_fixed_width_encoders_are_little_endian_and_reject_bool():
    assert u8(255) == b"\xff"
    assert u16(0x1234) == b"\x34\x12"
    assert u32(0x12345678) == b"\x78\x56\x34\x12"
    assert u64(0x0102030405060708) == bytes.fromhex("0807060504030201")
    for encoder, bad in ((u8, 256), (u16, -1), (u32, True), (u64, 1 << 64)):
        with pytest.raises(ValueError):
            encoder(bad)


def test_every_hash_domain_is_separated_and_argument_order_matters():
    tags = (
        "radix/spend-pk/v1",
        "radix/one-time/v1",
        "radix/note/v1",
        "radix/leaf/v1",
        "radix/tree-empty-leaf/v1",
        "radix/tree-node/v1",
        "radix/nullifier/v1",
        "radix/note-kdf/v1",
    )
    for tag in tags:
        left_right = shake_frame(tag, b"left", b"right")
        assert left_right != shake_frame(tag, b"right", b"left")
    assert len({shake_frame(tag, b"same") for tag in tags}) == len(tags)


def test_frame_parser_rejects_every_truncated_prefix_and_trailing_data():
    encoded = frame("radix/test/v1", [b"abc", b"", b"z" * 9])
    for end in range(len(encoded)):
        with pytest.raises(ValueError):
            decode_frame(encoded[:end], "radix/test/v1", [3, 0, (1, 9)])
    assert decode_frame(encoded, "radix/test/v1", [3, 0, (1, 9)]) == [b"abc", b"", b"z" * 9]
    with pytest.raises(ValueError):
        decode_frame(encoded + b"\x00", "radix/test/v1", [3, 0, (1, 9)])
    with pytest.raises(ValueError):
        decode_frame(encoded, "radix/wrong/v1", [3, 0, (1, 9)])


def test_vector_parser_requires_exact_integer_limits():
    encoded = b"\x01\x00\x01\x00\x00\x00a"
    invalid_limits = (
        {"min_count": True, "max_count": 1, "max_item_length": 1},
        {"min_count": 0, "max_count": 1.0, "max_item_length": 1},
        {"min_count": 0, "max_count": 1, "max_item_length": True},
        {"min_count": 0, "max_count": 1, "max_item_length": 1, "exact_item_length": True},
        {"min_count": 0, "max_count": 1, "max_item_length": 1 << 32},
        {"min_count": 0, "max_count": 1, "max_item_length": 1, "exact_item_length": 2},
    )
    for limits in invalid_limits:
        with pytest.raises(ValueError):
            decode_vec(encoded, **limits)


def test_non_ascii_tags_and_wrong_arity_are_rejected():
    with pytest.raises(ValueError):
        frame("radix/é", [b"x"])
    encoded = frame("radix/test/v1", [b"x"])
    with pytest.raises(ValueError):
        decode_frame(encoded, "radix/test/v1", [1, 1])


def test_vector_encoder_bounds_generator_consumption_by_count_limit():
    assert encode_vec((item for item in (b"a", b"bc")), max_count=2) == (
        b"\x02\x00\x01\x00\x00\x00a\x02\x00\x00\x00bc"
    )

    consumed = 0

    def endless_items():
        nonlocal consumed
        while True:
            consumed += 1
            yield b"x"

    with pytest.raises(ValueError, match="vector count exceeds limit"):
        encode_vec(endless_items(), max_count=3)
    assert consumed == 4

    for invalid_limit in (True, -1, 1 << 16):
        with pytest.raises(ValueError, match="invalid vector count limit"):
            encode_vec((), max_count=invalid_limit)


def test_vector_parser_checks_count_length_truncation_and_trailing_bytes():
    encoded = b"\x02\x00\x01\x00\x00\x00a\x02\x00\x00\x00bc"
    assert decode_vec(encoded, min_count=1, max_count=3, max_item_length=2) == [b"a", b"bc"]
    with pytest.raises(ValueError):
        decode_vec(encoded + b"x", min_count=1, max_count=3, max_item_length=2)
    with pytest.raises(ValueError):
        decode_vec(b"\x00\x00", min_count=1, max_count=3, max_item_length=2)
    with pytest.raises(ValueError):
        decode_vec(b"\x01\x00\x03\x00\x00\x00abc", min_count=1, max_count=3, max_item_length=2)
