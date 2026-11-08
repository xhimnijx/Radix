import pytest

from radix_core.providers import AES_GCM_TAG_BYTES
from radix_core.memo import (
    FIXED_PLAINTEXT_LENGTH,
    decode_padded_proposal,
    decode_plaintext_v1,
    encode_padded_proposal,
    encode_plaintext_v1,
)


def test_v1_variable_memo_plaintext_vectors_and_bounds():
    args = (42, b"r" * 64, b"s" * 64)
    for memo in (b"", b"memo", b"x" * 512):
        encoded = encode_plaintext_v1(*args, memo)
        assert len(encoded) == 140 + len(memo)
        assert len(encoded) + AES_GCM_TAG_BYTES == 156 + len(memo)
        assert decode_plaintext_v1(encoded) == (*args, memo)
    with pytest.raises(ValueError):
        encode_plaintext_v1(0, b"r" * 64, b"s" * 64, b"")
    with pytest.raises(ValueError):
        decode_plaintext_v1(encode_plaintext_v1(*args, b"m") + b"\x00")


def test_fixed_padded_memo_proposal_is_separate_and_canonical():
    args = (42, b"r" * 64, b"s" * 64)
    for memo in (b"", b"memo", b"x" * 512):
        encoded = encode_padded_proposal(*args, memo)
        assert len(encoded) == FIXED_PLAINTEXT_LENGTH
        assert len(encoded) + AES_GCM_TAG_BYTES == 668
        assert decode_padded_proposal(encoded) == (*args, memo)
    with pytest.raises(ValueError):
        decode_padded_proposal(encode_padded_proposal(*args, b"x")[:-1])
    encoded = bytearray(encode_padded_proposal(*args, b"x"))
    encoded[-1] = 1
    with pytest.raises(ValueError, match="padding"):
        decode_padded_proposal(bytes(encoded))
    with pytest.raises(ValueError):
        encode_padded_proposal(42, b"r" * 64, b"s" * 64, b"x" * 513)
