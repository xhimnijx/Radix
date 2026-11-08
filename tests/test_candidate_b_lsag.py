"""Tests for the Candidate-B group and linkable ring signature."""

import secrets

import pytest

from radix_core.candidate_b import group, lsag


def _is_probable_prime(n: int, rounds: int = 32) -> bool:
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small
    odd, exponent = n - 1, 0
    while odd % 2 == 0:
        odd //= 2
        exponent += 1
    for _ in range(rounds):
        base = secrets.randbelow(n - 3) + 2
        value = pow(base, odd, n)
        if value in (1, n - 1):
            continue
        for _ in range(exponent - 1):
            value = pow(value, 2, n)
            if value == n - 1:
                break
        else:
            return False
    return True


def _keypair():
    secret = secrets.randbelow(group.Q - 2) + 1
    return secret, group.scalar_mul(secret)


def test_group_parameters_are_a_valid_safe_prime_subgroup():
    group.validate_parameters()
    assert group.P.bit_length() == 256
    assert _is_probable_prime(group.P)
    assert _is_probable_prime(group.Q)
    assert group.P == 2 * group.Q + 1


def test_hash_to_point_is_deterministic_and_in_the_subgroup():
    first = group.hash_to_point(b"note")
    assert first == group.hash_to_point(b"note")
    assert group.is_valid_point(first)
    assert first != group.hash_to_point(b"other")


def test_scalar_encoding_is_canonical():
    value = 12345
    assert group.decode_scalar(group.encode_scalar(value)) == value
    with pytest.raises(ValueError):
        group.decode_scalar(group.Q.to_bytes(32, "big"))


@pytest.mark.parametrize("size", [1, 2, 3, 5, 16])
def test_sign_and_verify_roundtrip_for_each_ring_size(size):
    secrets_ = [secrets.randbelow(group.Q - 2) + 1 for _ in range(size)]
    ring = tuple(group.scalar_mul(secret) for secret in secrets_)
    signer = size // 2
    signature = lsag.sign(b"tx", ring, signer, secrets_[signer])

    assert lsag.verify(b"tx", ring, signature)
    assert signature.tag == lsag.tag_for(secrets_[signer], ring[signer])
    assert len(signature.responses) == size


def test_signature_does_not_reveal_the_signer():
    # Sanity check on the shape, not a security proof: the signature has exactly
    # one response per member regardless of which index signed.
    secrets_ = [secrets.randbelow(group.Q - 2) + 1 for _ in range(4)]
    ring = tuple(group.scalar_mul(secret) for secret in secrets_)
    first = lsag.sign(b"m", ring, 0, secrets_[0])
    third = lsag.sign(b"m", ring, 2, secrets_[2])
    assert len(first.encode()) == len(third.encode()) == 64 + 32 * 4


def test_wrong_message_ring_and_index_are_rejected():
    secrets_ = [secrets.randbelow(group.Q - 2) + 1 for _ in range(4)]
    ring = tuple(group.scalar_mul(secret) for secret in secrets_)
    signature = lsag.sign(b"amount:1", ring, 1, secrets_[1])

    assert not lsag.verify(b"amount:2", ring, signature)
    assert not lsag.verify(b"amount:1", ring[::-1], signature)
    with pytest.raises(lsag.RingSignatureError):
        lsag.sign(b"m", ring, 5, secrets_[1])
    with pytest.raises(lsag.RingSignatureError):
        # Secret does not match the declared signer index.
        lsag.sign(b"m", ring, 0, secrets_[1])


def test_each_response_is_covered_by_the_challenge_chain():
    secrets_ = [secrets.randbelow(group.Q - 2) + 1 for _ in range(3)]
    ring = tuple(group.scalar_mul(secret) for secret in secrets_)
    signature = lsag.sign(b"m", ring, 0, secrets_[0])

    for index in range(len(signature.responses)):
        mutated = list(signature.responses)
        mutated[index] = (mutated[index] + 1) % group.Q
        tampered = lsag.LinkableRingSignature(
            tag=signature.tag, c0=signature.c0, responses=tuple(mutated)
        )
        assert not lsag.verify(b"m", ring, tampered)


def test_tag_is_deterministic_across_signatures_and_rings():
    secret, key = _keypair()
    other = tuple(group.scalar_mul(secrets.randbelow(group.Q - 2) + 1) for _ in range(3))

    first = lsag.sign(b"m1", (key,) + other, 0, secret)
    second = lsag.sign(b"m2", (key,) + other, 0, secret)
    third = lsag.sign(b"m3", (key,), 0, secret)

    assert first.tag == second.tag == third.tag


def test_distinct_notes_have_distinct_tags():
    tags = set()
    for _ in range(16):
        secret, key = _keypair()
        tags.add(lsag.tag_for(secret, key))
    assert len(tags) == 16


def test_malformed_rings_and_signatures_are_rejected():
    secret, key = _keypair()
    with pytest.raises(lsag.RingSignatureError):
        lsag.sign(b"m", (), 0, secret)
    with pytest.raises(lsag.RingSignatureError):
        lsag.sign(b"m", (key, key), 0, secret)
    with pytest.raises(lsag.RingSignatureError):
        lsag.sign(b"m", (key, 0), 0, secret)

    signature = lsag.sign(b"m", (key,), 0, secret)
    assert not lsag.verify(b"m", (key, 1), signature)
    assert not lsag.verify(b"m", (key,), "not a signature")
    bad_tag = lsag.LinkableRingSignature(
        tag=0, c0=signature.c0, responses=signature.responses
    )
    assert not lsag.verify(b"m", (key,), bad_tag)


def test_signature_encoding_roundtrip():
    secret, key = _keypair()
    signature = lsag.sign(b"m", (key,), 0, secret)
    encoded = signature.encode()
    assert lsag.LinkableRingSignature.decode(encoded, 1) == signature
    with pytest.raises(lsag.RingSignatureError):
        lsag.LinkableRingSignature.decode(encoded, 2)
    with pytest.raises(lsag.RingSignatureError):
        lsag.LinkableRingSignature.decode(encoded[:-1], 1)
