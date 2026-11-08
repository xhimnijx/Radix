"""Experimental Candidate-A hash formulas. These are not a security claim."""
from __future__ import annotations

import hashlib

from .encoding import U64_MAX, frame, u64

SPEND_PK = "radix/spend-pk/v1"
NOTE_OWNER = "radix/one-time/v1"
NOTE_COMMITMENT = "radix/note/v1"
OUTPUT_LEAF = "radix/leaf/v1"
EMPTY_LEAF = "radix/tree-empty-leaf/v1"
TREE_NODE = "radix/tree-node/v1"
NULLIFIER = "radix/nullifier/v1"
NOTE_KDF = "radix/note-kdf/v1"

DIGEST_BYTES = 64
SHARED_SECRET_BYTES = 32


def shake_frame(tag: str, *fields: bytes, output_length: int = DIGEST_BYTES) -> bytes:
    if type(output_length) is not int or output_length <= 0:
        raise ValueError("SHAKE output length must be a positive integer")
    return hashlib.shake_256(frame(tag, fields)).digest(output_length)


def spend_public(secret: bytes) -> bytes:
    if type(secret) is not bytes or len(secret) != 64:
        raise ValueError("spend secret must be exactly 64 bytes")
    return shake_frame(SPEND_PK, secret)


def note_owner(spend_public_key: bytes, kem_shared_secret: bytes) -> bytes:
    if type(spend_public_key) is not bytes or len(spend_public_key) != 64:
        raise ValueError("spend public component must be 64 bytes")
    if type(kem_shared_secret) is not bytes or len(kem_shared_secret) != SHARED_SECRET_BYTES:
        raise ValueError("KEM shared secret must be 32 bytes")
    return shake_frame(NOTE_OWNER, spend_public_key, kem_shared_secret)


def note_commitment(owner: bytes, value: int, rho: bytes, randomness: bytes) -> bytes:
    if type(owner) is not bytes or len(owner) != 64:
        raise ValueError("owner value must be 64 bytes")
    if type(value) is not int or not 1 <= value <= U64_MAX:
        raise ValueError("note value must be a nonzero U64")
    if type(rho) is not bytes or type(randomness) is not bytes or len(rho) != 64 or len(randomness) != 64:
        raise ValueError("note commitment randomness must be 64 bytes each")
    return shake_frame(NOTE_COMMITMENT, owner, u64(value), rho, randomness)


def nullifier(secret: bytes, kem_shared_secret: bytes, rho: bytes) -> bytes:
    if type(secret) is not bytes or len(secret) != 64:
        raise ValueError("spend secret must be exactly 64 bytes")
    if type(kem_shared_secret) is not bytes or len(kem_shared_secret) != 32:
        raise ValueError("KEM shared secret must be exactly 32 bytes")
    if type(rho) is not bytes or len(rho) != 64:
        raise ValueError("rho must be exactly 64 bytes")
    return shake_frame(NULLIFIER, secret, kem_shared_secret, rho)


def output_leaf(commitment: bytes, kem_ciphertext: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    if type(commitment) is not bytes or len(commitment) != 64:
        raise ValueError("commitment must be 64 bytes")
    if type(kem_ciphertext) is not bytes or len(kem_ciphertext) != 1088:
        raise ValueError("ML-KEM-768 ciphertext must be 1088 bytes")
    if type(nonce) is not bytes or len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be 12 bytes")
    if type(ciphertext) is not bytes or not 156 <= len(ciphertext) <= 668:
        raise ValueError("experimental-v1 ciphertext must be 156..668 bytes")
    return shake_frame(OUTPUT_LEAF, commitment, kem_ciphertext, nonce, ciphertext)


def note_kdf(kem_shared_secret: bytes, kem_ciphertext: bytes, commitment: bytes) -> bytes:
    if type(kem_shared_secret) is not bytes or len(kem_shared_secret) != 32:
        raise ValueError("KEM shared secret must be 32 bytes")
    if type(kem_ciphertext) is not bytes or len(kem_ciphertext) != 1088:
        raise ValueError("ML-KEM-768 ciphertext must be 1088 bytes")
    if type(commitment) is not bytes or len(commitment) != 64:
        raise ValueError("commitment must be 64 bytes")
    return shake_frame(NOTE_KDF, kem_shared_secret, kem_ciphertext, commitment, output_length=32)
