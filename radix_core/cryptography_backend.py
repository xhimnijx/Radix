"""Concrete experimental-v1 ML-KEM-768 and AES-256-GCM adapters.

Backed by pyca/cryptography 50.x. ML-KEM private material is serialized as
FIPS 203's 64-byte key-generation seed (d || z), not the expanded 2400-byte
DecapsulationKey encoding. This is a reference integration, not a certified or
independently reviewed deployment backend.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .providers import (
    AES256_KEY_BYTES,
    AES_GCM_NONCE_BYTES,
    AES_GCM_TAG_BYTES,
    MLKEM768_CIPHERTEXT_BYTES,
    MLKEM768_PRIVATE_SEED_BYTES,
    MLKEM768_PUBLIC_KEY_BYTES,
    AeadAuthenticationError,
    CryptoBackendError,
)

_MLKEM_Q = 3329
_MLKEM_POLYVEC_BYTES = 3 * 384


def validate_mlkem768_public_key(public_key: bytes) -> None:
    """Reject wrong-size/noncanonical FIPS 203 ML-KEM-768 public encodings.

    The first 1152 bytes encode three polynomials with paired 12-bit
    coefficients. Every coefficient must be less than q=3329; the final 32
    bytes are rho. The cryptography parser is then used as a second check.
    This validates encoding, not possession of a corresponding secret key.
    """
    if type(public_key) is not bytes or len(public_key) != MLKEM768_PUBLIC_KEY_BYTES:
        raise ValueError("ML-KEM-768 public key must be exactly 1184 bytes")
    for offset in range(0, _MLKEM_POLYVEC_BYTES, 3):
        byte0, byte1, byte2 = public_key[offset : offset + 3]
        coefficient0 = byte0 | ((byte1 & 0x0F) << 8)
        coefficient1 = (byte1 >> 4) | (byte2 << 4)
        if coefficient0 >= _MLKEM_Q or coefficient1 >= _MLKEM_Q:
            raise ValueError("ML-KEM-768 public key has a noncanonical polynomial coefficient")
    try:
        imported = MLKEM768PublicKey.from_public_bytes(public_key)
        if imported.public_bytes_raw() != public_key:
            raise ValueError("ML-KEM-768 public key is not canonically encoded")
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError("ML-KEM-768 public key is rejected by the cryptography backend") from exc


class CryptographyMlKem768Provider:
    """FIPS 203 ML-KEM-768 using pyca/cryptography's OpenSSL-backed API.

    The private bytes are the backend's 64-byte ``d || z`` seed. ``generate``
    and encapsulation use cryptography/OpenSSL's CSPRNG. Decapsulation inherits
    that backend's implicit-rejection behavior for fixed-size ciphertexts.
    """

    __slots__ = ()

    @staticmethod
    def validate_public_key(public_key: bytes) -> None:
        validate_mlkem768_public_key(public_key)

    @staticmethod
    def validate_keypair(public_key: bytes, decapsulation_key: bytes) -> None:
        validate_mlkem768_public_key(public_key)
        if type(decapsulation_key) is not bytes or len(decapsulation_key) != MLKEM768_PRIVATE_SEED_BYTES:
            raise ValueError("ML-KEM-768 private seed must be exactly 64 bytes")
        try:
            private_key = MLKEM768PrivateKey.from_seed_bytes(decapsulation_key)
            derived_public_key = private_key.public_key().public_bytes_raw()
        except (ValueError, UnsupportedAlgorithm) as exc:
            raise ValueError("ML-KEM-768 private seed is rejected by the backend") from exc
        if derived_public_key != public_key:
            raise ValueError("ML-KEM-768 public/private key pair does not match")

    def generate_keypair(self) -> tuple[bytes, bytes]:
        try:
            private_key = MLKEM768PrivateKey.generate()
            public_key = private_key.public_key().public_bytes_raw()
            private_seed = private_key.private_bytes_raw()
            self.validate_keypair(public_key, private_seed)
            return public_key, private_seed
        except (ValueError, UnsupportedAlgorithm) as exc:
            raise CryptoBackendError(f"ML-KEM-768 key generation/validation failed ({type(exc).__name__})") from exc

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        try:
            validate_mlkem768_public_key(public_key)
            imported = MLKEM768PublicKey.from_public_bytes(public_key)
            shared_secret, ciphertext = imported.encapsulate()
        except (ValueError, UnsupportedAlgorithm) as exc:
            raise CryptoBackendError(f"ML-KEM-768 public-key import/encapsulation failed ({type(exc).__name__})") from exc
        return ciphertext, shared_secret

    def decapsulate(self, decapsulation_key: bytes, ciphertext: bytes) -> bytes:
        if type(decapsulation_key) is not bytes or len(decapsulation_key) != MLKEM768_PRIVATE_SEED_BYTES:
            raise ValueError("ML-KEM-768 private seed must be exactly 64 bytes")
        if type(ciphertext) is not bytes or len(ciphertext) != MLKEM768_CIPHERTEXT_BYTES:
            raise ValueError("ML-KEM-768 ciphertext must be exactly 1088 bytes")
        try:
            private_key = MLKEM768PrivateKey.from_seed_bytes(decapsulation_key)
            return private_key.decapsulate(ciphertext)
        except (ValueError, UnsupportedAlgorithm) as exc:
            raise CryptoBackendError(f"ML-KEM-768 decapsulation failed ({type(exc).__name__})") from exc


class CryptographyAes256GcmProvider:
    """AES-256-GCM adapter with ciphertext||tag serialization."""

    __slots__ = ()

    @staticmethod
    def _validate_inputs(key: bytes, nonce: bytes, data: bytes, associated_data: bytes) -> None:
        if type(key) is not bytes or len(key) != AES256_KEY_BYTES:
            raise ValueError("AES-256 key must be exactly 32 bytes")
        if type(nonce) is not bytes or len(nonce) != AES_GCM_NONCE_BYTES:
            raise ValueError("AES-GCM nonce must be exactly 12 bytes")
        if type(data) is not bytes or type(associated_data) is not bytes:
            raise ValueError("AES-GCM data and associated data must be bytes")

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
        self._validate_inputs(key, nonce, plaintext, associated_data)
        try:
            result = AESGCM(key).encrypt(nonce, plaintext, associated_data)
        except (ValueError, UnsupportedAlgorithm) as exc:
            raise CryptoBackendError(f"AES-256-GCM encryption failed ({type(exc).__name__})") from exc
        if type(result) is not bytes or len(result) != len(plaintext) + AES_GCM_TAG_BYTES:
            raise CryptoBackendError("AES-256-GCM returned a noncanonical ciphertext length")
        return result

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
        self._validate_inputs(key, nonce, ciphertext, associated_data)
        if len(ciphertext) < AES_GCM_TAG_BYTES:
            raise ValueError("AES-GCM ciphertext must include the 16-byte tag")
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
        except InvalidTag as exc:
            raise AeadAuthenticationError("AES-256-GCM authentication failed") from exc
        except (ValueError, UnsupportedAlgorithm) as exc:
            raise CryptoBackendError(f"AES-256-GCM decryption failed ({type(exc).__name__})") from exc
