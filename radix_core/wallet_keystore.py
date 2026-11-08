"""Encrypted experimental-v1 wallet backup and exclusive file lifecycle.

The envelope encrypts the spend secret and ML-KEM seed with scrypt + AES-256-GCM.
Password inputs are bounded to 4 KiB before the fixed-cost scrypt invocation.
This is a small reference keystore, not a hardened wallet: passwords are caller
provided, Python cannot reliably zeroize secrets, and OS file permissions/backup
policy remain the caller's responsibility.
"""
from __future__ import annotations

import os
import stat
from os import PathLike

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .cryptography_backend import CryptographyMlKem768Provider
from .crypto import spend_public
from .encoding import decode_frame, frame
from .entropy import SYSTEM_ENTROPY, EntropySource, draw_aead_nonce_v1, draw_random_bytes
from .providers import AES256_KEY_BYTES, AeadNonceRegistry
from .wallet import WalletKeysV1

MAX_WALLET_PASSWORD_BYTES = 4_096
SALT_BYTES = 16
KEY_BYTES = AES256_KEY_BYTES
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1


def _secret_frame(spend_secret: bytes, viewing_public_key: bytes, decapsulation_key: bytes) -> bytes:
    return frame(
        "radix/wallet-secrets/v1",
        (spend_secret, viewing_public_key, decapsulation_key),
    )


def _aad(salt: bytes) -> bytes:
    return frame("radix/wallet-file-aad/v1", (salt,))


def _password_bytes(password: bytes) -> None:
    if type(password) is not bytes or not password:
        raise ValueError("wallet password must be nonempty bytes")
    if len(password) > MAX_WALLET_PASSWORD_BYTES:
        raise ValueError(
            f"wallet password must not exceed {MAX_WALLET_PASSWORD_BYTES} bytes"
        )


def _derive_key(password: bytes, salt: bytes) -> bytes:
    try:
        return Scrypt(salt=salt, length=KEY_BYTES, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(password)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise WalletStoreError("wallet password KDF failed") from exc


class WalletStoreError(ValueError):
    """Wallet envelope is malformed, unauthenticated, or internally inconsistent."""


def seal_wallet_keys_v1(
    keys: WalletKeysV1,
    password: bytes,
    *,
    kem_provider: CryptographyMlKem768Provider,
    nonce_registry: AeadNonceRegistry,
    entropy_source: EntropySource = SYSTEM_ENTROPY,
) -> bytes:
    """Encrypt wallet secrets; requires a durable nonce registry and burns use first."""
    _password_bytes(password)
    if not isinstance(nonce_registry, AeadNonceRegistry) or not nonce_registry.is_persistent:
        raise ValueError("wallet sealing requires a persistent AeadNonceRegistry")
    if type(keys) is not WalletKeysV1:
        raise ValueError("wallet keys must be a WalletKeysV1 record")
    if type(keys.spend_secret) is not bytes or len(keys.spend_secret) != 64:
        raise ValueError("spend secret must be exactly 64 bytes")
    if spend_public(keys.spend_secret) != keys.spend_public_key:
        raise ValueError("wallet spend public key does not match its secret")
    try:
        kem_provider.validate_keypair(keys.viewing_public_key, keys.decapsulation_key)
    except (TypeError, ValueError) as exc:
        raise ValueError("wallet ML-KEM keypair is invalid") from exc

    salt = draw_random_bytes(SALT_BYTES, entropy_source)
    nonce = draw_aead_nonce_v1(entropy_source)
    key = _derive_key(password, salt)
    nonce_registry.reserve(key, nonce)
    plaintext = _secret_frame(keys.spend_secret, keys.viewing_public_key, keys.decapsulation_key)
    try:
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, _aad(salt))
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise WalletStoreError("wallet encryption failed") from exc
    return frame("radix/wallet-file/v1", (salt, nonce, ciphertext))


def open_wallet_keys_v1(
    envelope: bytes,
    password: bytes,
    *,
    kem_provider: CryptographyMlKem768Provider,
) -> WalletKeysV1:
    """Authenticate/decrypt an envelope and revalidate its KEM pair."""
    _password_bytes(password)
    plaintext_length = len(_secret_frame(b"s" * 64, b"p" * 1184, b"d" * 64))
    try:
        salt, nonce, ciphertext = decode_frame(
            envelope,
            "radix/wallet-file/v1",
            (SALT_BYTES, 12, plaintext_length + 16),
        )
    except ValueError as exc:
        raise WalletStoreError("wallet envelope is malformed or noncanonical") from exc

    key = _derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, _aad(salt))
    except InvalidTag as exc:
        raise WalletStoreError("wallet password is incorrect or envelope authentication failed") from exc
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise WalletStoreError("wallet decryption failed") from exc

    try:
        spend_secret, viewing_public_key, decapsulation_key = decode_frame(
            plaintext,
            "radix/wallet-secrets/v1",
            (64, 1184, 64),
        )
        spend_public_key = spend_public(spend_secret)
        kem_provider.validate_keypair(viewing_public_key, decapsulation_key)
        return WalletKeysV1(
            spend_secret=spend_secret,
            spend_public_key=spend_public_key,
            viewing_public_key=viewing_public_key,
            decapsulation_key=decapsulation_key,
        )
    except (TypeError, ValueError) as exc:
        raise WalletStoreError("decrypted wallet keys are inconsistent or invalid") from exc


def save_wallet_file_v1(
    path: str | PathLike[str],
    keys: WalletKeysV1,
    password: bytes,
    *,
    kem_provider: CryptographyMlKem768Provider,
    nonce_registry: AeadNonceRegistry,
    entropy_source: EntropySource = SYSTEM_ENTROPY,
) -> None:
    """Create a new encrypted wallet file; never overwrite an existing file."""
    envelope = seal_wallet_keys_v1(
        keys,
        password,
        kem_provider=kem_provider,
        nonce_registry=nonce_registry,
        entropy_source=entropy_source,
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(envelope)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def load_wallet_file_v1(
    path: str | PathLike[str],
    password: bytes,
    *,
    kem_provider: CryptographyMlKem768Provider,
) -> WalletKeysV1:
    """Read a bounded regular file and open the authenticated wallet envelope."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 2048:
            raise WalletStoreError("wallet file must be a regular file no larger than 2048 bytes")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            envelope = source.read(2049)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(envelope) > 2048:
        raise WalletStoreError("wallet file exceeds the 2048-byte limit")
    return open_wallet_keys_v1(envelope, password, kem_provider=kem_provider)
