"""Fail-closed interfaces and nonce lifecycle for experimental-v1 crypto.

This module validates provider boundaries, enforces experimental-v1 KDF/AAD
framing, and offers both process-local and SQLite-persistent AES-GCM nonce
registries. Concrete cryptography adapters live in ``cryptography_backend``.
Nothing here certifies the host entropy source, protects key memory, or makes a
production-security claim. Provider adapters are trusted, key-bearing local
boundaries, not remote-service abstractions: KEM decapsulation receives private
key bytes, and AEAD receives shared keys and plaintext. Remote/untrusted
providers can disclose keys, note contents, scan matches, and request metadata;
this API supplies no isolation or metadata-hiding layer.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from dataclasses import dataclass
from os import PathLike
from typing import Protocol

from .crypto import SHARED_SECRET_BYTES, note_kdf
from .memo import decode_plaintext_v1

MLKEM768_PUBLIC_KEY_BYTES = 1184
# pyca/cryptography persists FIPS 203's d||z key-generation seed. It expands
# this to the 2400-byte DecapsulationKey internally when restoring the key.
MLKEM768_PRIVATE_SEED_BYTES = 64
MLKEM768_EXPANDED_DECAPSULATION_KEY_BYTES = 2400
MLKEM768_DECAPSULATION_KEY_BYTES = MLKEM768_PRIVATE_SEED_BYTES
MLKEM768_CIPHERTEXT_BYTES = 1088
AES256_KEY_BYTES = 32
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16


class CryptoBackendError(RuntimeError):
    """A crypto provider failed or violated its declared API contract."""


class AeadAuthenticationError(CryptoBackendError):
    """An AEAD provider reports a ciphertext/tag authentication rejection."""


class NotePlaintextError(CryptoBackendError):
    """A ciphertext authenticated but did not decode as a canonical note plaintext.

    This is attacker-supplied data, not an infrastructure fault: any third party
    can construct a well-formed ciphertext whose plaintext fails the note rules
    (for example ``value == 0``). Batch scanners must treat it as a non-match,
    never as a fatal error, or a single crafted output can halt a wallet.
    """


class NonceReuseError(RuntimeError):
    """An AES-GCM key/nonce pair was already reserved in this registry."""


class NonceRegistryFullError(RuntimeError):
    """The bounded nonce registry is full; it never evicts."""


class NonceRegistryStorageError(RuntimeError):
    """A persistent nonce registry could not safely reserve a pair."""


class AeadNonceRegistry:
    """Nonce-use registry; optionally durable across process restarts.

    With no ``database_path``, reservations are thread-safe and process-local.
    With a filesystem path, each reservation is an SQLite transaction in WAL
    mode with ``synchronous=FULL`` and a unique fingerprint key, so separate
    instances/processes cannot successfully reserve the same pair twice. The
    record is committed before encryption and is never rolled back/evicted.
    Only domain-separated SHA-256 fingerprints are stored, never raw keys.

    Persistent mode assumes the database is on a local filesystem and is not
    deleted, restored to an older backup, or concurrently replaced. Those
    lifecycle failures cannot be detected by this helper.
    """

    _FINGERPRINT_DOMAIN = b"RADIX/AES-256-GCM/NONCE-REGISTRY/V1"

    def __init__(
        self,
        max_entries: int | None = None,
        *,
        database_path: str | PathLike[str] | None = None,
    ) -> None:
        if max_entries is not None and (type(max_entries) is not int or max_entries <= 0):
            raise ValueError("nonce registry capacity must be a positive integer or None")
        if database_path is not None:
            if not isinstance(database_path, (str, PathLike)):
                raise ValueError("nonce registry database path must be a filesystem path")
            database_path = os.fspath(database_path)
            if not database_path or database_path == ":memory:":
                raise ValueError("persistent nonce registry requires a durable filesystem path")
        self._max_entries = max_entries
        self._database_path = database_path
        self._fingerprints: set[bytes] = set()
        self._lock = threading.Lock()
        if self._database_path is not None:
            self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        assert self._database_path is not None
        connection = sqlite3.connect(self._database_path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize_database(self) -> None:
        try:
            connection = sqlite3.connect(self._database_path, timeout=30, isolation_level=None)
            try:
                mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
                if mode is None or mode[0].lower() != "wal":
                    raise sqlite3.DatabaseError("SQLite WAL mode is unavailable")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS radix_aead_nonce_reservations "
                    "(fingerprint BLOB PRIMARY KEY CHECK(length(fingerprint)=32)) WITHOUT ROWID"
                )
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise NonceRegistryStorageError("could not initialize durable nonce registry") from exc

    def _reserve_persistent(self, fingerprint: bytes) -> None:
        try:
            connection = self._connect()
        except sqlite3.Error as exc:
            raise NonceRegistryStorageError("could not open durable nonce registry") from exc
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT INTO radix_aead_nonce_reservations(fingerprint) VALUES (?)",
                    (fingerprint,),
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise NonceReuseError("AES-GCM key/nonce pair has already been reserved") from exc
            if self._max_entries is not None:
                count = connection.execute(
                    "SELECT count(*) FROM radix_aead_nonce_reservations"
                ).fetchone()[0]
                if count > self._max_entries:
                    connection.execute("ROLLBACK")
                    raise NonceRegistryFullError("nonce registry is full; no entries were evicted")
            connection.execute("COMMIT")
        except (NonceReuseError, NonceRegistryFullError):
            raise
        except sqlite3.Error as exc:
            try:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise NonceRegistryStorageError("could not durably reserve AES-GCM nonce pair") from exc
        finally:
            connection.close()

    @property
    def is_persistent(self) -> bool:
        """Whether this registry commits reservations to its SQLite database."""
        return self._database_path is not None

    def reserve(self, key: bytes, nonce: bytes) -> None:
        if type(key) is not bytes or len(key) != AES256_KEY_BYTES:
            raise ValueError("AES-256 key must be exactly 32 bytes")
        _validate_nonce(nonce)
        fingerprint = hashlib.sha256(self._FINGERPRINT_DOMAIN + key + nonce).digest()
        if self._database_path is not None:
            self._reserve_persistent(fingerprint)
            return
        with self._lock:
            if fingerprint in self._fingerprints:
                raise NonceReuseError("AES-GCM key/nonce pair has already been reserved")
            if self._max_entries is not None and len(self._fingerprints) >= self._max_entries:
                raise NonceRegistryFullError("AES-GCM nonce registry is full; no entries were evicted")
            self._fingerprints.add(fingerprint)


_PROCESS_NONCE_REGISTRY = AeadNonceRegistry()


class MlKem768Provider(Protocol):
    """Adapter contract for FIPS 203 ML-KEM-768.

    Encapsulation must use a cryptographically secure random source. The
    decapsulator must implement FIPS 203 implicit rejection for fixed-length
    ciphertexts; callers must not treat a returned secret as proof of a valid
    recipient or a successful note decryption. Private-key bytes use the
    provider's documented representation; this prototype's concrete adapter
    stores the standardized 64-byte ``d || z`` key-generation seed. This adapter
    is a trusted key boundary: decapsulation receives raw private-key bytes and
    per-output ciphertexts, so it must not forward them to an untrusted remote
    service or log wallet scans.
    """

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return ``(ciphertext, shared_secret)``."""
        ...

    def decapsulate(self, decapsulation_key: bytes, ciphertext: bytes) -> bytes:
        """Return the 32-byte shared secret, including implicit rejection."""
        ...


class MlKem768KeygenProvider(Protocol):
    """Key-generation boundary for FIPS 203 ML-KEM-768.

    Implementations must use a cryptographically secure random source. Key
    bytes are provider-specific. If a provider supplies ``validate_keypair``,
    ``generate_keypair_v1`` invokes it after checking the returned shapes.
    This boundary does not establish secure key storage or zeroization.
    """

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Return ``(public_key, decapsulation_key)``."""
        ...


class Aes256GcmProvider(Protocol):
    """Adapter contract for AES-256-GCM; ciphertext includes its 16-byte tag.

    A decryption adapter must raise ``AeadAuthenticationError`` only when
    authentication/tag verification fails. Other provider faults must remain
    distinguishable as backend failures for local recovery logic. The adapter
    receives keys and, for encryption, plaintext; decryption also reveals
    plaintext to it. Do not implement this as an untrusted remote service.
    """

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
        ...

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
        ...


@dataclass(frozen=True)
class KemEncapsulation:
    ciphertext: bytes
    shared_secret: bytes

    def __post_init__(self) -> None:
        if type(self.ciphertext) is not bytes or len(self.ciphertext) != MLKEM768_CIPHERTEXT_BYTES:
            raise ValueError("ML-KEM-768 ciphertext must be exactly 1088 bytes")
        if type(self.shared_secret) is not bytes or len(self.shared_secret) != SHARED_SECRET_BYTES:
            raise ValueError("ML-KEM-768 shared secret must be exactly 32 bytes")


@dataclass(frozen=True)
class KemKeypairV1:
    public_key: bytes
    decapsulation_key: bytes

    def __post_init__(self) -> None:
        if type(self.public_key) is not bytes or len(self.public_key) != MLKEM768_PUBLIC_KEY_BYTES:
            raise ValueError("ML-KEM-768 public key must be exactly 1184 bytes")
        if type(self.decapsulation_key) is not bytes or len(self.decapsulation_key) != MLKEM768_DECAPSULATION_KEY_BYTES:
            raise ValueError("ML-KEM-768 private seed must be exactly 64 bytes")


def _provider_method(provider: object, name: str):
    try:
        method = getattr(provider, name)
    except Exception as exc:
        raise CryptoBackendError(f"provider has no usable {name} method") from exc
    if not callable(method):
        raise CryptoBackendError(f"provider has no usable {name} method")
    return method


def _backend_call(operation: str, method, *args):
    try:
        return method(*args)
    except Exception as exc:
        raise CryptoBackendError(f"{operation} failed ({type(exc).__name__})") from exc


def _aead_decrypt_call(method, *args):
    try:
        return method(*args)
    except AeadAuthenticationError:
        raise
    except Exception as exc:
        raise CryptoBackendError(f"AES-256-GCM decryption failed ({type(exc).__name__})") from exc


def generate_keypair_v1(provider: MlKem768KeygenProvider) -> KemKeypairV1:
    """Generate and shape-check one ML-KEM-768 keypair.

    The provider owns the CSPRNG and cryptographic implementation; only output
    type and length are checked here.
    """
    result = _backend_call(
        "ML-KEM-768 key generation",
        _provider_method(provider, "generate_keypair"),
    )
    if type(result) is not tuple or len(result) != 2:
        raise CryptoBackendError("ML-KEM-768 key generation must return a 2-tuple")
    try:
        keypair = KemKeypairV1(public_key=result[0], decapsulation_key=result[1])
    except (TypeError, ValueError) as exc:
        raise CryptoBackendError(f"ML-KEM-768 key generation returned invalid output: {exc}") from exc
    validator = getattr(provider, "validate_keypair", None)
    if validator is not None:
        if not callable(validator):
            raise CryptoBackendError("ML-KEM-768 keypair validator is not callable")
        _backend_call("ML-KEM-768 keypair validation", validator, keypair.public_key, keypair.decapsulation_key)
    return keypair


def encapsulate_v1(provider: MlKem768Provider, public_key: bytes) -> KemEncapsulation:
    if type(public_key) is not bytes or len(public_key) != MLKEM768_PUBLIC_KEY_BYTES:
        raise ValueError("ML-KEM-768 public key must be exactly 1184 bytes")
    result = _backend_call("ML-KEM-768 encapsulation", _provider_method(provider, "encapsulate"), public_key)
    if type(result) is not tuple or len(result) != 2:
        raise CryptoBackendError("ML-KEM-768 encapsulation must return a 2-tuple")
    try:
        return KemEncapsulation(ciphertext=result[0], shared_secret=result[1])
    except (TypeError, ValueError) as exc:
        raise CryptoBackendError(f"ML-KEM-768 encapsulation returned invalid output: {exc}") from exc


def decapsulate_v1(
    provider: MlKem768Provider,
    decapsulation_key: bytes,
    ciphertext: bytes,
) -> bytes:
    if type(decapsulation_key) is not bytes or len(decapsulation_key) != MLKEM768_DECAPSULATION_KEY_BYTES:
        raise ValueError("ML-KEM-768 private seed must be exactly 64 bytes")
    if type(ciphertext) is not bytes or len(ciphertext) != MLKEM768_CIPHERTEXT_BYTES:
        raise ValueError("ML-KEM-768 ciphertext must be exactly 1088 bytes")
    secret = _backend_call(
        "ML-KEM-768 decapsulation",
        _provider_method(provider, "decapsulate"),
        decapsulation_key,
        ciphertext,
    )
    if type(secret) is not bytes or len(secret) != SHARED_SECRET_BYTES:
        raise CryptoBackendError("ML-KEM-768 decapsulation did not return exactly 32 bytes")
    return secret


def note_aad_v1(commitment: bytes, kem_ciphertext: bytes) -> bytes:
    """Candidate-A experimental-v1 AAD: ``U8(1) || cm || ct_kem``."""
    if type(commitment) is not bytes or len(commitment) != 64:
        raise ValueError("note commitment must be exactly 64 bytes")
    if type(kem_ciphertext) is not bytes or len(kem_ciphertext) != MLKEM768_CIPHERTEXT_BYTES:
        raise ValueError("ML-KEM-768 ciphertext must be exactly 1088 bytes")
    return b"\x01" + commitment + kem_ciphertext


def _derive_note_key(shared_secret: bytes, kem_ciphertext: bytes, commitment: bytes) -> bytes:
    try:
        key = note_kdf(shared_secret, kem_ciphertext, commitment)
    except ValueError as exc:
        raise ValueError(f"invalid note KDF context: {exc}") from exc
    if type(key) is not bytes or len(key) != AES256_KEY_BYTES:
        raise CryptoBackendError("note KDF did not produce an AES-256 key")
    return key


def _validate_nonce(nonce: bytes) -> None:
    if type(nonce) is not bytes or len(nonce) != AES_GCM_NONCE_BYTES:
        raise ValueError("AES-GCM nonce must be exactly 12 bytes")


def encrypt_note_v1(
    provider: Aes256GcmProvider,
    shared_secret: bytes,
    kem_ciphertext: bytes,
    commitment: bytes,
    nonce: bytes,
    plaintext: bytes,
    *,
    nonce_registry: AeadNonceRegistry | None = None,
) -> bytes:
    """Derive v1 key/AAD and encrypt once per key/nonce registry reservation.

    The default registry is process-local and does not survive a restart. Pass
    an explicit persistent ``AeadNonceRegistry`` for committed cross-restart
    history; callers must protect it from deletion, cloning and rollback.
    """
    _validate_nonce(nonce)
    key = _derive_note_key(shared_secret, kem_ciphertext, commitment)
    associated_data = note_aad_v1(commitment, kem_ciphertext)
    if type(plaintext) is not bytes:
        raise ValueError("note plaintext must be bytes")
    decode_plaintext_v1(plaintext)
    registry = _PROCESS_NONCE_REGISTRY if nonce_registry is None else nonce_registry
    if type(registry) is not AeadNonceRegistry:
        raise ValueError("nonce registry must be the canonical AeadNonceRegistry type")
    encrypt_method = _provider_method(provider, "encrypt")
    AeadNonceRegistry.reserve(registry, key, nonce)
    ciphertext = _backend_call(
        "AES-256-GCM encryption",
        encrypt_method,
        key,
        nonce,
        plaintext,
        associated_data,
    )
    if type(ciphertext) is not bytes or len(ciphertext) != len(plaintext) + AES_GCM_TAG_BYTES:
        raise CryptoBackendError("AES-256-GCM returned a noncanonical ciphertext length")
    if not 156 <= len(ciphertext) <= 668:
        raise CryptoBackendError("AES-256-GCM ciphertext is outside experimental-v1 bounds")
    return ciphertext


def decrypt_note_v1(
    provider: Aes256GcmProvider,
    shared_secret: bytes,
    kem_ciphertext: bytes,
    commitment: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    """Derive the v1 key/AAD, authenticate, and parse the note plaintext.

    Authentication rejection is preserved as ``AeadAuthenticationError``;
    other provider errors are normalized to ``CryptoBackendError``. Callers
    should avoid exposing distinguishable failure details to a remote party.
    """
    _validate_nonce(nonce)
    key = _derive_note_key(shared_secret, kem_ciphertext, commitment)
    associated_data = note_aad_v1(commitment, kem_ciphertext)
    if type(ciphertext) is not bytes or not 156 <= len(ciphertext) <= 668:
        raise ValueError("experimental-v1 ciphertext length must be 156..668")
    plaintext = _aead_decrypt_call(
        _provider_method(provider, "decrypt"),
        key,
        nonce,
        ciphertext,
        associated_data,
    )
    if type(plaintext) is not bytes or len(plaintext) != len(ciphertext) - AES_GCM_TAG_BYTES:
        raise CryptoBackendError("AES-256-GCM returned a noncanonical plaintext length")
    try:
        decode_plaintext_v1(plaintext)
    except ValueError as exc:
        # Authenticated but non-canonical plaintext is attacker-controlled data,
        # not a backend fault. Keep it distinguishable so batch scanners can skip
        # it without conflating it with an infrastructure failure.
        raise NotePlaintextError("AES-256-GCM returned a noncanonical note plaintext") from exc
    return plaintext
