from concurrent.futures import ThreadPoolExecutor

import pytest

from radix_core.crypto import note_kdf
from radix_core.memo import encode_plaintext_v1
from radix_core.cryptography_backend import (
    CryptographyAes256GcmProvider,
    CryptographyMlKem768Provider,
    validate_mlkem768_public_key,
)
from radix_core.providers import (
    AeadAuthenticationError,
    AeadNonceRegistry,
    CryptoBackendError,
    NonceRegistryFullError,
    NonceRegistryStorageError,
    NonceReuseError,
    decapsulate_v1,
    encapsulate_v1,
    encrypt_note_v1,
    generate_keypair_v1,
)


def test_real_mlkem768_keygen_encapsulate_decapsulate_and_seed_restore():
    provider = CryptographyMlKem768Provider()
    keypair = generate_keypair_v1(provider)
    assert len(keypair.public_key) == 1184
    assert len(keypair.decapsulation_key) == 64  # pyca's FIPS 203 d||z seed representation

    encapsulation = encapsulate_v1(provider, keypair.public_key)
    assert len(encapsulation.ciphertext) == 1088
    assert len(encapsulation.shared_secret) == 32
    restored_secret = decapsulate_v1(
        CryptographyMlKem768Provider(), keypair.decapsulation_key, encapsulation.ciphertext
    )
    assert restored_secret == encapsulation.shared_secret

    # FIPS 203 decapsulation uses implicit rejection: a malformed-but-correctly-sized
    # ciphertext produces a secret, while the authenticated note layer rejects it.
    mutated = bytearray(encapsulation.ciphertext)
    mutated[0] ^= 1
    rejected_secret = decapsulate_v1(provider, keypair.decapsulation_key, bytes(mutated))
    assert len(rejected_secret) == 32
    assert rejected_secret != encapsulation.shared_secret


def test_real_mlkem_backend_rejects_noncanonical_public_encoding_and_mismatched_keys():
    provider = CryptographyMlKem768Provider()
    keypair = provider.generate_keypair()
    validate_mlkem768_public_key(keypair[0])
    provider.validate_keypair(*keypair)

    # The first packed 12-bit coefficient is set to q (3329), which is not
    # canonical; length-only parsing must not accept it.
    malformed = bytearray(keypair[0])
    malformed[0] = 0x01
    malformed[1] = (malformed[1] & 0xF0) | 0x0D
    with pytest.raises(ValueError, match="noncanonical polynomial coefficient"):
        validate_mlkem768_public_key(bytes(malformed))
    with pytest.raises(ValueError, match="noncanonical polynomial coefficient"):
        validate_mlkem768_public_key(b"\xff" * 1184)
    with pytest.raises(ValueError, match="exactly 1184"):
        validate_mlkem768_public_key(b"p" * 1183)

    other_public, _ = provider.generate_keypair()
    with pytest.raises(ValueError, match="does not match"):
        provider.validate_keypair(other_public, keypair[1])
    with pytest.raises(ValueError, match="exactly 64"):
        provider.validate_keypair(keypair[0], b"short")


def test_real_aes256_gcm_matches_nist_empty_plaintext_tag_and_authenticates():
    provider = CryptographyAes256GcmProvider()
    key = b"\x00" * 32
    nonce = b"\x00" * 12
    # NIST AES-256-GCM test vector for empty plaintext and empty AAD.
    assert provider.encrypt(key, nonce, b"", b"").hex() == "530f8afbc74536b9a963b4f1c4cb738b"

    plaintext = b"radix note payload"
    associated_data = b"radix test aad"
    ciphertext = provider.encrypt(key, nonce, plaintext, associated_data)
    assert provider.decrypt(key, nonce, ciphertext, associated_data) == plaintext
    altered = bytearray(ciphertext)
    altered[-1] ^= 1
    with pytest.raises(AeadAuthenticationError):
        provider.decrypt(key, nonce, bytes(altered), associated_data)
    with pytest.raises(AeadAuthenticationError):
        provider.decrypt(key, nonce, ciphertext, b"different aad")
    with pytest.raises(ValueError, match="nonce"):
        provider.encrypt(key, b"bad", plaintext, associated_data)


def test_persistent_nonce_reservation_survives_registry_recreation(tmp_path):
    database = tmp_path / "radix-nonces.sqlite3"
    first = AeadNonceRegistry(max_entries=None, database_path=database)
    key, nonce = b"k" * 32, b"n" * 12
    first.reserve(key, nonce)

    reopened = AeadNonceRegistry(max_entries=None, database_path=database)
    with pytest.raises(NonceReuseError, match="already been reserved"):
        reopened.reserve(key, nonce)
    # The uniqueness key is the AES key/nonce pair, not either field alone.
    reopened.reserve(key, b"o" * 12)
    reopened.reserve(b"x" * 32, nonce)


def test_persistent_nonce_reservation_is_atomic_across_registry_instances(tmp_path):
    database = tmp_path / "radix-shared-nonces.sqlite3"
    registries = [
        AeadNonceRegistry(max_entries=None, database_path=database),
        AeadNonceRegistry(max_entries=None, database_path=database),
    ]

    def reserve(registry):
        try:
            registry.reserve(b"k" * 32, b"n" * 12)
            return "reserved"
        except NonceReuseError:
            return "duplicate"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(reserve, registries))
    assert sorted(results) == ["duplicate", "reserved"]


def test_persistent_nonce_registry_burns_before_failure_and_never_evicts(tmp_path):
    database = tmp_path / "bounded-nonces.sqlite3"
    first = AeadNonceRegistry(max_entries=1, database_path=database)
    first.reserve(b"k" * 32, b"n" * 12)
    reopened = AeadNonceRegistry(max_entries=1, database_path=database)
    with pytest.raises(NonceReuseError):
        reopened.reserve(b"k" * 32, b"n" * 12)
    with pytest.raises(NonceRegistryFullError):
        reopened.reserve(b"k" * 32, b"o" * 12)


def test_persistent_registry_rejects_ephemeral_or_corrupt_storage(tmp_path):
    with pytest.raises(ValueError, match="durable filesystem path"):
        AeadNonceRegistry(database_path=":memory:")

    corrupt = tmp_path / "not-a-database.sqlite3"
    corrupt.write_bytes(b"not sqlite")
    with pytest.raises(NonceRegistryStorageError, match="initialize"):
        AeadNonceRegistry(database_path=corrupt)


def test_persistent_nonce_is_burned_before_aead_failure(tmp_path):
    class FailingAeadProvider:
        def encrypt(self, key, nonce, plaintext, associated_data):
            raise OSError("simulated backend failure")

    database = tmp_path / "burned-nonces.sqlite3"
    registry = AeadNonceRegistry(max_entries=None, database_path=database)
    shared_secret = b"s" * 32
    kem_ciphertext = b"c" * 1088
    commitment = b"m" * 64
    nonce = b"n" * 12
    plaintext = encode_plaintext_v1(1, b"r" * 64, b"x" * 64, b"")
    key = note_kdf(shared_secret, kem_ciphertext, commitment)

    with pytest.raises(CryptoBackendError, match="encryption failed"):
        encrypt_note_v1(
            FailingAeadProvider(),
            shared_secret,
            kem_ciphertext,
            commitment,
            nonce,
            plaintext,
            nonce_registry=registry,
        )
    reopened = AeadNonceRegistry(max_entries=None, database_path=database)
    with pytest.raises(NonceReuseError):
        reopened.reserve(key, nonce)
