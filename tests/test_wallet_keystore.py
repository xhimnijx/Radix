import os

import pytest

from radix_core.cryptography_backend import CryptographyMlKem768Provider
from radix_core.providers import AeadNonceRegistry, NonceReuseError
from radix_core.wallet import generate_wallet_keys_v1
from radix_core.wallet_keystore import (
    MAX_WALLET_PASSWORD_BYTES,
    WalletStoreError,
    load_wallet_file_v1,
    open_wallet_keys_v1,
    save_wallet_file_v1,
    seal_wallet_keys_v1,
)


class RepeatingEntropy:
    def token_bytes(self, length):
        return b"s" * length


def test_wallet_envelope_roundtrip_wrong_password_and_tampering(tmp_path):
    provider = CryptographyMlKem768Provider()
    keys = generate_wallet_keys_v1(provider)
    registry = AeadNonceRegistry(
        max_entries=None,
        database_path=tmp_path / "wallet-envelope-nonces.sqlite3",
    )
    envelope = seal_wallet_keys_v1(
        keys,
        b"a sufficiently long test passphrase",
        kem_provider=provider,
        nonce_registry=registry,
    )

    restored = open_wallet_keys_v1(
        envelope,
        b"a sufficiently long test passphrase",
        kem_provider=provider,
    )
    assert restored == keys
    with pytest.raises(WalletStoreError, match="password is incorrect"):
        open_wallet_keys_v1(envelope, b"wrong password", kem_provider=provider)

    altered = bytearray(envelope)
    altered[-1] ^= 1
    with pytest.raises(WalletStoreError, match="malformed|authentication"):
        open_wallet_keys_v1(bytes(altered), b"a sufficiently long test passphrase", kem_provider=provider)
    with pytest.raises(WalletStoreError, match="malformed"):
        open_wallet_keys_v1(envelope + b"trailing", b"a sufficiently long test passphrase", kem_provider=provider)


def test_wallet_file_creation_is_exclusive_and_loads_the_same_keys(tmp_path):
    provider = CryptographyMlKem768Provider()
    keys = generate_wallet_keys_v1(provider)
    registry = AeadNonceRegistry(
        max_entries=None,
        database_path=tmp_path / "file-wallet-nonces.sqlite3",
    )
    path = tmp_path / "wallet.radix"
    save_wallet_file_v1(
        path,
        keys,
        b"passphrase for file backup",
        kem_provider=provider,
        nonce_registry=registry,
    )
    assert os.path.getsize(path) <= 2048
    restored = load_wallet_file_v1(path, b"passphrase for file backup", kem_provider=provider)
    assert restored == keys

    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        save_wallet_file_v1(
            path,
            keys,
            b"passphrase for file backup",
            kem_provider=provider,
            nonce_registry=registry,
        )
    assert path.read_bytes() == original


def test_password_inputs_are_bounded_before_wallet_kdf():
    provider = CryptographyMlKem768Provider()
    oversized_password = b"p" * (MAX_WALLET_PASSWORD_BYTES + 1)

    with pytest.raises(ValueError, match="must not exceed"):
        open_wallet_keys_v1(b"", oversized_password, kem_provider=provider)
    with pytest.raises(ValueError, match="must not exceed"):
        seal_wallet_keys_v1(
            None,
            oversized_password,
            kem_provider=provider,
            nonce_registry=None,
        )


def test_wallet_sealing_requires_durable_nonce_history_and_burns_before_use(tmp_path):
    provider = CryptographyMlKem768Provider()
    keys = generate_wallet_keys_v1(provider)
    with pytest.raises(ValueError, match="persistent"):
        seal_wallet_keys_v1(
            keys,
            b"password",
            kem_provider=provider,
            nonce_registry=AeadNonceRegistry(),
        )

    database = tmp_path / "wallet-repeated-entropy.sqlite3"
    persistent = AeadNonceRegistry(max_entries=None, database_path=database)
    entropy = RepeatingEntropy()
    seal_wallet_keys_v1(
        keys,
        b"password",
        kem_provider=provider,
        nonce_registry=persistent,
        entropy_source=entropy,
    )
    # Same salt + password derives the same AES key; same nonce is rejected
    # across instances, even though no second ciphertext was produced.
    reopened = AeadNonceRegistry(max_entries=None, database_path=database)
    with pytest.raises(NonceReuseError):
        seal_wallet_keys_v1(
            keys,
            b"password",
            kem_provider=provider,
            nonce_registry=reopened,
            entropy_source=entropy,
        )
