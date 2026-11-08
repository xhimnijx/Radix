import pytest

from radix_core.crypto import note_kdf
from radix_core.memo import encode_plaintext_v1
from radix_core.providers import (
    AeadAuthenticationError,
    AeadNonceRegistry,
    CryptoBackendError,
    NonceRegistryFullError,
    NonceReuseError,
    decapsulate_v1,
    generate_keypair_v1,
    decrypt_note_v1,
    encapsulate_v1,
    encrypt_note_v1,
    note_aad_v1,
)


class FakeKemProvider:
    def encapsulate(self, public_key):
        return b"c" * 1088, b"s" * 32

    def decapsulate(self, decapsulation_key, ciphertext):
        return b"s" * 32


class FakeKemKeygenProvider:
    def __init__(self, result):
        self.result = result

    def generate_keypair(self):
        return self.result


class BadKemProvider:
    def __init__(self, result):
        self.result = result

    def encapsulate(self, public_key):
        return self.result

    def decapsulate(self, decapsulation_key, ciphertext):
        return b"short"


KEM_CIPHERTEXT = b"c" * 1088
SHARED_SECRET = b"s" * 32
COMMITMENT = b"m" * 64
NONCE = b"n" * 12


class FakeAeadProvider:
    def __init__(self):
        self.last_aad = None
        self.last_key = None
        self.reject = False
        self.encrypt_calls = 0

    def encrypt(self, key, nonce, plaintext, associated_data):
        self.encrypt_calls += 1
        self.last_key = key
        self.last_aad = associated_data
        return plaintext + b"t" * 16

    def decrypt(self, key, nonce, ciphertext, associated_data):
        self.last_key = key
        self.last_aad = associated_data
        if self.reject:
            raise AeadAuthenticationError("authentication failed")
        return ciphertext[:-16]


def note_plaintext(memo=b"demo"):
    return encode_plaintext_v1(23, b"r" * 64, b"x" * 64, memo)


def test_mlkem_adapter_contract_checks_shapes_and_fixed_lengths():
    provider = FakeKemProvider()
    encapsulation = encapsulate_v1(provider, b"p" * 1184)
    assert encapsulation.ciphertext == b"c" * 1088
    assert encapsulation.shared_secret == b"s" * 32
    assert decapsulate_v1(provider, b"k" * 64, encapsulation.ciphertext) == b"s" * 32

    with pytest.raises(ValueError, match="public key"):
        encapsulate_v1(provider, b"p")
    with pytest.raises(ValueError, match="private seed"):
        decapsulate_v1(provider, b"k", b"c" * 1088)
    with pytest.raises(CryptoBackendError, match="2-tuple"):
        encapsulate_v1(BadKemProvider([b"c" * 1088, b"s" * 32]), b"p" * 1184)
    with pytest.raises(CryptoBackendError, match="invalid output"):
        encapsulate_v1(BadKemProvider((b"c", b"s" * 32)), b"p" * 1184)
    with pytest.raises(CryptoBackendError, match="did not return"):
        decapsulate_v1(BadKemProvider(None), b"k" * 64, b"c" * 1088)


def test_mlkem_key_generation_adapter_checks_return_tuple_and_key_shapes():
    keypair = generate_keypair_v1(
        FakeKemKeygenProvider((b"p" * 1184, b"d" * 64))
    )
    assert keypair.public_key == b"p" * 1184
    assert keypair.decapsulation_key == b"d" * 64

    with pytest.raises(CryptoBackendError, match="2-tuple"):
        generate_keypair_v1(FakeKemKeygenProvider([b"p" * 1184, b"d" * 64]))
    with pytest.raises(CryptoBackendError, match="invalid output"):
        generate_keypair_v1(FakeKemKeygenProvider((b"p", b"d" * 64)))
    with pytest.raises(CryptoBackendError, match="no usable generate_keypair"):
        generate_keypair_v1(BadKemProvider(None))

    class BrokenKeygenProvider:
        def generate_keypair(self):
            raise OSError("random source unavailable")

    with pytest.raises(CryptoBackendError, match=r"key generation failed \(OSError\)"):
        generate_keypair_v1(BrokenKeygenProvider())


def test_aes_gcm_v1_adapter_derives_exact_kdf_and_aad_and_checks_roundtrip():

    provider = FakeAeadProvider()
    plaintext = note_plaintext()
    ciphertext = encrypt_note_v1(
        provider,
        SHARED_SECRET,
        KEM_CIPHERTEXT,
        COMMITMENT,
        NONCE,
        plaintext,
        nonce_registry=AeadNonceRegistry(),
    )
    assert len(ciphertext) == len(plaintext) + 16
    assert provider.last_key == note_kdf(SHARED_SECRET, KEM_CIPHERTEXT, COMMITMENT)
    assert provider.last_aad == b"\x01" + COMMITMENT + KEM_CIPHERTEXT
    assert note_aad_v1(COMMITMENT, KEM_CIPHERTEXT) == provider.last_aad

    decrypted = decrypt_note_v1(
        provider, SHARED_SECRET, KEM_CIPHERTEXT, COMMITMENT, NONCE, ciphertext
    )
    assert decrypted == plaintext
    assert provider.last_key == note_kdf(SHARED_SECRET, KEM_CIPHERTEXT, COMMITMENT)
    assert provider.last_aad == b"\x01" + COMMITMENT + KEM_CIPHERTEXT


def test_aead_contract_rejects_noncanonical_inputs_and_backend_outputs():
    provider = FakeAeadProvider()
    with pytest.raises(ValueError, match="nonce"):
        encrypt_note_v1(
            provider, SHARED_SECRET, KEM_CIPHERTEXT, COMMITMENT, b"n", note_plaintext(),
            nonce_registry=AeadNonceRegistry(),
        )
    with pytest.raises(ValueError, match="commitment"):
        encrypt_note_v1(
            provider, SHARED_SECRET, KEM_CIPHERTEXT, b"bad", NONCE, note_plaintext(),
            nonce_registry=AeadNonceRegistry(),
        )
    with pytest.raises(ValueError, match="noncanonical"):
        encrypt_note_v1(provider, SHARED_SECRET, KEM_CIPHERTEXT, COMMITMENT, NONCE, b"x" * 140)

    class BadLengthAead:
        def encrypt(self, key, nonce, plaintext, associated_data):
            return b"short"

    with pytest.raises(CryptoBackendError, match="ciphertext length"):
        encrypt_note_v1(
            BadLengthAead(),
            SHARED_SECRET,
            KEM_CIPHERTEXT,
            COMMITMENT,
            NONCE,
            note_plaintext(),
            nonce_registry=AeadNonceRegistry(),
        )


def test_aead_authentication_errors_and_noncanonical_backend_plaintext_fail_closed():
    provider = FakeAeadProvider()
    ciphertext = encrypt_note_v1(
        provider,
        SHARED_SECRET,
        KEM_CIPHERTEXT,
        COMMITMENT,
        NONCE,
        note_plaintext(),
        nonce_registry=AeadNonceRegistry(),
    )
    provider.reject = True
    with pytest.raises(AeadAuthenticationError, match="authentication failed"):
        decrypt_note_v1(provider, SHARED_SECRET, KEM_CIPHERTEXT, COMMITMENT, NONCE, ciphertext)

    class NoncanonicalAead:
        def decrypt(self, key, nonce, ciphertext, associated_data):
            return b"x" * (len(ciphertext) - 16)

    with pytest.raises(CryptoBackendError, match="noncanonical note plaintext"):
        decrypt_note_v1(
            NoncanonicalAead(), SHARED_SECRET, KEM_CIPHERTEXT, COMMITMENT, NONCE, ciphertext
        )


def test_nonce_registry_rejects_reuse_before_calling_aead():
    provider = FakeAeadProvider()
    registry = AeadNonceRegistry()
    args = (SHARED_SECRET, KEM_CIPHERTEXT, COMMITMENT, NONCE, note_plaintext())

    encrypt_note_v1(provider, *args, nonce_registry=registry)
    with pytest.raises(NonceReuseError, match="already been reserved"):
        encrypt_note_v1(provider, *args, nonce_registry=registry)
    assert provider.encrypt_calls == 1

    # Nonce reuse across distinct derived AES keys is a different pair.
    encrypt_note_v1(
        provider,
        b"q" * 32,
        KEM_CIPHERTEXT,
        COMMITMENT,
        NONCE,
        note_plaintext(),
        nonce_registry=registry,
    )
    assert provider.encrypt_calls == 2


def test_nonce_is_burned_on_backend_failure_and_capacity_never_evicts():
    registry = AeadNonceRegistry(max_entries=1)

    class BrokenAead:
        def encrypt(self, key, nonce, plaintext, associated_data):
            raise OSError("backend failed")

    args = (SHARED_SECRET, KEM_CIPHERTEXT, COMMITMENT, NONCE, note_plaintext())
    with pytest.raises(CryptoBackendError, match="encryption failed"):
        encrypt_note_v1(BrokenAead(), *args, nonce_registry=registry)
    with pytest.raises(NonceReuseError):
        encrypt_note_v1(FakeAeadProvider(), *args, nonce_registry=registry)

    other_nonce = b"o" * 12
    other_args = (SHARED_SECRET, KEM_CIPHERTEXT, COMMITMENT, other_nonce, note_plaintext())
    with pytest.raises(NonceRegistryFullError, match="no entries were evicted"):
        encrypt_note_v1(
            FakeAeadProvider(), *other_args, nonce_registry=registry
        )


def test_nonce_registry_is_atomic_under_concurrent_encryptions():
    from concurrent.futures import ThreadPoolExecutor

    provider = FakeAeadProvider()
    registry = AeadNonceRegistry()
    args = (SHARED_SECRET, KEM_CIPHERTEXT, COMMITMENT, NONCE, note_plaintext())

    def attempt():
        try:
            encrypt_note_v1(provider, *args, nonce_registry=registry)
        except NonceReuseError:
            return "duplicate"
        return "encrypted"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: attempt(), range(2)))
    assert sorted(results) == ["duplicate", "encrypted"]
    assert provider.encrypt_calls == 1


def test_default_nonce_registry_guards_normal_api_use():
    shared_secret = b"z" * 32
    kem_ciphertext = b"z" * 1088
    commitment = b"z" * 64
    nonce = b"z" * 12
    plaintext = note_plaintext()
    provider = FakeAeadProvider()

    encrypt_note_v1(provider, shared_secret, kem_ciphertext, commitment, nonce, plaintext)
    with pytest.raises(NonceReuseError):
        encrypt_note_v1(provider, shared_secret, kem_ciphertext, commitment, nonce, plaintext)
    assert provider.encrypt_calls == 1
