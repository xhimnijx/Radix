from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from radix_core.crypto import note_commitment, note_owner, nullifier, output_leaf, spend_public
from radix_core.cryptography_backend import CryptographyMlKem768Provider
from radix_core.encoding import U64_MAX
from radix_core.entropy import EntropyError
from radix_core.memo import encode_plaintext_v1
from radix_core.merkle import OutputTree
from radix_core.providers import (
    AeadAuthenticationError,
    AeadNonceRegistry,
    CryptoBackendError,
    encrypt_note_v1,
)
from radix_core.wallet import (
    MAX_OUTPUT_RAW_FIELD_BYTES,
    MAX_SCAN_CHUNK_AUTH_PATH_BYTES,
    MAX_SCAN_CHUNK_RAW_FIELD_BYTES,
    NoteRecoveryError,
    WalletKeysV1,
    WalletScanCursorSnapshotV1,
    WalletScanCursorV1,
    create_note_output_for_address_v1,
    create_note_output_to_v1,
    create_note_output_v1,
    generate_wallet_keys_v1,
    recover_note_v1,
    scan_authenticated_outputs_v1,
    scan_outputs_v1,
    serialize_wallet_address_v1,
)
from radix_core.wire import OutputRecord, parse_address, serialize_address


KEM_CIPHERTEXT = b"c" * 1088
SHARED_SECRET = b"s" * 32
SPEND_SECRET = b"w" * 64
NONCE = b"n" * 12
RHO = b"r" * 64
RANDOMNESS = b"x" * 64
VALID_VIEWING_PUBLIC_KEY, _ = CryptographyMlKem768Provider().generate_keypair()


class FakeKemProvider:
    def __init__(self):
        self.encapsulate_calls = 0

    def generate_keypair(self):
        return VALID_VIEWING_PUBLIC_KEY, b"d" * 64

    def encapsulate(self, public_key):
        self.encapsulate_calls += 1
        return KEM_CIPHERTEXT, SHARED_SECRET

    def decapsulate(self, decapsulation_key, ciphertext):
        return SHARED_SECRET


class FakeAeadProvider:
    def __init__(self, failure=None, reject_nonces=()):
        self.failure = failure
        self.reject_nonces = set(reject_nonces)
        self.encrypt_calls = 0

    def encrypt(self, key, nonce, plaintext, associated_data):
        self.encrypt_calls += 1
        return plaintext + b"t" * 16

    def decrypt(self, key, nonce, ciphertext, associated_data):
        if nonce in self.reject_nonces:
            raise AeadAuthenticationError("test non-recipient")
        if self.failure == "auth":
            raise AeadAuthenticationError("test authentication rejection")
        if self.failure == "backend":
            raise OSError("backend unavailable")
        return ciphertext[:-16]


def build_output(provider, *, public_commitment=None, nonce=NONCE):
    plaintext = encode_plaintext_v1(23, RHO, RANDOMNESS, b"wallet test")
    correct_commitment = note_commitment(
        note_owner(spend_public(SPEND_SECRET), SHARED_SECRET),
        23,
        RHO,
        RANDOMNESS,
    )
    ciphertext = encrypt_note_v1(
        provider,
        SHARED_SECRET,
        KEM_CIPHERTEXT,
        correct_commitment,
        nonce,
        plaintext,
        nonce_registry=AeadNonceRegistry(),
    )
    commitment = correct_commitment if public_commitment is None else public_commitment
    return OutputRecord(
        commitment=commitment,
        kem_ciphertext=KEM_CIPHERTEXT,
        nonce=nonce,
        ciphertext=ciphertext,
        leaf=output_leaf(commitment, KEM_CIPHERTEXT, nonce, ciphertext),
    )


def recover(provider, output, spend_secret=SPEND_SECRET):
    return recover_note_v1(
        FakeKemProvider(),
        provider,
        b"d" * 64,
        spend_secret,
        output,
    )


class FixedEntropy:
    def __init__(self, values):
        self.values = list(values)

    def token_bytes(self, length):
        return self.values.pop(0)


def test_wallet_key_generation_assembles_spend_and_kem_keys():
    spend_secret = b"k" * 64
    keys = generate_wallet_keys_v1(
        FakeKemProvider(),
        entropy_source=FixedEntropy([spend_secret]),
    )

    assert keys.spend_secret == spend_secret
    assert keys.spend_public_key == spend_public(spend_secret)
    assert keys.viewing_public_key == VALID_VIEWING_PUBLIC_KEY
    assert keys.decapsulation_key == b"d" * 64
    assert "k" * 64 not in repr(keys)
    assert "d" * 64 not in repr(keys)

    chain_id = b"c" * 32
    address = serialize_wallet_address_v1(keys, chain_id)
    assert parse_address(address, expected_chain_id=chain_id) == (
        chain_id, keys.spend_public_key, keys.viewing_public_key
    )
    mismatched = WalletKeysV1(
        keys.spend_secret, b"!" * 64, keys.viewing_public_key, keys.decapsulation_key
    )
    with pytest.raises(ValueError, match="does not match"):
        serialize_wallet_address_v1(mismatched, chain_id)
    with pytest.raises(ValueError, match="chain ID"):
        serialize_wallet_address_v1(keys, b"bad")


def test_wallet_creates_canonical_output_and_keeps_local_opening_for_recovery():
    kem = FakeKemProvider()
    aead = FakeAeadProvider()
    rho = b"a" * 64
    randomness = b"b" * 64
    nonce = b"c" * 12
    created = create_note_output_v1(
        kem,
        aead,
        bytes(1184),
        SPEND_SECRET,
        23,
        b"created in test",
        entropy_source=FixedEntropy([rho, randomness, nonce]),
        nonce_registry=AeadNonceRegistry(),
    )

    assert kem.encapsulate_calls == 1
    assert created.output.kem_ciphertext == KEM_CIPHERTEXT
    assert (created.value, created.rho, created.randomness, created.memo) == (
        23,
        rho,
        randomness,
        b"created in test",
    )
    recovered = recover(FakeAeadProvider(), created.output)
    assert recovered is not None
    assert (recovered.value, recovered.rho, recovered.randomness, recovered.memo) == (
        created.value,
        created.rho,
        created.randomness,
        created.memo,
    )
    assert recovered.nullifier == nullifier(SPEND_SECRET, SHARED_SECRET, rho)
    assert created.recipient_spend_public_key == spend_public(SPEND_SECRET)
    assert created.owner == note_owner(spend_public(SPEND_SECRET), SHARED_SECRET)
    assert created.kem_shared_secret == SHARED_SECRET
    assert SHARED_SECRET.hex() not in repr(created)


def test_wallet_creates_output_for_another_address_spend_key():
    kem = FakeKemProvider()
    aead = FakeAeadProvider()
    recipient_secret = b"z" * 64
    recipient_spend_public_key = spend_public(recipient_secret)
    rho = b"q" * 64
    randomness = b"v" * 64
    nonce = b"m" * 12

    created = create_note_output_to_v1(
        kem,
        aead,
        VALID_VIEWING_PUBLIC_KEY,
        recipient_spend_public_key,
        41,
        b"private transfer memo",
        entropy_source=FixedEntropy([rho, randomness, nonce]),
        nonce_registry=AeadNonceRegistry(),
    )

    expected_owner = note_owner(recipient_spend_public_key, SHARED_SECRET)
    assert created.owner == expected_owner
    assert created.recipient_spend_public_key == recipient_spend_public_key
    assert created.kem_shared_secret == SHARED_SECRET
    assert created.output.commitment == note_commitment(expected_owner, 41, rho, randomness)
    recovered = recover(FakeAeadProvider(), created.output, recipient_secret)
    assert recovered is not None
    assert (recovered.value, recovered.rho, recovered.randomness) == (41, rho, randomness)
    assert recipient_spend_public_key.hex() not in repr(created)
    assert SHARED_SECRET.hex() not in repr(created)

    with pytest.raises(ValueError, match="exactly 64 bytes"):
        create_note_output_to_v1(
            kem,
            aead,
            VALID_VIEWING_PUBLIC_KEY,
            b"short",
            41,
            entropy_source=FixedEntropy([rho, randomness, nonce]),
        )


def test_wallet_creates_output_from_chain_bound_address_before_entropy_use():
    kem = FakeKemProvider()
    aead = FakeAeadProvider()
    recipient_secret = b"z" * 64
    recipient_spend_public_key = spend_public(recipient_secret)
    chain_id = b"c" * 32
    address = serialize_address(
        chain_id,
        recipient_spend_public_key,
        VALID_VIEWING_PUBLIC_KEY,
    )
    rho = b"q" * 64
    randomness = b"v" * 64
    nonce = b"m" * 12

    created = create_note_output_for_address_v1(
        kem,
        aead,
        address,
        41,
        b"address-based transfer",
        expected_chain_id=chain_id,
        entropy_source=FixedEntropy([rho, randomness, nonce]),
        nonce_registry=AeadNonceRegistry(),
    )

    assert created.recipient_spend_public_key == recipient_spend_public_key
    assert created.owner == note_owner(recipient_spend_public_key, SHARED_SECRET)
    assert kem.encapsulate_calls == 1
    assert aead.encrypt_calls == 1
    recovered = recover(FakeAeadProvider(), created.output, recipient_secret)
    assert recovered is not None
    assert recovered.value == 41

    unused_entropy = FixedEntropy([rho, randomness, nonce])
    with pytest.raises(ValueError, match="chain ID mismatch"):
        create_note_output_for_address_v1(
            kem,
            aead,
            address,
            41,
            expected_chain_id=b"x" * 32,
            entropy_source=unused_entropy,
        )
    assert len(unused_entropy.values) == 3
    assert kem.encapsulate_calls == 1
    assert aead.encrypt_calls == 1


def test_wallet_scan_skips_only_auth_rejections_and_keeps_absolute_positions():


    rejected_nonce = b"z" * 12
    rejected_output = build_output(FakeAeadProvider(), nonce=rejected_nonce)
    owned_output = build_output(FakeAeadProvider(), nonce=b"y" * 12)

    scanned = scan_outputs_v1(
        FakeKemProvider(),
        FakeAeadProvider(reject_nonces=(rejected_nonce,)),
        b"d" * 64,
        SPEND_SECRET,
        (rejected_output, owned_output),
        start_index=41,
    )

    assert len(scanned) == 1
    assert scanned[0].output_index == 42
    assert scanned[0].note.value == 23
    assert scanned[0].note.nullifier == nullifier(SPEND_SECRET, SHARED_SECRET, RHO)


def test_wallet_authenticated_scan_checks_paths_before_callbacks():
    output = build_output(FakeAeadProvider())
    tree = OutputTree()
    tree.append(output.leaf)
    path = tree.authentication_path(0)

    class CountingKemProvider(FakeKemProvider):
        def __init__(self, target):
            super().__init__()
            self.decapsulation_calls = 0
            self.target = target

        def decapsulate(self, decapsulation_key, ciphertext):
            self.decapsulation_calls += 1
            if self.target is not None:
                object.__setattr__(self.target, "commitment", b"!" * 64)
                self.target = None
            return super().decapsulate(decapsulation_key, ciphertext)

    kem = CountingKemProvider(output)
    bad_path = (b"!" * 64,) + path[1:]
    with pytest.raises(NoteRecoveryError, match="not in the trusted root"):
        scan_authenticated_outputs_v1(
            kem,
            FakeAeadProvider(),
            b"d" * 64,
            SPEND_SECRET,
            (output,),
            (bad_path,),
            tree.root,
        )
    assert kem.decapsulation_calls == 0

    with pytest.raises(NoteRecoveryError, match="not in the trusted root"):
        scan_authenticated_outputs_v1(
            kem,
            FakeAeadProvider(),
            b"d" * 64,
            SPEND_SECRET,
            (output,),
            (path,),
            b"!" * 64,
        )
    assert kem.decapsulation_calls == 0

    scanned = scan_authenticated_outputs_v1(
        kem,
        FakeAeadProvider(),
        b"d" * 64,
        SPEND_SECRET,
        (output,),
        (path,),
        tree.root,
        start_index=0,
    )
    assert [item.output_index for item in scanned] == [0]
    assert [item.note.value for item in scanned] == [23]
    assert kem.decapsulation_calls == 1


def test_wallet_authenticated_scan_prevalidates_all_paths_before_provider_callbacks():
    aead = FakeAeadProvider()
    outputs = (
        build_output(aead),
        build_output(aead, nonce=b"m" * 12),
    )
    tree = OutputTree()
    for output in outputs:
        tree.append(output.leaf)
    paths = (tree.authentication_path(0), tree.authentication_path(1))
    corrupted_second_path = (b"!" * 64,) + paths[1][1:]

    class CountingKemProvider(FakeKemProvider):
        def __init__(self):
            super().__init__()
            self.decapsulation_calls = 0

        def decapsulate(self, decapsulation_key, ciphertext):
            self.decapsulation_calls += 1
            return super().decapsulate(decapsulation_key, ciphertext)

    class CountingAeadProvider(FakeAeadProvider):
        def __init__(self):
            super().__init__()
            self.decryption_calls = 0

        def decrypt(self, key, nonce, ciphertext, associated_data):
            self.decryption_calls += 1
            return super().decrypt(key, nonce, ciphertext, associated_data)

    kem = CountingKemProvider()
    counted_aead = CountingAeadProvider()
    with pytest.raises(NoteRecoveryError, match="output at index 1 is not in the trusted root"):
        scan_authenticated_outputs_v1(
            kem,
            counted_aead,
            b"d" * 64,
            SPEND_SECRET,
            outputs,
            (paths[0], corrupted_second_path),
            tree.root,
        )

    assert kem.decapsulation_calls == 0
    assert counted_aead.decryption_calls == 0


def test_wallet_authenticated_scan_prevalidates_path_shapes_before_output_snapshots(monkeypatch):
    import radix_core.wallet as wallet_module

    aead = FakeAeadProvider()
    outputs = (build_output(aead), build_output(aead, nonce=b"m" * 12))
    tree = OutputTree()
    for output in outputs:
        tree.append(output.leaf)
    paths = (tree.authentication_path(0), tree.authentication_path(1))
    malformed_second = (b"x" * 63,) + paths[1][1:]

    def unexpected_snapshot(_output):
        pytest.fail("output snapshot ran before every path shape was validated")

    monkeypatch.setattr(wallet_module, "_snapshot_output_v1", unexpected_snapshot)
    with pytest.raises(ValueError, match="sibling must be 64 bytes"):
        scan_authenticated_outputs_v1(
            FakeKemProvider(),
            aead,
            b"d" * 64,
            SPEND_SECRET,
            outputs,
            (paths[0], malformed_second),
            tree.root,
        )


def test_wallet_authenticated_scan_rejects_bad_path_shape_and_index():
    output = build_output(FakeAeadProvider())
    tree = OutputTree()
    tree.append(output.leaf)
    path = tree.authentication_path(0)
    kem = FakeKemProvider()
    aead = FakeAeadProvider()

    with pytest.raises(ValueError, match="64 siblings"):
        scan_authenticated_outputs_v1(
            kem, aead, b"d" * 64, SPEND_SECRET, (output,), ((b"x" * 64,),), tree.root
        )
    malformed_sibling_path = (b"x" * 63,) + path[1:]
    with pytest.raises(ValueError, match="sibling must be 64 bytes"):
        scan_authenticated_outputs_v1(
            kem, aead, b"d" * 64, SPEND_SECRET, (output,), (malformed_sibling_path,), tree.root
        )
    with pytest.raises(NoteRecoveryError, match="not in the trusted root"):
        scan_authenticated_outputs_v1(
            kem, aead, b"d" * 64, SPEND_SECRET, (output,), (path,), tree.root, start_index=1
        )
    with pytest.raises(ValueError, match="one authentication path per output"):
        scan_authenticated_outputs_v1(
            kem, aead, b"d" * 64, SPEND_SECRET, (output,), (), tree.root
        )


def test_wallet_scan_snapshots_the_full_chunk_before_provider_callbacks():
    first = build_output(FakeAeadProvider())
    second = build_output(FakeAeadProvider())

    class MutatingKemProvider(FakeKemProvider):
        def __init__(self, target):
            super().__init__()
            self.target = target

        def decapsulate(self, decapsulation_key, ciphertext):
            if self.target is not None:
                object.__setattr__(self.target, "commitment", b"!" * 64)
                self.target = None
            return super().decapsulate(decapsulation_key, ciphertext)

    scanned = scan_outputs_v1(
        MutatingKemProvider(second),
        FakeAeadProvider(),
        b"d" * 64,
        SPEND_SECRET,
        (first, second),
        start_index=70,
    )

    assert [entry.output_index for entry in scanned] == [70, 71]
    assert [entry.note.value for entry in scanned] == [23, 23]


def test_wallet_scan_is_bounded_canonical_and_fails_closed():
    output = build_output(FakeAeadProvider())

    with pytest.raises(ValueError, match="canonical tuple"):
        scan_outputs_v1(FakeKemProvider(), FakeAeadProvider(), b"d" * 64, SPEND_SECRET, [output])
    with pytest.raises(ValueError, match="exceeds 1024"):
        scan_outputs_v1(
            FakeKemProvider(), FakeAeadProvider(), b"d" * 64, SPEND_SECRET, (output,) * 1025
        )
    with pytest.raises(ValueError, match="index range"):
        scan_outputs_v1(
            FakeKemProvider(), FakeAeadProvider(), b"d" * 64, SPEND_SECRET,
            (output, output), start_index=(1 << 64) - 1,
        )
    with pytest.raises(ValueError, match="start index"):
        scan_outputs_v1(FakeKemProvider(), FakeAeadProvider(), b"d" * 64, SPEND_SECRET, (), start_index=True)
    assert scan_outputs_v1(
        FakeKemProvider(), FakeAeadProvider(), b"d" * 64, SPEND_SECRET, (), start_index=1 << 64
    ) == ()
    with pytest.raises(NoteRecoveryError, match="spend secret is invalid"):
        scan_outputs_v1(FakeKemProvider(), FakeAeadProvider(), b"d" * 64, b"s" * 63, ())
    with pytest.raises(ValueError, match="private seed must be exactly 64 bytes"):
        scan_outputs_v1(FakeKemProvider(), FakeAeadProvider(), b"d" * 63, SPEND_SECRET, ())

    malformed = OutputRecord(
        output.commitment,
        output.kem_ciphertext,
        output.nonce,
        output.ciphertext,
        b"!" * 64,
    )
    with pytest.raises(ValueError, match="private seed must be exactly 64 bytes"):
        scan_outputs_v1(
            FakeKemProvider(), FakeAeadProvider(), b"d" * 63, SPEND_SECRET, (malformed,)
        )
    with pytest.raises(NoteRecoveryError, match="noncanonical"):
        scan_outputs_v1(
            FakeKemProvider(), FakeAeadProvider(), b"d" * 64, SPEND_SECRET,
            (output, malformed),
        )
    with pytest.raises(CryptoBackendError, match="decryption failed"):
        scan_outputs_v1(
            FakeKemProvider(), FakeAeadProvider("backend"), b"d" * 64, SPEND_SECRET,
            (output,),
        )


def test_wallet_scan_chunk_raw_field_bounds_are_derived_from_schemas():
    assert MAX_OUTPUT_RAW_FIELD_BYTES == 1_896
    assert MAX_SCAN_CHUNK_RAW_FIELD_BYTES == 1_941_504
    assert MAX_SCAN_CHUNK_AUTH_PATH_BYTES == 4_194_304


def test_wallet_cursor_authenticated_scan_advances_only_after_membership_and_scan():
    output = build_output(FakeAeadProvider())
    tree = OutputTree()
    tree.append(output.leaf)
    path = tree.authentication_path(0)
    cursor = WalletScanCursorV1(start_index=0)

    class CountingKemProvider(FakeKemProvider):
        def __init__(self):
            super().__init__()
            self.decapsulation_calls = 0

        def decapsulate(self, decapsulation_key, ciphertext):
            self.decapsulation_calls += 1
            return super().decapsulate(decapsulation_key, ciphertext)

    kem = CountingKemProvider()
    with pytest.raises(ValueError, match="trusted leaf count must be an integer"):
        cursor.scan_authenticated_chunk(
            kem,
            FakeAeadProvider(),
            b"d" * 64,
            SPEND_SECRET,
            (output,),
            (path,),
            tree.root,
            trusted_leaf_count=True,
        )
    with pytest.raises(ValueError, match="exceeds trusted leaf count"):
        cursor.scan_authenticated_chunk(
            kem,
            FakeAeadProvider(),
            b"d" * 64,
            SPEND_SECRET,
            (output,),
            (path,),
            tree.root,
            trusted_leaf_count=0,
        )
    assert cursor.next_output_index == 0
    assert kem.decapsulation_calls == 0

    with pytest.raises(NoteRecoveryError, match="not in the trusted root"):
        cursor.scan_authenticated_chunk(
            kem, FakeAeadProvider(), b"d" * 64, SPEND_SECRET, (output,), (path,), b"!" * 64
        )
    assert cursor.next_output_index == 0
    assert kem.decapsulation_calls == 0

    scanned = cursor.scan_authenticated_chunk(
        kem,
        FakeAeadProvider(),
        b"d" * 64,
        SPEND_SECRET,
        (output,),
        (path,),
        tree.root,
        trusted_leaf_count=1,
    )
    assert [entry.output_index for entry in scanned] == [0]
    assert cursor.next_output_index == 1
    assert kem.decapsulation_calls == 1
    authenticated_state = cursor.snapshot()
    assert authenticated_state == WalletScanCursorSnapshotV1(
        next_output_index=1,
        scan_mode="authenticated",
        trusted_root=tree.root,
        trusted_leaf_count=1,
    )
    restored = WalletScanCursorV1.from_snapshot(authenticated_state)
    assert restored.snapshot() == authenticated_state

    class EqualityBomb:
        def __eq__(self, other):
            raise AssertionError("untrusted root equality must not be invoked")

    with pytest.raises(ValueError, match="trusted output root must be exactly 64 bytes"):
        restored.scan_authenticated_chunk(
            kem,
            FakeAeadProvider(),
            b"d" * 64,
            SPEND_SECRET,
            (output,),
            (path,),
            EqualityBomb(),
            trusted_leaf_count=1,
        )
    assert restored.next_output_index == 1

    class CountEqualityBomb:
        def __eq__(self, other):
            raise AssertionError("untrusted count equality must not be invoked")

    with pytest.raises(ValueError, match="trusted leaf count must be an integer"):
        restored.scan_authenticated_chunk(
            kem,
            FakeAeadProvider(),
            b"d" * 64,
            SPEND_SECRET,
            (output,),
            (path,),
            tree.root,
            trusted_leaf_count=CountEqualityBomb(),
        )
    assert restored.next_output_index == 1

    second_output = build_output(FakeAeadProvider())
    extended_tree = OutputTree()
    extended_tree.append(output.leaf)
    extended_tree.append(second_output.leaf)
    second_path = extended_tree.authentication_path(1)
    with pytest.raises(ValueError, match="scan checkpoint differs"):
        restored.scan_authenticated_chunk(
            kem,
            FakeAeadProvider(),
            b"d" * 64,
            SPEND_SECRET,
            (second_output,),
            (second_path,),
            extended_tree.root,
            trusted_leaf_count=2,
        )
    with pytest.raises(ValueError, match="cannot switch scan modes"):
        cursor.scan_chunk(
            kem, FakeAeadProvider(), b"d" * 64, SPEND_SECRET, (second_output,)
        )
    assert cursor.next_output_index == 1
    assert restored.next_output_index == 1
    assert kem.decapsulation_calls == 1


@pytest.mark.parametrize(
    "snapshot",
    [
        WalletScanCursorSnapshotV1(0, None),
        WalletScanCursorSnapshotV1(U64_MAX + 1, "legacy"),
        WalletScanCursorSnapshotV1(3, "authenticated", b"r" * 64),
        WalletScanCursorSnapshotV1(
            U64_MAX + 1, "authenticated", b"z" * 64, U64_MAX + 1
        ),
    ],
)
def test_wallet_cursor_snapshot_encoding_roundtrips_canonically(snapshot):
    encoded = snapshot.to_bytes()
    decoded = WalletScanCursorSnapshotV1.from_bytes(encoded)
    assert decoded == snapshot
    assert decoded.to_bytes() == encoded
    assert WalletScanCursorV1.from_snapshot(decoded).snapshot() == snapshot


def test_wallet_cursor_snapshot_encoding_rejects_noncanonical_inputs():
    authenticated = WalletScanCursorSnapshotV1(5, "authenticated", b"r" * 64)
    encoded = authenticated.to_bytes()
    count_encoded = WalletScanCursorSnapshotV1(
        5, "authenticated", b"r" * 64, 5
    ).to_bytes()
    malformed = [
        (encoded + bytes([0]), "trailing bytes"),
        (encoded[:-1], "authenticated snapshot is truncated"),
        (count_encoded[:-1], "leaf count is truncated"),
        (b"XXXXXXXX" + encoded[8:], "version is invalid"),
        (
            encoded[:8] + (U64_MAX + 2).to_bytes(9, "little") + encoded[17:],
            "outside the depth-64 range",
        ),
        (encoded[:17] + bytes([3]) + encoded[18:], "flags are invalid"),
        (encoded[:18] + bytes([2]) + encoded[19:], "flags are invalid"),
        (
            count_encoded[:83] + (U64_MAX + 2).to_bytes(9, "little"),
            "outside",
        ),
    ]
    for wire, message in malformed:
        with pytest.raises(ValueError, match=message):
            WalletScanCursorSnapshotV1.from_bytes(wire)

    legacy_with_count_flag = bytearray(WalletScanCursorSnapshotV1(1, "legacy").to_bytes())
    legacy_with_count_flag[18] = 1
    with pytest.raises(ValueError, match="only authenticated snapshots"):
        WalletScanCursorSnapshotV1.from_bytes(bytes(legacy_with_count_flag))
    with pytest.raises(ValueError, match="encoding must be bytes"):
        WalletScanCursorSnapshotV1.from_bytes(bytearray(encoded))


def test_authenticated_snapshot_restore_requires_external_root_count_and_position():
    root = b"r" * 64
    state = WalletScanCursorSnapshotV1(5, "authenticated", root, 9)
    encoded = state.to_bytes()
    restored = WalletScanCursorV1.from_authenticated_snapshot_bytes(
        encoded,
        trusted_root=root,
        trusted_leaf_count=9,
        expected_next_output_index=5,
    )
    assert restored.snapshot() == state

    mismatches = [
        ({"trusted_root": b"x" * 64}, "caller-authenticated root"),
        ({"trusted_leaf_count": 10}, "caller-authenticated count"),
        ({"expected_next_output_index": 4}, "caller-expected index"),
    ]
    for changes, message in mismatches:
        arguments = {
            "trusted_root": root,
            "trusted_leaf_count": 9,
            "expected_next_output_index": 5,
        }
        arguments.update(changes)
        with pytest.raises(ValueError, match=message):
            WalletScanCursorV1.from_authenticated_snapshot_bytes(encoded, **arguments)

    with pytest.raises(ValueError, match="authenticated snapshot"):
        WalletScanCursorV1.from_authenticated_snapshot_bytes(
            WalletScanCursorSnapshotV1(5, "legacy").to_bytes(),
            trusted_root=root,
            trusted_leaf_count=9,
            expected_next_output_index=5,
        )
    with pytest.raises(ValueError, match="exceeds trusted leaf count"):
        WalletScanCursorV1.from_authenticated_snapshot_bytes(
            encoded,
            trusted_root=root,
            trusted_leaf_count=4,
            expected_next_output_index=5,
        )


def test_wallet_cursor_cannot_upgrade_legacy_scan_history_to_authenticated():
    first = build_output(FakeAeadProvider())
    second = build_output(FakeAeadProvider())
    cursor = WalletScanCursorV1()
    fresh_state = cursor.snapshot()
    assert fresh_state == WalletScanCursorSnapshotV1(0, None)
    assert WalletScanCursorV1.from_snapshot(fresh_state).snapshot() == fresh_state
    with pytest.raises(ValueError, match="output index"):
        WalletScanCursorSnapshotV1(True, None)
    with pytest.raises(ValueError, match="requires a 64-byte trusted root"):
        WalletScanCursorSnapshotV1(1, "authenticated")

    class SnapshotCheckingKem(FakeKemProvider):
        def decapsulate(self, decapsulation_key, ciphertext):
            with pytest.raises(RuntimeError, match="cannot snapshot an active wallet scan"):
                cursor.snapshot()
            return super().decapsulate(decapsulation_key, ciphertext)

    cursor.scan_chunk(
        SnapshotCheckingKem(), FakeAeadProvider(), b"d" * 64, SPEND_SECRET, (first,)
    )
    assert cursor.next_output_index == 1
    legacy_state = cursor.snapshot()
    assert legacy_state == WalletScanCursorSnapshotV1(1, "legacy")
    restored = WalletScanCursorV1.from_snapshot(legacy_state)
    assert restored.snapshot() == legacy_state
    assert restored.next_output_index == 1

    tree = OutputTree()
    tree.append(first.leaf)
    tree.append(second.leaf)
    with pytest.raises(ValueError, match="cannot switch scan modes"):
        restored.scan_authenticated_chunk(
            FakeKemProvider(),
            FakeAeadProvider(),
            b"d" * 64,
            SPEND_SECRET,
            (second,),
            (tree.authentication_path(1),),
            tree.root,
            trusted_leaf_count=2,
        )
    assert cursor.next_output_index == 1


def test_wallet_scan_cursor_rejects_malformed_chunk_before_callbacks_or_advancing():
    first = build_output(FakeAeadProvider())
    malformed = OutputRecord(
        first.commitment,
        first.kem_ciphertext,
        first.nonce,
        first.ciphertext,
        b"!" * 64,
    )
    cursor = WalletScanCursorV1(start_index=41)

    class CountingKemProvider(FakeKemProvider):
        def __init__(self):
            super().__init__()
            self.decapsulate_calls = 0

        def decapsulate(self, decapsulation_key, ciphertext):
            self.decapsulate_calls += 1
            return super().decapsulate(decapsulation_key, ciphertext)

    kem = CountingKemProvider()
    with pytest.raises(NoteRecoveryError, match="noncanonical"):
        cursor.scan_chunk(kem, FakeAeadProvider(), b"d" * 64, SPEND_SECRET, (first, malformed))

    assert kem.decapsulate_calls == 0
    assert cursor.next_output_index == 41
    recovered = cursor.scan_chunk(
        FakeKemProvider(), FakeAeadProvider(), b"d" * 64, SPEND_SECRET, (first,)
    )
    assert [entry.output_index for entry in recovered] == [41]
    assert cursor.next_output_index == 42


def test_wallet_scan_cursor_advances_atomically_across_bounded_chunks():
    first = build_output(FakeAeadProvider())
    second = build_output(FakeAeadProvider(), nonce=b"y" * 12)
    cursor = WalletScanCursorV1(start_index=41)

    first_notes = cursor.scan_chunk(
        FakeKemProvider(), FakeAeadProvider(), b"d" * 64, SPEND_SECRET, (first,)
    )
    assert [entry.output_index for entry in first_notes] == [41]
    assert cursor.next_output_index == 42

    second_notes = cursor.scan_chunk(
        FakeKemProvider(), FakeAeadProvider(), b"d" * 64, SPEND_SECRET, (second,)
    )
    assert [entry.output_index for entry in second_notes] == [42]
    assert cursor.next_output_index == 43

    with pytest.raises(CryptoBackendError, match="decryption failed"):
        cursor.scan_chunk(
            FakeKemProvider(), FakeAeadProvider("backend"), b"d" * 64,
            SPEND_SECRET, (first,),
        )
    assert cursor.next_output_index == 43


def test_wallet_scan_cursor_rejects_overlapping_chunks_and_allows_retry():
    output = build_output(FakeAeadProvider())
    cursor = WalletScanCursorV1(start_index=41)
    provider_entered = Event()
    release_provider = Event()
    second_call_started = Event()

    class BlockingKemProvider(FakeKemProvider):
        def decapsulate(self, decapsulation_key, ciphertext):
            provider_entered.set()
            if not release_provider.wait(timeout=3):
                raise RuntimeError("test provider timed out waiting for release")
            return SHARED_SECRET

    def scan_second_chunk():
        second_call_started.set()
        return cursor.scan_chunk(
            FakeKemProvider(), FakeAeadProvider(), b"d" * 64, SPEND_SECRET, (output,)
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(
            cursor.scan_chunk,
            BlockingKemProvider(),
            FakeAeadProvider(),
            b"d" * 64,
            SPEND_SECRET,
            (output,),
        )
        try:
            assert provider_entered.wait(timeout=2)
            position_future = executor.submit(lambda: cursor.next_output_index)
            assert position_future.result(timeout=1) == 41
            second_future = executor.submit(scan_second_chunk)
            assert second_call_started.wait(timeout=2)
            with pytest.raises(RuntimeError, match="already scanning"):
                second_future.result(timeout=1)
        finally:
            release_provider.set()

        first_notes = first_future.result(timeout=3)
        second_notes = cursor.scan_chunk(
            FakeKemProvider(), FakeAeadProvider(), b"d" * 64, SPEND_SECRET, (output,)
        )

    assert [entry.output_index for entry in first_notes] == [41]
    assert [entry.output_index for entry in second_notes] == [42]
    assert cursor.next_output_index == 43


def test_wallet_scan_cursor_allows_retry_after_active_scan_failure():
    output = build_output(FakeAeadProvider())
    cursor = WalletScanCursorV1(start_index=63)
    provider_entered = Event()
    release_provider = Event()
    second_call_started = Event()

    class BlockingFailingKemProvider(FakeKemProvider):
        def decapsulate(self, decapsulation_key, ciphertext):
            provider_entered.set()
            if not release_provider.wait(timeout=3):
                raise RuntimeError("test provider timed out waiting for release")
            raise OSError("injected decapsulation failure")

    def scan_waiting_chunk():
        second_call_started.set()
        return cursor.scan_chunk(
            FakeKemProvider(), FakeAeadProvider(), b"d" * 64, SPEND_SECRET, (output,)
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        failed_future = executor.submit(
            cursor.scan_chunk,
            BlockingFailingKemProvider(),
            FakeAeadProvider(),
            b"d" * 64,
            SPEND_SECRET,
            (output,),
        )
        try:
            assert provider_entered.wait(timeout=2)
            waiting_future = executor.submit(scan_waiting_chunk)
            assert second_call_started.wait(timeout=2)
            with pytest.raises(RuntimeError, match="already scanning"):
                waiting_future.result(timeout=1)
        finally:
            release_provider.set()

        with pytest.raises(CryptoBackendError, match="decapsulation failed"):
            failed_future.result(timeout=3)
        recovered = cursor.scan_chunk(
            FakeKemProvider(), FakeAeadProvider(), b"d" * 64, SPEND_SECRET, (output,)
        )

    assert [entry.output_index for entry in recovered] == [63]
    assert cursor.next_output_index == 64


def test_wallet_scan_cursor_rejects_reentrant_provider_callbacks():
    output = build_output(FakeAeadProvider())
    cursor = WalletScanCursorV1(start_index=90)

    class ReentrantKemProvider(FakeKemProvider):
        def decapsulate(self, decapsulation_key, ciphertext):
            cursor.scan_chunk(
                self, FakeAeadProvider(), decapsulation_key, SPEND_SECRET, ()
            )
            return SHARED_SECRET

    with pytest.raises(
        CryptoBackendError,
        match=r"ML-KEM-768 decapsulation failed \(RuntimeError\)",
    ) as error:
        cursor.scan_chunk(
            ReentrantKemProvider(), FakeAeadProvider(), b"d" * 64,
            SPEND_SECRET, (output,),
        )
    # The provider boundary sanitizes callback exceptions but preserves the
    # cursor's reentrancy rejection as the chained cause.
    assert isinstance(error.value.__cause__, RuntimeError)
    assert str(error.value.__cause__) == "wallet scan cursor is already scanning"
    assert cursor.next_output_index == 90


def test_wallet_scan_cursor_validates_start_and_tree_end():
    with pytest.raises(ValueError, match="start index"):
        WalletScanCursorV1(start_index=True)
    cursor = WalletScanCursorV1(start_index=U64_MAX)
    output = build_output(FakeAeadProvider())
    with pytest.raises(ValueError, match="index range"):
        cursor.scan_chunk(
            FakeKemProvider(), FakeAeadProvider(), b"d" * 64,
            SPEND_SECRET, (output, output),
        )
    assert cursor.next_output_index == U64_MAX


def test_wallet_creation_rejects_invalid_inputs_and_entropy_before_kem_call():

    kem = FakeKemProvider()
    with pytest.raises(ValueError, match="nonzero U64"):
        create_note_output_v1(
            kem,
            FakeAeadProvider(),
            bytes(1184),
            SPEND_SECRET,
            0,
            entropy_source=FixedEntropy([]),
        )
    assert kem.encapsulate_calls == 0

    with pytest.raises(EntropyError, match="noncanonical byte count"):
        create_note_output_v1(
            kem,
            FakeAeadProvider(),
            bytes(1184),
            SPEND_SECRET,
            1,
            entropy_source=FixedEntropy([b"short"]),
        )
    assert kem.encapsulate_calls == 0


def test_wallet_recovers_note_only_after_commitment_opening_and_derives_nullifier():

    output = build_output(FakeAeadProvider())
    note = recover(FakeAeadProvider(), output)

    assert note is not None
    assert (note.value, note.rho, note.randomness, note.memo) == (
        23,
        RHO,
        RANDOMNESS,
        b"wallet test",
    )
    assert note.nullifier == nullifier(SPEND_SECRET, SHARED_SECRET, RHO)


def test_wallet_scan_skips_only_authentication_rejections_not_backend_faults():
    output = build_output(FakeAeadProvider())
    assert recover(FakeAeadProvider(failure="auth"), output) is None
    with pytest.raises(CryptoBackendError, match="decryption failed"):
        recover(FakeAeadProvider(failure="backend"), output)


def test_wallet_rejects_wrong_spend_secret_and_authenticated_commitment_mismatch():
    output = build_output(FakeAeadProvider())
    with pytest.raises(NoteRecoveryError, match="commitment"):
        recover(FakeAeadProvider(), output, spend_secret=b"z" * 64)

    changed_commitment = bytes([output.commitment[0] ^ 1]) + output.commitment[1:]
    inconsistent_output = build_output(
        FakeAeadProvider(),
        public_commitment=changed_commitment,
    )
    with pytest.raises(NoteRecoveryError, match="does not match"):
        recover(FakeAeadProvider(), inconsistent_output)


def test_wallet_rejects_noncanonical_output_before_decryption():
    output = build_output(FakeAeadProvider())
    malformed = OutputRecord(
        commitment=output.commitment,
        kem_ciphertext=output.kem_ciphertext,
        nonce=output.nonce,
        ciphertext=output.ciphertext,
        leaf=b"bad",
    )
    with pytest.raises(NoteRecoveryError, match="noncanonical"):
        recover(FakeAeadProvider(), malformed)


def test_wallet_rejects_output_subclasses_that_override_canonical_validation():
    class LyingOutputRecord(OutputRecord):
        def serialize(self):
            return b"pretend canonical"

        def leaf_matches_fields(self):
            return True

    forged = LyingOutputRecord(b"x", b"bad", b"bad", b"bad", b"z" * 64)
    with pytest.raises(NoteRecoveryError, match="output record type"):
        recover(FakeAeadProvider(), forged)


def test_wallet_recomputes_leaf_without_trusting_instance_method_overrides():
    forged = build_output(FakeAeadProvider())
    object.__setattr__(forged, "leaf", b"!" * 64)
    object.__setattr__(forged, "leaf_matches_fields", lambda: True)
    object.__setattr__(forged, "serialize", lambda: b"pretend canonical")

    with pytest.raises(NoteRecoveryError, match="output leaf"):
        recover(FakeAeadProvider(), forged)


def test_wallet_recovery_uses_validated_output_snapshot_across_provider_callbacks():
    output = build_output(FakeAeadProvider())

    class MutatingKemProvider:
        def decapsulate(self, decapsulation_key, ciphertext):
            object.__setattr__(output, "commitment", b"!" * 64)
            return SHARED_SECRET

    recovered = recover_note_v1(
        MutatingKemProvider(),
        FakeAeadProvider(),
        b"d" * 64,
        SPEND_SECRET,
        output,
    )
    assert recovered is not None
    assert recovered.value == 23
    assert recovered.nullifier == nullifier(SPEND_SECRET, SHARED_SECRET, RHO)


def test_wallet_rejects_output_without_leaking_shadowed_serializer_exceptions():
    forged = build_output(FakeAeadProvider())
    object.__setattr__(forged, "leaf", b"!" * 64)
    object.__setattr__(forged, "leaf_matches_fields", lambda: True)

    def explode():
        raise RuntimeError("untrusted method must not run")

    object.__setattr__(forged, "serialize", explode)
    with pytest.raises(NoteRecoveryError, match="output leaf"):
        recover(FakeAeadProvider(), forged)
