from radix_core.cryptography_backend import (
    CryptographyAes256GcmProvider,
    CryptographyMlKem768Provider,
)
from radix_core.providers import AeadNonceRegistry
from radix_core.wallet import (
    create_note_output_v1,
    generate_wallet_keys_v1,
    recover_note_v1,
    scan_outputs_v1,
    serialize_wallet_address_v1,
)
from radix_core.wire import parse_address


def test_real_crypto_wallet_keygen_address_send_recover_and_scan(tmp_path):
    kem = CryptographyMlKem768Provider()
    aead = CryptographyAes256GcmProvider()
    keys = generate_wallet_keys_v1(kem)

    chain_id = b"R" * 32
    address = serialize_wallet_address_v1(keys, chain_id)
    decoded_chain, decoded_spend_key, decoded_view_key = parse_address(
        address, expected_chain_id=chain_id
    )
    assert (decoded_chain, decoded_spend_key, decoded_view_key) == (
        chain_id,
        keys.spend_public_key,
        keys.viewing_public_key,
    )

    created = create_note_output_v1(
        kem,
        aead,
        keys.viewing_public_key,
        keys.spend_secret,
        42,
        b"real ML-KEM and AES-GCM roundtrip",
        nonce_registry=AeadNonceRegistry(
            max_entries=None,
            database_path=tmp_path / "wallet-nonce-history.sqlite3",
        ),
    )
    recovered = recover_note_v1(
        kem,
        aead,
        keys.decapsulation_key,
        keys.spend_secret,
        created.output,
    )
    assert recovered is not None
    assert (recovered.value, recovered.memo) == (42, b"real ML-KEM and AES-GCM roundtrip")

    scanned = scan_outputs_v1(
        kem,
        aead,
        keys.decapsulation_key,
        keys.spend_secret,
        (created.output,),
        start_index=9001,
    )
    assert len(scanned) == 1
    assert scanned[0].output_index == 9001
    assert scanned[0].note.nullifier == recovered.nullifier

    # A wrong viewing secret follows ML-KEM implicit rejection and AEAD auth
    # failure; scanning treats the output as a non-recipient, not as a note.
    other_keys = generate_wallet_keys_v1(kem)
    assert scan_outputs_v1(
        kem,
        aead,
        other_keys.decapsulation_key,
        other_keys.spend_secret,
        (created.output,),
        start_index=9001,
    ) == ()
