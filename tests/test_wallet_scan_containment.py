"""Regression tests for scan liveness against hostile, attacker-crafted outputs.

Threat: any third party who knows a victim's public address can encapsulate to
the victim's viewing key, so they know the KEM shared secret. They can therefore
build a wire-canonical output that authenticates under the victim's key but does
not open to the published commitment (or decrypts to a non-canonical plaintext).
Before the containment fix, such an output raised out of the scan loop, aborted
the whole chunk, and left ``WalletScanCursorV1`` pinned at the same index, so the
victim's wallet could never advance again.

These tests fail on the pre-fix behaviour and assert the post-fix contract:
authenticated-but-inconsistent outputs are skipped, honest notes in the same
chunk are still returned, and the cursor advances.
"""

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from radix_core.crypto import note_commitment, note_kdf, note_owner, output_leaf
from radix_core.cryptography_backend import (
    CryptographyAes256GcmProvider,
    CryptographyMlKem768Provider,
)
from radix_core.encoding import u32, u64
from radix_core.memo import encode_plaintext_v1
from radix_core.providers import AeadNonceRegistry, note_aad_v1
from radix_core.wallet import (
    NoteRecoveryError,
    WalletScanCursorV1,
    create_note_output_to_v1,
    generate_wallet_keys_v1,
    recover_note_v1,
    scan_outputs_v1,
)
from radix_core.wire import OutputRecord, serialize_output_v1

KEM = CryptographyMlKem768Provider()
AEAD = CryptographyAes256GcmProvider()
REGISTRY = AeadNonceRegistry()


def _victim():
    return generate_wallet_keys_v1(KEM)


def _honest_output(victim, value: int = 42) -> OutputRecord:
    return create_note_output_to_v1(
        KEM,
        AEAD,
        victim.viewing_public_key,
        victim.spend_public_key,
        value,
        b"honest note",
        nonce_registry=REGISTRY,
    ).output


def _hostile_output(
    victim,
    *,
    committed_value: int,
    plaintext: bytes,
    seed: int,
) -> OutputRecord:
    """Build an output that authenticates for the victim but is inconsistent."""
    ciphertext, shared_secret = KEM.encapsulate(victim.viewing_public_key)
    rho = bytes([seed]) * 64
    randomness = bytes([seed + 1]) * 64
    owner = note_owner(victim.spend_public_key, shared_secret)
    commitment = note_commitment(owner, committed_value, rho, randomness)
    nonce = bytes([seed]) * 12
    key = note_kdf(shared_secret, ciphertext, commitment)
    payload = AESGCM(key).encrypt(nonce, plaintext, note_aad_v1(commitment, ciphertext))
    output = OutputRecord(
        commitment=commitment,
        kem_ciphertext=ciphertext,
        nonce=nonce,
        ciphertext=payload,
        leaf=output_leaf(commitment, ciphertext, nonce, payload),
    )
    serialize_output_v1(output)
    return output


def _commitment_mismatch_output(victim, seed: int = 3) -> OutputRecord:
    """Authenticates, decrypts to value 5, but the commitment says 999."""
    rho = bytes([seed]) * 64
    randomness = bytes([seed + 1]) * 64
    plaintext = encode_plaintext_v1(5, rho, randomness, b"")
    return _hostile_output(
        victim, committed_value=999, plaintext=plaintext, seed=seed
    )


def _noncanonical_plaintext_output(victim, seed: int = 5) -> OutputRecord:
    """Authenticates, but the plaintext encodes the forbidden zero value."""
    rho = bytes([seed]) * 64
    randomness = bytes([seed + 1]) * 64
    plaintext = u64(0) + rho + randomness + u32(0)
    assert len(plaintext) == 140
    return _hostile_output(victim, committed_value=7, plaintext=plaintext, seed=seed)


def test_hostile_output_before_honest_note_does_not_abort_the_chunk():
    victim = _victim()
    honest = _honest_output(victim)
    hostile = _commitment_mismatch_output(victim)

    scanned = scan_outputs_v1(
        KEM, AEAD, victim.decapsulation_key, victim.spend_secret, (hostile, honest)
    )

    assert [note.output_index for note in scanned] == [1]
    assert scanned[0].note.value == 42


def test_hostile_output_after_honest_note_does_not_abort_the_chunk():
    victim = _victim()
    honest = _honest_output(victim)
    hostile = _commitment_mismatch_output(victim)

    scanned = scan_outputs_v1(
        KEM, AEAD, victim.decapsulation_key, victim.spend_secret, (honest, hostile)
    )

    assert [note.output_index for note in scanned] == [0]


def test_authenticated_noncanonical_plaintext_is_skipped_not_fatal():
    victim = _victim()
    honest = _honest_output(victim)
    hostile = _noncanonical_plaintext_output(victim)

    scanned = scan_outputs_v1(
        KEM, AEAD, victim.decapsulation_key, victim.spend_secret, (hostile, honest)
    )

    assert [note.output_index for note in scanned] == [1]


def test_cursor_advances_past_hostile_outputs():
    victim = _victim()
    hostile = _commitment_mismatch_output(victim)
    honest = _honest_output(victim)
    cursor = WalletScanCursorV1()

    first = cursor.scan_chunk(
        KEM, AEAD, victim.decapsulation_key, victim.spend_secret, (hostile, honest)
    )
    assert [note.output_index for note in first] == [1]
    assert cursor.next_output_index == 2

    second = cursor.scan_chunk(
        KEM, AEAD, victim.decapsulation_key, victim.spend_secret, (_honest_output(victim, 7),)
    )
    assert [note.output_index for note in second] == [2]
    assert cursor.next_output_index == 3


def test_single_output_recovery_still_reports_the_inconsistency():
    """The batch scan contains the error; the precise single-output API does not."""
    victim = _victim()
    hostile = _commitment_mismatch_output(victim)

    with pytest.raises(NoteRecoveryError, match="does not match commitment"):
        recover_note_v1(
            KEM, AEAD, victim.decapsulation_key, victim.spend_secret, hostile
        )
