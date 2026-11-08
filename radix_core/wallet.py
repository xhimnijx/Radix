"""Experimental-v1 wallet-key, note creation/recovery, and scan primitives."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from hmac import compare_digest
from threading import Lock
from typing import Literal

from .crypto import note_commitment, note_owner, nullifier, output_leaf, spend_public
from .encoding import U64_MAX
from .entropy import (
    SYSTEM_ENTROPY,
    EntropySource,
    draw_aead_nonce_v1,
    draw_note_blinding,
    draw_spend_secret,
)
from .memo import MEMO_MAX, decode_plaintext_v1, encode_plaintext_v1
from .merkle import DEPTH as OUTPUT_TREE_DEPTH, verify_membership
from .providers import (
    AeadAuthenticationError,
    AeadNonceRegistry,
    Aes256GcmProvider,
    MlKem768KeygenProvider,
    MlKem768Provider,
    MLKEM768_DECAPSULATION_KEY_BYTES,
    MLKEM768_PUBLIC_KEY_BYTES,
    decapsulate_v1,
    decrypt_note_v1,
    encapsulate_v1,
    encrypt_note_v1,
    generate_keypair_v1,
)
from .wire import (
    MAX_OUTPUT_RAW_FIELD_BYTES,
    OutputRecord,
    parse_address,
    serialize_address,
    serialize_output_v1,
    validate_output_record_v1,
)

MAX_SCAN_CHUNK_OUTPUTS = 1024
MAX_SCAN_CHUNK_RAW_FIELD_BYTES = MAX_SCAN_CHUNK_OUTPUTS * MAX_OUTPUT_RAW_FIELD_BYTES
MAX_SCAN_CHUNK_AUTH_PATH_BYTES = (
    MAX_SCAN_CHUNK_OUTPUTS * OUTPUT_TREE_DEPTH * 64
)
WALLET_SCAN_CURSOR_SNAPSHOT_MAGIC_V1 = b"RDXWCS01"
WALLET_SCAN_CURSOR_SNAPSHOT_MAX_BYTES_V1 = 8 + 9 + 1 + 1 + 64 + 9


class NoteRecoveryError(ValueError):
    """The public output or its authenticated opening is inconsistent."""


@dataclass(frozen=True)
class RecoveredNoteV1:
    value: int = field(repr=False)
    rho: bytes = field(repr=False)
    randomness: bytes = field(repr=False)
    memo: bytes = field(repr=False)
    nullifier: bytes = field(repr=False)


@dataclass(frozen=True)
class ScannedNoteV1:
    """A recovered note with its claimed absolute output-tree position."""

    output_index: int
    note: RecoveredNoteV1


@dataclass(frozen=True)
class CreatedNoteV1:
    """A freshly encrypted output plus confidential local proof/opening material."""

    output: OutputRecord
    owner: bytes = field(repr=False)
    recipient_spend_public_key: bytes = field(repr=False)
    kem_shared_secret: bytes = field(repr=False)
    value: int = field(repr=False)
    rho: bytes = field(repr=False)
    randomness: bytes = field(repr=False)
    memo: bytes = field(repr=False)


@dataclass(frozen=True)
class WalletKeysV1:
    """Raw key material; callers are responsible for secure custody."""

    spend_secret: bytes = field(repr=False)
    spend_public_key: bytes
    viewing_public_key: bytes
    decapsulation_key: bytes = field(repr=False)


@dataclass(frozen=True)
class WalletScanCursorSnapshotV1:
    """Persistable local scan state; it does not authenticate its contents."""

    next_output_index: int
    scan_mode: Literal["legacy", "authenticated"] | None
    trusted_root: bytes | None = None
    trusted_leaf_count: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.next_output_index) is not int
            or not 0 <= self.next_output_index <= U64_MAX + 1
        ):
            raise ValueError("snapshot output index is outside the depth-64 range")
        if self.scan_mode is not None and (
            type(self.scan_mode) is not str
            or self.scan_mode not in ("legacy", "authenticated")
        ):
            raise ValueError("snapshot scan mode is invalid")
        if self.scan_mode == "authenticated":
            if type(self.trusted_root) is not bytes or len(self.trusted_root) != 64:
                raise ValueError("authenticated snapshot requires a 64-byte trusted root")
            if self.trusted_leaf_count is not None and (
                type(self.trusted_leaf_count) is not int
                or not 0 <= self.trusted_leaf_count <= U64_MAX + 1
            ):
                raise ValueError("snapshot trusted leaf count is outside [0, 2^64]")
        elif self.trusted_root is not None or self.trusted_leaf_count is not None:
            raise ValueError("only authenticated snapshots may contain a root/count")

    def to_bytes(self) -> bytes:
        """Encode a canonical, bounded local checkpoint (not an authenticated one)."""
        # Revalidate in case a caller bypassed frozen-dataclass construction.
        self.__post_init__()
        mode = {None: 0, "legacy": 1, "authenticated": 2}[self.scan_mode]
        has_count = self.trusted_leaf_count is not None
        encoded = bytearray(WALLET_SCAN_CURSOR_SNAPSHOT_MAGIC_V1)
        encoded.extend(self.next_output_index.to_bytes(9, "little"))
        encoded.extend((mode, int(has_count)))
        if self.scan_mode == "authenticated":
            assert self.trusted_root is not None
            encoded.extend(self.trusted_root)
        if has_count:
            encoded.extend(self.trusted_leaf_count.to_bytes(9, "little"))
        return bytes(encoded)

    @classmethod
    def from_bytes(cls, data: bytes) -> WalletScanCursorSnapshotV1:
        """Decode a strict local checkpoint; callers must authenticate its source."""
        if type(data) is not bytes:
            raise ValueError("wallet cursor snapshot encoding must be bytes")
        if not (
            8 + 9 + 2 <= len(data) <= WALLET_SCAN_CURSOR_SNAPSHOT_MAX_BYTES_V1
        ):
            raise ValueError("wallet cursor snapshot encoding has an invalid size")
        if data[:8] != WALLET_SCAN_CURSOR_SNAPSHOT_MAGIC_V1:
            raise ValueError("wallet cursor snapshot version is invalid")

        next_output_index = int.from_bytes(data[8:17], "little")
        mode_tag, has_count = data[17], data[18]
        modes = {0: None, 1: "legacy", 2: "authenticated"}
        if mode_tag not in modes or has_count not in (0, 1):
            raise ValueError("wallet cursor snapshot flags are invalid")
        scan_mode = modes[mode_tag]
        if has_count and scan_mode != "authenticated":
            raise ValueError("only authenticated snapshots may contain a leaf count")

        offset = 19
        trusted_root = None
        trusted_leaf_count = None
        if scan_mode == "authenticated":
            if len(data) < offset + 64:
                raise ValueError("authenticated snapshot is truncated")
            trusted_root = data[offset : offset + 64]
            offset += 64
        if has_count:
            if len(data) < offset + 9:
                raise ValueError("authenticated snapshot leaf count is truncated")
            trusted_leaf_count = int.from_bytes(data[offset : offset + 9], "little")
            offset += 9
        if offset != len(data):
            raise ValueError("wallet cursor snapshot has trailing bytes")
        return cls(
            next_output_index=next_output_index,
            scan_mode=scan_mode,
            trusted_root=trusted_root,
            trusted_leaf_count=trusted_leaf_count,
        )


def _snapshot_output_v1(output: OutputRecord) -> OutputRecord:
    if type(output) is not OutputRecord:
        raise NoteRecoveryError("output record type is invalid")
    try:
        # Detach the record shell but reuse field references: validation below
        # requires exact immutable bytes, so copying up to 1,941,504 raw field
        # bytes for a full scan chunk is unnecessary and callbacks cannot rewrite them.
        snapshot = OutputRecord(
            commitment=output.commitment,
            kem_ciphertext=output.kem_ciphertext,
            nonce=output.nonce,
            ciphertext=output.ciphertext,
            leaf=output.leaf,
        )
        validate_output_record_v1(snapshot)
    except (AttributeError, TypeError, ValueError) as exc:
        raise NoteRecoveryError(f"output record is noncanonical: {exc}") from exc
    return snapshot


def generate_wallet_keys_v1(
    kem_keygen_provider: MlKem768KeygenProvider,
    *,
    entropy_source: EntropySource = SYSTEM_ENTROPY,
) -> WalletKeysV1:
    """Assemble Candidate-A spend and ML-KEM key material.

    This helper returns unencrypted secrets and provides no secure storage,
    backup, seed derivation, or zeroization.
    """
    spend_secret = draw_spend_secret(entropy_source)
    spend_public_key = spend_public(spend_secret)
    kem_keypair = generate_keypair_v1(kem_keygen_provider)
    return WalletKeysV1(
        spend_secret=spend_secret,
        spend_public_key=spend_public_key,
        viewing_public_key=kem_keypair.public_key,
        decapsulation_key=kem_keypair.decapsulation_key,
    )


def serialize_wallet_address_v1(keys: WalletKeysV1, chain_id: bytes) -> bytes:
    """Serialize a wallet address after checking its spend-key relation.

    This confirms ``spend_public_key == spend_public(spend_secret)`` and
    delegates canonical ML-KEM public-key validation to the concrete backend.
    It does not prove control of the corresponding decapsulation key or recipient
    ownership.
    """
    if type(keys) is not WalletKeysV1:
        raise ValueError("wallet keys must use the canonical WalletKeysV1 type")
    if type(keys.spend_public_key) is not bytes or len(keys.spend_public_key) != 64:
        raise ValueError("wallet spend public key must be exactly 64 bytes")
    expected_spend_public_key = spend_public(keys.spend_secret)
    if not compare_digest(expected_spend_public_key, keys.spend_public_key):
        raise ValueError("wallet spend public key does not match its secret")
    return serialize_address(chain_id, keys.spend_public_key, keys.viewing_public_key)


def _validate_note_output_request(
    viewing_public_key: bytes,
    value: int,
    memo: bytes,
    nonce_registry: AeadNonceRegistry | None,
) -> None:
    if (
        type(viewing_public_key) is not bytes
        or len(viewing_public_key) != MLKEM768_PUBLIC_KEY_BYTES
    ):
        raise ValueError("ML-KEM-768 public key must be exactly 1184 bytes")
    if type(value) is not int or not 1 <= value <= U64_MAX:
        raise ValueError("note value must be a nonzero U64")
    if type(memo) is not bytes or len(memo) > MEMO_MAX:
        raise ValueError("memo must be bytes of length at most 512")
    if nonce_registry is not None and type(nonce_registry) is not AeadNonceRegistry:
        raise ValueError("nonce registry must be the canonical AeadNonceRegistry type")


def create_note_output_v1(
    kem_provider: MlKem768Provider,
    aead_provider: Aes256GcmProvider,
    viewing_public_key: bytes,
    spend_secret: bytes,
    value: int,
    memo: bytes = b"",
    *,
    entropy_source: EntropySource = SYSTEM_ENTROPY,
    nonce_registry: AeadNonceRegistry | None = None,
) -> CreatedNoteV1:
    """Create an experimental-v1 self-output using a spend secret.

    For a transfer to another wallet, use :func:`create_note_output_to_v1`
    with the recipient's spend public key. This compatibility helper derives
    the local spend public key itself. The key encapsulation and AEAD must be
    real, reviewed implementations for any security use. Protect all returned
    opening and proof-witness material as wallet secret data.
    """
    _validate_note_output_request(viewing_public_key, value, memo, nonce_registry)
    recipient_spend_public_key = spend_public(spend_secret)
    return _create_note_output_with_spend_public_key(
        kem_provider,
        aead_provider,
        viewing_public_key,
        recipient_spend_public_key,
        value,
        memo,
        entropy_source=entropy_source,
        nonce_registry=nonce_registry,
    )


def create_note_output_to_v1(
    kem_provider: MlKem768Provider,
    aead_provider: Aes256GcmProvider,
    viewing_public_key: bytes,
    recipient_spend_public_key: bytes,
    value: int,
    memo: bytes = b"",
    *,
    entropy_source: EntropySource = SYSTEM_ENTROPY,
    nonce_registry: AeadNonceRegistry | None = None,
) -> CreatedNoteV1:
    """Create an output for a recipient's public address components.

    This accepts only the fixed-width spend key and a viewing public key; the
    caller is responsible for obtaining them from a canonical recipient
    address. Prefer :func:`create_note_output_for_address_v1` to have the
    address and expected chain ID validated together. Neither helper proves
    recipient ownership, ML-KEM encapsulation provenance, or network acceptance.
    Returned shared-secret/opening fields are confidential local witness
    material and must not be logged or published.
    """
    _validate_note_output_request(viewing_public_key, value, memo, nonce_registry)
    if (
        type(recipient_spend_public_key) is not bytes
        or len(recipient_spend_public_key) != 64
    ):
        raise ValueError("recipient spend public key must be exactly 64 bytes")
    return _create_note_output_with_spend_public_key(
        kem_provider,
        aead_provider,
        viewing_public_key,
        recipient_spend_public_key,
        value,
        memo,
        entropy_source=entropy_source,
        nonce_registry=nonce_registry,
    )


def create_note_output_for_address_v1(
    kem_provider: MlKem768Provider,
    aead_provider: Aes256GcmProvider,
    recipient_address: bytes,
    value: int,
    memo: bytes = b"",
    *,
    expected_chain_id: bytes,
    entropy_source: EntropySource = SYSTEM_ENTROPY,
    nonce_registry: AeadNonceRegistry | None = None,
) -> CreatedNoteV1:
    """Create an output from a canonical, chain-bound recipient address.

    The address parser validates its framing, ML-KEM public-key encoding, and
    the caller-supplied expected chain ID before any note entropy is consumed.
    This does not prove recipient ownership, KEM provenance, or network
    acceptance; returned witness material remains confidential local data.
    """
    _, recipient_spend_public_key, viewing_public_key = parse_address(
        recipient_address,
        expected_chain_id=expected_chain_id,
    )
    return create_note_output_to_v1(
        kem_provider,
        aead_provider,
        viewing_public_key,
        recipient_spend_public_key,
        value,
        memo,
        entropy_source=entropy_source,
        nonce_registry=nonce_registry,
    )


def _create_note_output_with_spend_public_key(
    kem_provider: MlKem768Provider,
    aead_provider: Aes256GcmProvider,
    viewing_public_key: bytes,
    recipient_spend_public_key: bytes,
    value: int,
    memo: bytes,
    *,
    entropy_source: EntropySource,
    nonce_registry: AeadNonceRegistry | None,
) -> CreatedNoteV1:
    rho, randomness = draw_note_blinding(entropy_source)
    nonce = draw_aead_nonce_v1(entropy_source)
    plaintext = encode_plaintext_v1(value, rho, randomness, memo)
    encapsulation = encapsulate_v1(kem_provider, viewing_public_key)
    owner = note_owner(recipient_spend_public_key, encapsulation.shared_secret)
    commitment = note_commitment(owner, value, rho, randomness)
    ciphertext = encrypt_note_v1(
        aead_provider,
        encapsulation.shared_secret,
        encapsulation.ciphertext,
        commitment,
        nonce,
        plaintext,
        nonce_registry=nonce_registry,
    )
    output = OutputRecord(
        commitment=commitment,
        kem_ciphertext=encapsulation.ciphertext,
        nonce=nonce,
        ciphertext=ciphertext,
        leaf=output_leaf(commitment, encapsulation.ciphertext, nonce, ciphertext),
    )
    serialize_output_v1(output)
    return CreatedNoteV1(
        output=output,
        owner=owner,
        recipient_spend_public_key=recipient_spend_public_key,
        kem_shared_secret=encapsulation.shared_secret,
        value=value,
        rho=rho,
        randomness=randomness,
        memo=memo,
    )


def _recover_note_from_snapshot_v1(
    kem_provider: MlKem768Provider,
    aead_provider: Aes256GcmProvider,
    decapsulation_key: bytes,
    spend_secret: bytes,
    spend_public_key: bytes,
    snapshot: OutputRecord,
) -> RecoveredNoteV1 | None:
    """Recover from a previously validated immutable output snapshot."""
    shared_secret = decapsulate_v1(
        kem_provider,
        decapsulation_key,
        snapshot.kem_ciphertext,
    )
    try:
        plaintext = decrypt_note_v1(
            aead_provider,
            shared_secret,
            snapshot.kem_ciphertext,
            snapshot.commitment,
            snapshot.nonce,
            snapshot.ciphertext,
        )
    except AeadAuthenticationError:
        return None

    value, rho, randomness, memo = decode_plaintext_v1(plaintext)
    owner = note_owner(spend_public_key, shared_secret)
    expected_commitment = note_commitment(owner, value, rho, randomness)
    if not compare_digest(expected_commitment, snapshot.commitment):
        raise NoteRecoveryError("authenticated note opening does not match commitment")

    return RecoveredNoteV1(
        value=value,
        rho=rho,
        randomness=randomness,
        memo=memo,
        nullifier=nullifier(spend_secret, shared_secret, rho),
    )


def recover_note_v1(
    kem_provider: MlKem768Provider,
    aead_provider: Aes256GcmProvider,
    decapsulation_key: bytes,
    spend_secret: bytes,
    output: OutputRecord,
) -> RecoveredNoteV1 | None:
    """Recover an owned output, returning ``None`` only on AEAD auth failure.

    A successful AEAD decrypt is not sufficient: the recovered opening must
    recompute the public commitment for ``spend_secret``. ``None`` is the
    expected scan result for a non-recipient output under ML-KEM implicit
    rejection. Provider/operational errors are not treated as non-matches. The
    canonical fields are snapshotted before invoking providers so later mutation
    of the caller-owned frozen record cannot change the validated context.
    """
    snapshot = _snapshot_output_v1(output)
    try:
        spend_public_key = spend_public(spend_secret)
    except ValueError as exc:
        raise NoteRecoveryError(f"spend secret is invalid: {exc}") from exc
    return _recover_note_from_snapshot_v1(
        kem_provider,
        aead_provider,
        decapsulation_key,
        spend_secret,
        spend_public_key,
        snapshot,
    )


def _validate_scan_range(
    outputs: tuple[OutputRecord, ...], start_index: int
) -> None:
    if type(outputs) is not tuple:
        raise ValueError("scan outputs must be a canonical tuple")
    if len(outputs) > MAX_SCAN_CHUNK_OUTPUTS:
        raise ValueError(f"scan chunk exceeds {MAX_SCAN_CHUNK_OUTPUTS} outputs")
    if type(start_index) is not int or not 0 <= start_index <= U64_MAX + 1:
        raise ValueError("scan start index must be a U64 leaf index or the exclusive tree end")
    if start_index + len(outputs) > U64_MAX + 1:
        raise ValueError("scan chunk exceeds the depth-64 output index range")


def _validate_trusted_root(trusted_root: bytes) -> None:
    if type(trusted_root) is not bytes or len(trusted_root) != 64:
        raise ValueError("trusted output root must be exactly 64 bytes")


def _validate_trusted_leaf_count_value(trusted_leaf_count: int | None) -> None:
    if trusted_leaf_count is not None and (
        type(trusted_leaf_count) is not int
        or not 0 <= trusted_leaf_count <= U64_MAX + 1
    ):
        raise ValueError("trusted leaf count must be an integer in [0, 2^64]")


def _validate_trusted_leaf_count(
    outputs: tuple[OutputRecord, ...], start_index: int, trusted_leaf_count: int | None
) -> None:
    _validate_trusted_leaf_count_value(trusted_leaf_count)
    if trusted_leaf_count is not None and start_index + len(outputs) > trusted_leaf_count:
        raise ValueError("scan range exceeds trusted leaf count")


def _scan_credentials(
    decapsulation_key: bytes, spend_secret: bytes
) -> bytes:
    # Reject malformed credentials before doing up to 1,024 leaf hashes or
    # snapshot constructions. These checks invoke no caller-supplied provider.
    if (
        type(decapsulation_key) is not bytes
        or len(decapsulation_key) != MLKEM768_DECAPSULATION_KEY_BYTES
    ):
        raise ValueError("ML-KEM-768 private seed must be exactly 64 bytes")
    try:
        return spend_public(spend_secret)
    except ValueError as exc:
        raise NoteRecoveryError(f"spend secret is invalid: {exc}") from exc


def _recover_scan_snapshots(
    kem_provider: MlKem768Provider,
    aead_provider: Aes256GcmProvider,
    decapsulation_key: bytes,
    spend_secret: bytes,
    spend_public_key: bytes,
    snapshots: tuple[OutputRecord, ...],
    start_index: int,
) -> tuple[ScannedNoteV1, ...]:
    recovered: list[ScannedNoteV1] = []
    for offset, output in enumerate(snapshots):
        note = _recover_note_from_snapshot_v1(
            kem_provider,
            aead_provider,
            decapsulation_key,
            spend_secret,
            spend_public_key,
            output,
        )
        if note is not None:
            recovered.append(ScannedNoteV1(output_index=start_index + offset, note=note))
    return tuple(recovered)


def scan_outputs_v1(
    kem_provider: MlKem768Provider,
    aead_provider: Aes256GcmProvider,
    decapsulation_key: bytes,
    spend_secret: bytes,
    outputs: tuple[OutputRecord, ...],
    *,
    start_index: int = 0,
) -> tuple[ScannedNoteV1, ...]:
    """Recover owned notes from one bounded chunk with caller-asserted positions.

    This legacy convenience helper does not authenticate chunk source,
    continuity, or root. Prefer ``scan_authenticated_outputs_v1`` when a trusted
    output-tree root and per-output authentication paths are available.

    Use only trusted local KEM/AEAD adapters. The scan sends each decapsulation
    key/ciphertext to the KEM adapter and shared secrets/ciphertexts to the AEAD
    adapter; per-output calls and AEAD success/failure expose scan order,
    progress, matches, and timing. These interfaces provide no remote isolation
    or metadata-hiding protocol.
    """
    _validate_scan_range(outputs, start_index)
    spend_public_key = _scan_credentials(decapsulation_key, spend_secret)
    # Snapshot/validate the entire chunk before any provider callback can mutate
    # caller-owned records not yet scanned.
    snapshots = tuple(_snapshot_output_v1(output) for output in outputs)
    return _recover_scan_snapshots(
        kem_provider,
        aead_provider,
        decapsulation_key,
        spend_secret,
        spend_public_key,
        snapshots,
        start_index,
    )


def scan_authenticated_outputs_v1(
    kem_provider: MlKem768Provider,
    aead_provider: Aes256GcmProvider,
    decapsulation_key: bytes,
    spend_secret: bytes,
    outputs: tuple[OutputRecord, ...],
    authentication_paths: tuple[tuple[bytes, ...], ...],
    trusted_root: bytes,
    *,
    start_index: int = 0,
    trusted_leaf_count: int | None = None,
) -> tuple[ScannedNoteV1, ...]:
    """Authenticate each output's index/leaf against a caller-trusted root, then scan.

    The caller must authenticate ``trusted_root`` and supply one depth-64 path
    per output. Optionally supply the leaf count authenticated for that same root
    to reject ranges beyond the populated prefix. Membership does not establish
    chunk-source provenance or completeness. For the 1,024-output maximum, path
    digests total at most 4 MiB of raw bytes; path/object overhead is additional.
    Use only trusted local KEM/AEAD adapters: this per-output scan gives them
    key material and exposes scan order, progress, AEAD matches, and timing.
    No remote isolation, batching privacy, or metadata-hiding protocol is
    provided here.
    """
    _validate_scan_range(outputs, start_index)
    _validate_trusted_leaf_count(outputs, start_index, trusted_leaf_count)
    _validate_trusted_root(trusted_root)
    if type(authentication_paths) is not tuple or len(authentication_paths) != len(outputs):
        raise ValueError("scan requires exactly one authentication path per output")
    for path in authentication_paths:
        if type(path) is not tuple or len(path) != OUTPUT_TREE_DEPTH:
            raise ValueError("each output authentication path must contain 64 siblings")
        if any(type(sibling) is not bytes or len(sibling) != 64 for sibling in path):
            raise ValueError("each output authentication sibling must be 64 bytes")

    spend_public_key = _scan_credentials(decapsulation_key, spend_secret)
    # One immutable snapshot feeds both membership checks and recovery, avoiding
    # a mutation window between authenticating the leaf and scanning the record.
    snapshots = tuple(_snapshot_output_v1(output) for output in outputs)
    for offset, (output, path) in enumerate(zip(snapshots, authentication_paths)):
        if not verify_membership(output.leaf, start_index + offset, path, trusted_root):
            raise NoteRecoveryError(
                f"output at index {start_index + offset} is not in the trusted root"
            )
    return _recover_scan_snapshots(
        kem_provider,
        aead_provider,
        decapsulation_key,
        spend_secret,
        spend_public_key,
        snapshots,
        start_index,
    )


class WalletScanCursorV1:
    """Position tracker for sequential bounded wallet scans.

    The cursor advances only when a whole chunk scans successfully. An
    overlapping call is rejected and can be retried after the active call ends;
    this avoids waiting inside callbacks and prevents ambiguous ordering. The
    legacy ``scan_chunk`` method accepts caller-asserted positions;
    ``scan_authenticated_chunk`` additionally checks membership against a
    supplied root. Neither authenticates that root, the chain source, or scan
    completeness. Its first successful chunk fixes the cursor to either legacy
    or authenticated mode for its lifetime; authenticated mode additionally pins
    the exact root/count pair. Construct a new cursor when changing modes or
    checkpoints. Persist it with the corresponding range/root checkpoint, not as
    an independent source of chain truth.
    """

    __slots__ = (
        "_next_output_index",
        "_scanning",
        "_scan_lock",
        "_scan_mode",
        "_trusted_checkpoint",
    )

    def __init__(self, start_index: int = 0) -> None:
        if type(start_index) is not int or not 0 <= start_index <= U64_MAX + 1:
            raise ValueError(
                "scan start index must be a U64 leaf index or the exclusive tree end"
            )
        self._next_output_index = start_index
        self._scanning = False
        self._scan_lock = Lock()
        self._scan_mode: Literal["legacy", "authenticated"] | None = None
        self._trusted_checkpoint: tuple[bytes, int | None] | None = None

    @property
    def next_output_index(self) -> int:
        """Next local output position; this is not an authenticated chain tip."""
        with self._scan_lock:
            return self._next_output_index

    def snapshot(self) -> WalletScanCursorSnapshotV1:
        """Return immutable state for caller-managed persistence.

        Snapshots are unavailable during an active provider scan, and restoring
        one does not authenticate its root, count, prior scan history, or source.
        """
        with self._scan_lock:
            if self._scanning:
                raise RuntimeError("cannot snapshot an active wallet scan")
            checkpoint = self._trusted_checkpoint
            return WalletScanCursorSnapshotV1(
                next_output_index=self._next_output_index,
                scan_mode=self._scan_mode,
                trusted_root=checkpoint[0] if checkpoint is not None else None,
                trusted_leaf_count=checkpoint[1] if checkpoint is not None else None,
            )

    @classmethod
    def from_snapshot(
        cls, snapshot: WalletScanCursorSnapshotV1
    ) -> WalletScanCursorV1:
        """Restore local state without authenticating its checkpoint or position.

        For persisted bytes used in an authenticated scan, prefer
        :meth:`from_authenticated_snapshot_bytes` with an independently trusted
        root, leaf count, and expected next position.
        """
        if type(snapshot) is not WalletScanCursorSnapshotV1:
            raise ValueError("wallet cursor snapshot has the wrong type")
        snapshot = WalletScanCursorSnapshotV1(
            next_output_index=snapshot.next_output_index,
            scan_mode=snapshot.scan_mode,
            trusted_root=snapshot.trusted_root,
            trusted_leaf_count=snapshot.trusted_leaf_count,
        )
        cursor = cls(start_index=snapshot.next_output_index)
        cursor._scan_mode = snapshot.scan_mode
        if snapshot.scan_mode == "authenticated":
            # __post_init__ has enforced the root's canonical fixed-size encoding.
            assert snapshot.trusted_root is not None
            cursor._trusted_checkpoint = (
                snapshot.trusted_root,
                snapshot.trusted_leaf_count,
            )
        return cursor

    @classmethod
    def from_authenticated_snapshot_bytes(
        cls,
        encoded: bytes,
        *,
        trusted_root: bytes,
        trusted_leaf_count: int,
        expected_next_output_index: int,
    ) -> WalletScanCursorV1:
        """Restore only when persisted state matches independently trusted context.

        The caller must authenticate the root/count together for the same
        checkpoint and supply an independently trusted next position. This checks
        equality only, not prior scan completeness, source continuity, or snapshot
        authenticity by itself.
        """
        if type(trusted_root) is not bytes or len(trusted_root) != 64:
            raise ValueError("trusted output root must be exactly 64 bytes")
        if (
            type(trusted_leaf_count) is not int
            or not 0 <= trusted_leaf_count <= U64_MAX + 1
        ):
            raise ValueError("trusted leaf count is outside [0, 2^64]")
        if (
            type(expected_next_output_index) is not int
            or not 0 <= expected_next_output_index <= U64_MAX + 1
        ):
            raise ValueError("expected output index is outside the depth-64 range")
        if expected_next_output_index > trusted_leaf_count:
            raise ValueError("expected output index exceeds trusted leaf count")

        snapshot = WalletScanCursorSnapshotV1.from_bytes(encoded)
        if snapshot.scan_mode != "authenticated":
            raise ValueError("authenticated restore requires an authenticated snapshot")
        assert snapshot.trusted_root is not None
        if not compare_digest(snapshot.trusted_root, trusted_root):
            raise ValueError("snapshot root differs from caller-authenticated root")
        if snapshot.trusted_leaf_count != trusted_leaf_count:
            raise ValueError("snapshot leaf count differs from caller-authenticated count")
        if snapshot.next_output_index != expected_next_output_index:
            raise ValueError("snapshot position differs from caller-expected index")
        return cls.from_snapshot(snapshot)

    def _scan_chunk(
        self,
        outputs: tuple[OutputRecord, ...],
        scan: Callable[[int], tuple[ScannedNoteV1, ...]],
        *,
        mode: Literal["legacy", "authenticated"],
        checkpoint: tuple[bytes, int | None] | None = None,
    ) -> tuple[ScannedNoteV1, ...]:
        with self._scan_lock:
            if self._scanning:
                raise RuntimeError("wallet scan cursor is already scanning")
            if type(mode) is not str or mode not in ("legacy", "authenticated"):
                raise ValueError("wallet scan cursor mode is invalid")
            if self._scan_mode is not None and mode != self._scan_mode:
                raise ValueError("wallet scan cursor cannot switch scan modes")
            if (
                self._trusted_checkpoint is not None
                and checkpoint != self._trusted_checkpoint
            ):
                raise ValueError("scan checkpoint differs from cursor checkpoint")
            start_index = self._next_output_index
            self._scanning = True

        try:
            scanned = scan(start_index)
        except BaseException:
            with self._scan_lock:
                self._scanning = False
            raise
        with self._scan_lock:
            self._next_output_index = start_index + len(outputs)
            if self._scan_mode is None:
                self._scan_mode = mode
            if checkpoint is not None and self._trusted_checkpoint is None:
                self._trusted_checkpoint = checkpoint
            self._scanning = False
        return scanned

    def scan_chunk(
        self,
        kem_provider: MlKem768Provider,
        aead_provider: Aes256GcmProvider,
        decapsulation_key: bytes,
        spend_secret: bytes,
        outputs: tuple[OutputRecord, ...],
    ) -> tuple[ScannedNoteV1, ...]:
        """Scan exactly the next chunk and advance only after success.

        Overlapping calls fail fast; a caller may retry after the active scan
        completes. The state lock is released while invoking providers so
        provider callbacks cannot hold it across arbitrary external code.
        """
        return self._scan_chunk(
            outputs,
            lambda start_index: scan_outputs_v1(
                kem_provider,
                aead_provider,
                decapsulation_key,
                spend_secret,
                outputs,
                start_index=start_index,
            ),
            mode="legacy",
        )

    def scan_authenticated_chunk(
        self,
        kem_provider: MlKem768Provider,
        aead_provider: Aes256GcmProvider,
        decapsulation_key: bytes,
        spend_secret: bytes,
        outputs: tuple[OutputRecord, ...],
        authentication_paths: tuple[tuple[bytes, ...], ...],
        trusted_root: bytes,
        *,
        trusted_leaf_count: int | None = None,
    ) -> tuple[ScannedNoteV1, ...]:
        """Authenticate this sequential chunk against a caller-trusted root.

        The current cursor position supplies the expected start index. Optionally
        enforce a leaf count authenticated for the same root/checkpoint. The first
        successful chunk fixes the cursor mode; authenticated mode also pins the
        exact root/count, rejecting later mode switches or checkpoint changes.
        Cursor advancement and pinning occur only after every check and note scan
        succeeds. Root/count/checkpoint
        authentication remains the caller's responsibility.
        """
        # Validate values before _scan_chunk compares its checkpoint with the
        # cursor's pinned tuple. Only exact bytes/int primitives may reach that
        # comparison; arbitrary caller-defined __eq__ methods must not run while
        # the scan-state lock is held.
        _validate_trusted_root(trusted_root)
        _validate_trusted_leaf_count_value(trusted_leaf_count)
        return self._scan_chunk(
            outputs,
            lambda start_index: scan_authenticated_outputs_v1(
                kem_provider,
                aead_provider,
                decapsulation_key,
                spend_secret,
                outputs,
                authentication_paths,
                trusted_root,
                start_index=start_index,
                trusted_leaf_count=trusted_leaf_count,
            ),
            mode="authenticated",
            checkpoint=(trusted_root, trusted_leaf_count),
        )
