"""Canonical experimental-v1 address/output/transaction-statement codecs.

Proof bytes, network envelopes, and the proposed fixed-memo successor format are
intentionally not defined here.
"""
from __future__ import annotations

from dataclasses import dataclass

from .crypto import output_leaf
from .cryptography_backend import validate_mlkem768_public_key
from .encoding import decode_frame, decode_vec, encode_vec, frame, read_uint, u16, u64

TAG_ADDRESS = "radix/address/v1"
TAG_OUTPUT = "radix/output/v1"
TAG_STATEMENT = "radix/tx-statement/v1"
TX_VERSION_V1 = 1
MAX_ITEMS = 16

ADDRESS_FIELDS = (32, 64, 1184)
OUTPUT_FIELDS = (64, 1088, 12, (156, 668), 64)
MAX_OUTPUT_RAW_FIELD_BYTES = sum(
    width if isinstance(width, int) else max(width) for width in OUTPUT_FIELDS
)
MIN_OUTPUT_FRAME_BYTES = len(frame(TAG_OUTPUT, [bytes(64), bytes(1088), bytes(12), bytes(156), bytes(64)]))
MAX_OUTPUT_FRAME_BYTES = len(frame(TAG_OUTPUT, [bytes(64), bytes(1088), bytes(12), bytes(668), bytes(64)]))
MAX_NULLIFIER_VECTOR_BYTES = 2 + MAX_ITEMS * (4 + 64)
MAX_OUTPUT_VECTOR_BYTES = 2 + MAX_ITEMS * (4 + MAX_OUTPUT_FRAME_BYTES)
MAX_STATEMENT_BYTES = (
    5
    + 1
    + 2
    + len(TAG_STATEMENT.encode("ascii"))
    + 2
    + 7 * 4
    + 32
    + 2
    + 8
    + 64
    + 8
    + MAX_NULLIFIER_VECTOR_BYTES
    + MAX_OUTPUT_VECTOR_BYTES
)


@dataclass(frozen=True)
class OutputRecord:
    commitment: bytes
    kem_ciphertext: bytes
    nonce: bytes
    ciphertext: bytes
    leaf: bytes

    def serialize(self) -> bytes:
        return serialize_output_v1(self)

    def leaf_matches_fields(self) -> bool:
        try:
            return self.leaf == output_leaf(
                self.commitment, self.kem_ciphertext, self.nonce, self.ciphertext
            )
        except ValueError:
            return False


@dataclass(frozen=True)
class TransactionStatementV1:
    chain_id: bytes
    anchor_height: int
    root_out: bytes
    fee: int
    nullifiers: tuple[bytes, ...]
    outputs: tuple[OutputRecord, ...]

    def serialize(self) -> bytes:
        return serialize_statement_v1(self)


def validate_output_record_v1(output: OutputRecord) -> None:
    """Validate canonical public fields without dispatching instance methods."""
    if type(output) is not OutputRecord:
        raise ValueError("output record must be the canonical OutputRecord type")
    if type(output.commitment) is not bytes or len(output.commitment) != 64:
        raise ValueError("output commitment must be 64 bytes")
    if type(output.kem_ciphertext) is not bytes or len(output.kem_ciphertext) != 1088:
        raise ValueError("ML-KEM-768 ciphertext must be 1088 bytes")
    if type(output.nonce) is not bytes or len(output.nonce) != 12:
        raise ValueError("AES-GCM nonce must be 12 bytes")
    if type(output.ciphertext) is not bytes or not 156 <= len(output.ciphertext) <= 668:
        raise ValueError("experimental-v1 ciphertext length must be 156..668")
    if type(output.leaf) is not bytes or len(output.leaf) != 64:
        raise ValueError("output leaf must be 64 bytes")
    expected_leaf = output_leaf(
        output.commitment, output.kem_ciphertext, output.nonce, output.ciphertext
    )
    if output.leaf != expected_leaf:
        raise ValueError("output leaf does not match public output fields")


def serialize_output_v1(output: OutputRecord) -> bytes:
    """Serialize an output using the canonical field validator and encoder."""
    validate_output_record_v1(output)
    return frame(
        TAG_OUTPUT,
        [output.commitment, output.kem_ciphertext, output.nonce, output.ciphertext, output.leaf],
    )


def serialize_address(chain_id: bytes, spend_public: bytes, viewing_public: bytes) -> bytes:
    if type(chain_id) is not bytes or len(chain_id) != 32:
        raise ValueError("chain ID must be 32 bytes")
    if type(spend_public) is not bytes or len(spend_public) != 64:
        raise ValueError("spend public component must be 64 bytes")
    validate_mlkem768_public_key(viewing_public)
    return frame(TAG_ADDRESS, [chain_id, spend_public, viewing_public])


def parse_address(data: bytes, *, expected_chain_id: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    fields = decode_frame(data, TAG_ADDRESS, ADDRESS_FIELDS)
    validate_mlkem768_public_key(fields[2])
    if expected_chain_id is not None:
        if type(expected_chain_id) is not bytes or len(expected_chain_id) != 32:
            raise ValueError("expected chain ID must be 32 bytes")
        if fields[0] != expected_chain_id:
            raise ValueError("chain ID mismatch")
    return fields[0], fields[1], fields[2]


def parse_output_v1(data: bytes) -> OutputRecord:
    fields = decode_frame(data, TAG_OUTPUT, OUTPUT_FIELDS)
    output = OutputRecord(*fields)
    validate_output_record_v1(output)
    return output


def serialize_statement_v1(statement: TransactionStatementV1) -> bytes:
    if type(statement) is not TransactionStatementV1:
        raise ValueError("statement must be the canonical TransactionStatementV1 type")
    if type(statement.chain_id) is not bytes or len(statement.chain_id) != 32:
        raise ValueError("chain ID must be 32 bytes")
    if type(statement.anchor_height) is not int or not 0 <= statement.anchor_height < (1 << 64):
        raise ValueError("anchor height must be a U64")
    if type(statement.root_out) is not bytes or len(statement.root_out) != 64:
        raise ValueError("output root must be 64 bytes")
    if type(statement.fee) is not int or not 0 <= statement.fee < (1 << 64):
        raise ValueError("fee must be a U64")
    if type(statement.nullifiers) is not tuple:
        raise ValueError("nullifier vector must be a canonical tuple")
    if type(statement.outputs) is not tuple:
        raise ValueError("output vector must be a canonical tuple")
    if not 1 <= len(statement.nullifiers) <= MAX_ITEMS:
        raise ValueError("input count must be 1..16")
    if not 1 <= len(statement.outputs) <= MAX_ITEMS:
        raise ValueError("output count must be 1..16")
    if any(type(nf) is not bytes or len(nf) != 64 for nf in statement.nullifiers):
        raise ValueError("nullifiers must each be 64 bytes")
    if len(set(statement.nullifiers)) != len(statement.nullifiers):
        raise ValueError("duplicate nullifier")
    if any(type(output) is not OutputRecord for output in statement.outputs):
        raise ValueError("statement outputs must use the canonical OutputRecord type")
    encoded_outputs = [serialize_output_v1(output) for output in statement.outputs]
    commitments = [output.commitment for output in statement.outputs]
    if len(set(commitments)) != len(commitments):
        raise ValueError("duplicate output commitment")

    encoded = frame(
        TAG_STATEMENT,
        [
            statement.chain_id,
            u16(TX_VERSION_V1),
            u64(statement.anchor_height),
            statement.root_out,
            u64(statement.fee),
            encode_vec(statement.nullifiers, max_count=MAX_ITEMS),
            encode_vec(encoded_outputs, max_count=MAX_ITEMS),
        ],
    )
    if len(encoded) > MAX_STATEMENT_BYTES:
        raise ValueError("transaction statement exceeds size limit")
    return encoded


def parse_statement_v1(
    data: bytes,
    *,
    expected_chain_id: bytes | None = None,
) -> TransactionStatementV1:
    if type(data) is not bytes:
        raise ValueError("frame encoding must be bytes")
    if len(data) > MAX_STATEMENT_BYTES:
        raise ValueError("transaction statement exceeds size limit")
    fields = decode_frame(
        data,
        TAG_STATEMENT,
        [
            32,
            2,
            8,
            64,
            8,
            (2 + 4 + 64, MAX_NULLIFIER_VECTOR_BYTES),
            (2 + 4 + MIN_OUTPUT_FRAME_BYTES, MAX_OUTPUT_VECTOR_BYTES),
        ],
    )
    chain_id, version_bytes, anchor_bytes, root_out, fee_bytes, nf_vec, output_vec = fields
    if expected_chain_id is not None:
        if type(expected_chain_id) is not bytes or len(expected_chain_id) != 32:
            raise ValueError("expected chain ID must be 32 bytes")
        if chain_id != expected_chain_id:
            raise ValueError("chain ID mismatch")

    version, end = read_uint(version_bytes, 0, 2)
    if end != len(version_bytes) or version != TX_VERSION_V1:
        raise ValueError("unsupported transaction version")
    anchor_height, end = read_uint(anchor_bytes, 0, 8)
    if end != len(anchor_bytes):
        raise ValueError("invalid anchor height")
    fee, end = read_uint(fee_bytes, 0, 8)
    if end != len(fee_bytes):
        raise ValueError("invalid fee")

    nullifiers = decode_vec(
        nf_vec,
        min_count=1,
        max_count=MAX_ITEMS,
        max_item_length=64,
        exact_item_length=64,
    )
    if len(set(nullifiers)) != len(nullifiers):
        raise ValueError("duplicate nullifier")

    output_frames = decode_vec(
        output_vec,
        min_count=1,
        max_count=MAX_ITEMS,
        max_item_length=MAX_OUTPUT_FRAME_BYTES,
    )
    outputs = tuple(parse_output_v1(item) for item in output_frames)
    commitments = [output.commitment for output in outputs]
    if len(set(commitments)) != len(commitments):
        raise ValueError("duplicate output commitment")

    return TransactionStatementV1(
        chain_id=chain_id,
        anchor_height=anchor_height,
        root_out=root_out,
        fee=fee,
        nullifiers=tuple(nullifiers),
        outputs=outputs,
    )
