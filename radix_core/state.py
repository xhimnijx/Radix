"""Atomic full-node block transition model with fail-closed verifier hooks.

This is an in-memory reference state machine, not a consensus node. Proof/mint
validity is delegated to mandatory injected callbacks; no stub accepts by default.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from .encoding import U64_MAX
from .merkle import EMPTY_HASHES, OutputTree, check_append_capacity
from .rules import BlockHeaderRef, anchor_ok
from .wire import (
    OutputRecord,
    TransactionStatementV1,
    parse_statement_v1,
    serialize_output_v1,
    serialize_statement_v1,
)


class BlockRejected(ValueError):
    """The proposed block cannot be applied atomically."""


MAX_MINT_OUTPUTS = 16
MAX_MINT_AMOUNT = MAX_MINT_OUTPUTS * U64_MAX


@dataclass(frozen=True)
class Transfer:
    statement: TransactionStatementV1
    proof: bytes


@dataclass(frozen=True)
class Mint:
    outputs: tuple[OutputRecord, ...]
    proof: bytes


@dataclass(frozen=True, init=False)
class LedgerState:
    """Immutable defensive snapshot, not an authenticated checkpoint.

    The output root can be bound to a header during block application, but that
    header does not authenticate the nullifier or commitment sets. A caller must
    derive those sets by ordered replay from genesis (or use a future
    authenticated-checkpoint format) before treating this state as consensus-valid.
    """

    _tree: OutputTree
    nullifiers: frozenset[bytes]
    commitments: frozenset[bytes]

    def __init__(
        self,
        tree: OutputTree,
        nullifiers: frozenset[bytes] = frozenset(),
        commitments: frozenset[bytes] = frozenset(),
    ) -> None:
        if type(tree) is not OutputTree:
            raise ValueError("ledger state tree must be the canonical OutputTree type")
        tree.validate_integrity()
        if type(nullifiers) is not frozenset or type(commitments) is not frozenset:
            raise ValueError("ledger uniqueness sets must be frozensets")
        if any(type(value) is not bytes or len(value) != 64 for value in nullifiers):
            raise ValueError("ledger nullifiers must each be 64 bytes")
        if any(type(value) is not bytes or len(value) != 64 for value in commitments):
            raise ValueError("ledger commitments must each be 64 bytes")
        object.__setattr__(self, "_tree", tree.clone())
        object.__setattr__(self, "nullifiers", nullifiers)
        object.__setattr__(self, "commitments", commitments)

    @property
    def tree(self) -> OutputTree:
        """Return a copy so callers cannot mutate an accepted ledger snapshot."""
        return self._tree.clone()

    @classmethod
    def empty(cls) -> LedgerState:
        return cls(OutputTree())


TransferVerifier = Callable[[TransactionStatementV1, bytes], bool]
MintVerifier = Callable[[Mint, int], bool]


def _reject(message: str) -> None:
    raise BlockRejected(message)


def _snapshot_output(output: OutputRecord) -> OutputRecord:
    """Copy and validate public output fields without retaining caller aliases."""
    if type(output) is not OutputRecord:
        _reject("output record type is invalid")
    try:
        snapshot = OutputRecord(
            commitment=output.commitment,
            kem_ciphertext=output.kem_ciphertext,
            nonce=output.nonce,
            ciphertext=output.ciphertext,
            leaf=output.leaf,
        )
        serialize_output_v1(snapshot)
    except (AttributeError, TypeError, ValueError) as exc:
        _reject(f"noncanonical output: {exc}")
    return snapshot


def _snapshot_mint(mint: Mint) -> Mint:
    """Copy and validate a mint before exposing any objects to a verifier."""
    if type(mint) is not Mint or type(mint.proof) is not bytes:
        _reject("mint record or proof encoding is invalid")
    if type(mint.outputs) is not tuple or not 1 <= len(mint.outputs) <= MAX_MINT_OUTPUTS:
        _reject("mint output vector must be a tuple with 1..16 items")
    return Mint(tuple(_snapshot_output(output) for output in mint.outputs), mint.proof)


def _snapshot_transfer(transfer: Transfer, index: int) -> tuple[Transfer, int]:
    """Canonicalize a transfer and return its encoded statement byte count."""
    if type(transfer) is not Transfer or type(transfer.proof) is not bytes:
        _reject(f"transfer {index}: malformed record or proof")
    if type(transfer.statement) is not TransactionStatementV1:
        _reject(f"transfer {index}: statement type is invalid")
    try:
        encoded = serialize_statement_v1(transfer.statement)
        statement = parse_statement_v1(encoded)
    except (AttributeError, TypeError, ValueError) as exc:
        _reject(f"transfer {index}: noncanonical statement: {exc}")
    return Transfer(statement, transfer.proof), len(encoded)


def _snapshot_anchor_headers(
    headers: dict[bytes, BlockHeaderRef],
    parent_id: bytes,
    minimum_anchor_height: int,
) -> dict[bytes, BlockHeaderRef | None]:
    """Copy only the selected branch through the lowest referenced anchor."""
    snapshot: dict[bytes, BlockHeaderRef | None] = {}
    current_id = parent_id
    seen: set[bytes] = set()
    while current_id not in seen:
        seen.add(current_id)
        header = headers.get(current_id)
        if type(header) is not BlockHeaderRef:
            snapshot[current_id] = None
            break
        try:
            copied = BlockHeaderRef(
                header.block_id,
                header.parent_id,
                header.height,
                header.output_root,
            )
        except (AttributeError, TypeError, ValueError):
            snapshot[current_id] = None
            break
        snapshot[current_id] = copied
        if (
            copied.block_id != current_id
            or copied.height <= minimum_anchor_height
            or copied.parent_id is None
        ):
            break
        current_id = copied.parent_id
    return snapshot


def apply_block(
    parent_state: LedgerState,
    *,
    candidate_height: int,
    parent_id: bytes,
    headers: dict[bytes, BlockHeaderRef],
    chain_id: bytes,
    transfers: Sequence[Transfer],
    mint: Mint,
    scheduled_subsidy: int,
    aggregate_fee_limit: int,
    max_transfers: int,
    max_total_proof_bytes: int,
    verify_transfer: TransferVerifier,
    verify_mint: MintVerifier,
    max_total_statement_bytes: int = 1_048_576,
) -> LedgerState:
    """Apply ordered transfers and exactly one mint, or raise without mutation.

    `aggregate_fee_limit`, `max_transfers`, `max_total_proof_bytes`, and
    `max_total_statement_bytes` are local policy parameters because the draft
    has not fixed block fee/size caps. The statement-byte cap defaults to 1 MiB
    and counts serialized transfer statements only; the proof-byte cap counts
    mint and transfer proof bytes only. Neither is a canonical full block-payload
    limit. `verify_mint` must prove
    the mint outputs sum to `scheduled_subsidy + all included transfer fees`;
    this model does not invent a subsidy schedule or a mint proof relation.
    Input transactions and the mint are snapshotted before callbacks, and
    verifiers receive detached canonical record copies; return-value correctness
    remains a trusted hook. Cheap structural, uniqueness, anchor, and accounting
    checks run across the whole block before any proof-verifier callback.
    Output-tree capacity is preflighted once, and the block's leaves are appended
    in one ordered batch to avoid a full sparse-tree staging copy per transfer.
    """
    if type(parent_state) is not LedgerState:
        _reject("parent state type is invalid")
    if type(parent_state._tree) is not OutputTree:
        _reject("parent output tree type is invalid")
    try:
        parent_state._tree.validate_integrity()
    except (TypeError, ValueError) as exc:
        _reject(f"parent output tree integrity check failed: {exc}")
    if type(parent_state.nullifiers) is not frozenset or type(parent_state.commitments) is not frozenset:
        _reject("parent uniqueness state must be immutable frozensets")
    if type(candidate_height) is not int or not 1 <= candidate_height < (1 << 64):
        _reject("candidate height must be a positive U64")
    if type(parent_id) is not bytes or len(parent_id) != 32:
        _reject("parent ID must be 32 bytes")
    if type(chain_id) is not bytes or len(chain_id) != 32:
        _reject("chain ID must be 32 bytes")
    if type(scheduled_subsidy) is not int or scheduled_subsidy < 0:
        _reject("scheduled subsidy must be a nonnegative integer")
    if scheduled_subsidy > MAX_MINT_AMOUNT:
        _reject("scheduled subsidy cannot fit in 1..16 nonzero U64 mint outputs")
    if type(aggregate_fee_limit) is not int or aggregate_fee_limit < 0:
        _reject("aggregate fee limit must be a nonnegative integer")
    if type(max_transfers) is not int or max_transfers < 0:
        _reject("maximum transfer count must be a nonnegative integer")
    if type(max_total_proof_bytes) is not int or max_total_proof_bytes < 0:
        _reject("maximum total proof bytes must be a nonnegative integer")
    if type(max_total_statement_bytes) is not int or max_total_statement_bytes < 0:
        _reject("maximum total statement bytes must be a nonnegative integer")
    if type(headers) is not dict:
        _reject("header index must be a dictionary")
    if not callable(verify_transfer) or not callable(verify_mint):
        _reject("transfer and mint verifiers are required")
    if type(transfers) not in (tuple, list):
        _reject("transfer sequence must be a list or tuple")
    if len(transfers) > max_transfers:
        _reject("transfer count exceeds configured limit")

    # Capture the bounded sequence and each proof bytes object before tallying.
    # The proof bytes are immutable; otherwise a caller mutating a list/record
    # concurrently could replace a proof after the cap check but before
    # _snapshot_transfer reads it. Statement objects are serialized/snapshotted
    # below and are not treated as immutable merely because their dataclass is frozen.
    caller_transfers = tuple(transfers)
    captured_transfers: list[tuple[TransactionStatementV1, bytes]] = []
    for index, transfer in enumerate(caller_transfers):
        if type(transfer) is not Transfer:
            _reject(f"transfer {index}: malformed record or proof")
        statement = transfer.statement
        proof = transfer.proof
        if type(proof) is not bytes:
            _reject(f"transfer {index}: malformed record or proof")
        captured_transfers.append((statement, proof))

    if type(mint) is not Mint:
        _reject("mint record or proof encoding is invalid")
    mint_outputs = mint.outputs
    mint_proof = mint.proof
    if type(mint_proof) is not bytes:
        _reject("mint record or proof encoding is invalid")

    # The local cap covers captured mint/transfer proof bytes only; it is not a
    # full canonical block-payload accounting rule. No statement serialization,
    # output snapshotting, or verifier callback happens before this check.
    proof_bytes = len(mint_proof)
    if proof_bytes > max_total_proof_bytes:
        _reject("total proof bytes exceed configured limit")
    for index, (_statement, proof) in enumerate(captured_transfers):
        if len(proof) > max_total_proof_bytes - proof_bytes:
            _reject("total proof bytes exceed configured limit")
        proof_bytes += len(proof)

    # Construct private records from the exact proof references that were
    # byte-counted, then enforce the cumulative canonical statement budget as
    # each individual bounded statement is serialized and snapshotted.
    transfer_snapshots = []
    statement_bytes = 0
    for index, (statement, proof) in enumerate(captured_transfers):
        snapshot, encoded_size = _snapshot_transfer(Transfer(statement, proof), index)
        if encoded_size > max_total_statement_bytes - statement_bytes:
            _reject("total statement bytes exceed configured limit")
        statement_bytes += encoded_size
        transfer_snapshots.append(snapshot)
    transfers = tuple(transfer_snapshots)
    mint = _snapshot_mint(Mint(mint_outputs, mint_proof))
    minimum_anchor_height = min(
        (transfer.statement.anchor_height for transfer in transfers),
        default=candidate_height - 1,
    )
    headers = _snapshot_anchor_headers(headers, parent_id, minimum_anchor_height)

    parent_header = headers.get(parent_id)
    if (
        type(parent_header) is not BlockHeaderRef
        or parent_header.block_id != parent_id
        or parent_header.height != candidate_height - 1
    ):
        _reject("candidate parent is missing, malformed, or has the wrong height")

    staged_tree = parent_state._tree.clone()
    if staged_tree.root != parent_header.output_root:
        _reject("parent state output root does not match candidate parent header")

    # Preflight the whole block once, then append its ordered outputs as one batch
    # after validation. Repeated per-transaction append_many calls cloned every
    # sparse tree level for each transfer, amplifying work with transfer count.
    output_count = len(mint.outputs) + sum(
        len(transfer.statement.outputs) for transfer in transfers
    )
    try:
        check_append_capacity(staged_tree.leaf_count, output_count)
    except ValueError as exc:
        _reject(f"block output count exceeds tree capacity: {exc}")
    for transfer in transfers:
        if any(output.leaf == EMPTY_HASHES[0] for output in transfer.statement.outputs):
            _reject("block output uses the reserved empty-leaf digest")
    if any(output.leaf == EMPTY_HASHES[0] for output in mint.outputs):
        _reject("mint output uses the reserved empty-leaf digest")

    staged_nullifiers = set(parent_state.nullifiers)
    staged_commitments = set(parent_state.commitments)
    if any(type(value) is not bytes or len(value) != 64 for value in staged_nullifiers):
        _reject("parent nullifier state is malformed")
    if any(type(value) is not bytes or len(value) != 64 for value in staged_commitments):
        _reject("parent commitment state is malformed")

    # Preflight every inexpensive block/statement constraint before invoking
    # potentially expensive proof-verifier callbacks.
    fee_total = 0
    for transfer_index, transfer in enumerate(transfers):
        statement = transfer.statement
        if statement.chain_id != chain_id:
            _reject(f"transfer {transfer_index}: chain ID mismatch")
        if not anchor_ok(
            candidate_height,
            parent_id,
            statement.anchor_height,
            statement.root_out,
            headers,
        ):
            _reject(f"transfer {transfer_index}: anchor is not valid on parent ancestry")
        for output in statement.outputs:
            _snapshot_output(output)

        if any(nf in staged_nullifiers for nf in statement.nullifiers):
            _reject(f"transfer {transfer_index}: duplicate nullifier")
        commitments = [output.commitment for output in statement.outputs]
        if any(cm in staged_commitments for cm in commitments):
            _reject(f"transfer {transfer_index}: duplicate output commitment")
        next_fees = fee_total + statement.fee
        if next_fees > aggregate_fee_limit:
            _reject("aggregate transfer fees exceed configured limit")
        if scheduled_subsidy + next_fees > MAX_MINT_AMOUNT:
            _reject("mint total cannot fit in 1..16 nonzero U64 outputs")

        staged_nullifiers.update(statement.nullifiers)
        staged_commitments.update(commitments)
        fee_total = next_fees

    mint_commitments = [output.commitment for output in mint.outputs]
    if len(set(mint_commitments)) != len(mint_commitments):
        _reject("mint contains duplicate commitments")
    if any(cm in staged_commitments for cm in mint_commitments):
        _reject("mint commitment duplicates prior or transfer output")
    expected_mint_value = scheduled_subsidy + fee_total
    if not 1 <= expected_mint_value <= MAX_MINT_AMOUNT:
        _reject("mint total cannot fit in 1..16 nonzero U64 outputs")

    for transfer_index, transfer in enumerate(transfers):
        try:
            # Give the callback a separate parsed record: frozen records can
            # still be mutated with object.__setattr__, so consensus must not
            # reuse a verifier-visible object after returning from the hook.
            verifier_statement = parse_statement_v1(
                serialize_statement_v1(transfer.statement)
            )
            proof_valid = verify_transfer(verifier_statement, transfer.proof)
        except Exception as exc:
            _reject(f"transfer {transfer_index}: verifier failed: {type(exc).__name__}")
        if proof_valid is not True:
            _reject(f"transfer {transfer_index}: proof rejected")

    try:
        verifier_mint = Mint(
            tuple(_snapshot_output(output) for output in mint.outputs),
            mint.proof,
        )
        mint_valid = verify_mint(verifier_mint, expected_mint_value)
    except Exception as exc:
        _reject(f"mint verifier failed: {type(exc).__name__}")
    if mint_valid is not True:
        _reject("mint proof or issuance amount rejected")
    staged_commitments.update(mint_commitments)

    def block_output_leaves() -> Iterable[bytes]:
        for transfer in transfers:
            for output in transfer.statement.outputs:
                yield output.leaf
        for output in mint.outputs:
            yield output.leaf

    try:
        staged_tree.append_many(block_output_leaves())
    except (TypeError, ValueError) as exc:
        _reject(f"block output-tree append failed: {exc}")

    return LedgerState(
        tree=staged_tree,
        nullifiers=frozenset(staged_nullifiers),
        commitments=frozenset(staged_commitments),
    )
